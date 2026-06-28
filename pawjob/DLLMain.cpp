#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <intrin.h>
#include <array>
#include <cctype>
#include <cstring>
#include <cwctype>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <atomic>
#include <print>
#include <format>
#include <ranges>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>

#pragma comment(lib, "Ws2_32.lib")

#include <minhook/MinHook.h>
#pragma comment(lib, "minhook/libMinHook.x86.lib")

#include "modules/advapi32.h"
#include "modules/D3DX9_43.h"
#include "modules/gdi32.h"
#include "modules/kernel32.h"
#include "modules/msvcp140.h"
#include "modules/ntdll.h"
#include "modules/shell32.h"
#include "modules/ucrtbase.h"
#include "modules/user32.h"
#include "modules/VCRUNTIME140.h"
#include "modules/winmm.h"
#include "modules/ws2_32.h"

#include "obfuscated_calls.h"
#include "obfuscated_jmps.h"

#ifndef PAWJOB_ENABLE_FILE_LOGGING
#define PAWJOB_ENABLE_FILE_LOGGING 0
#endif

struct dmp_symbol
{
	const char* module;
	const char* proc;
	uintptr_t   address;
};

std::unordered_map<uintptr_t, dmp_symbol> dmp_symbols;

uintptr_t __stdcall get_target(uintptr_t old_address)
{
	if (auto it = dmp_symbols.find(old_address); it != dmp_symbols.end()) {
		return it->second.address;
	}
	return static_cast<uintptr_t>(-1);
}

uintptr_t get_target_impl = reinterpret_cast<uintptr_t>(&get_target);

#pragma pack(1)
struct obfuscation_hook
{
	uint8_t original_bytes[8];
	uint8_t shellcode0[9];
	uint32_t get_target_impl_address;
	uint8_t shellcode1[6];
	uint8_t push;
	uint32_t return_address;
	uint8_t shellcode2[3];
};
#pragma pack()

obfuscation_hook* obfuscated_call_hooks;
obfuscation_hook* obfuscated_jmp_hooks;

bool init_obfuscation_hooks(auto& calls, auto& jmps)
{
	size_t calls_size = sizeof(obfuscation_hook) * (calls.size() + 1);
	size_t jmps_size = sizeof(obfuscation_hook) * (jmps.size() + 1);

	obfuscated_call_hooks = (obfuscation_hook*)VirtualAlloc(nullptr, calls_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	obfuscated_jmp_hooks = (obfuscation_hook*)VirtualAlloc(nullptr, jmps_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!obfuscated_call_hooks || !obfuscated_jmp_hooks)
		return false;

	static auto init_hook = [&](obfuscation_hook* hook, uintptr_t start, size_t size, bool is_call = false)
		{
			static std::array<uint8_t, 9> shellcode0 = { 0x68, 0xEF, 0xBE, 0xAD, 0xDE, 0x60, 0x50, 0xFF, 0x15 };
			static std::array<uint8_t, 6> shellcode1 = { 0x89, 0x44, 0x24, 0x20, 0x61, 0x58 };
			static std::array<uint8_t, 3> shellcode2 = { 0xFF, 0xE0, 0xCC };

			memset(hook, 0x90, sizeof(obfuscation_hook));
			// copy old bytes
			memcpy(hook, reinterpret_cast<void*>(start), size);
			// set up shellcodes...
			memcpy(hook->shellcode0, shellcode0.data(), shellcode0.size());
			memcpy(hook->shellcode1, shellcode1.data(), shellcode1.size());
			memcpy(hook->shellcode2, shellcode2.data(), shellcode2.size());

			hook->get_target_impl_address = reinterpret_cast<uint32_t>(&get_target_impl);
			
			// set up return address
			if (is_call)
			{
				hook->push = 0x68;
				hook->return_address = start + size + 2;
			}

			// set up hook
			// fill with int3
			memset(reinterpret_cast<void*>(start), 0xCC, size + 2);
			*reinterpret_cast<uint8_t*>(start) = 0xE9;
			*reinterpret_cast<uint32_t*>(start + 1) = reinterpret_cast<uintptr_t>(hook) - start - 5;

		};

	// calls
	for (size_t i = 0; i < calls.size(); i++)
	{
		obfuscated_call_t& call = calls[i];
		obfuscation_hook* hook = &obfuscated_call_hooks[i];
		init_hook(hook, call.start_address, call.size2call, true);
	}

	// jmps
	for (size_t i = 0; i < jmps.size(); i++)
	{
		obfuscated_jmp_t& jmp = jmps[i];
		obfuscation_hook* hook = &obfuscated_jmp_hooks[i];
		init_hook(hook, jmp.start_address, jmp.size2jmp);
	}

	return true;
}

void load_modules()
{
	auto load_symbols = [&](const pawjob::module& module)
		{
			for (auto& symbol : module.export_symbols)
			{
				dmp_symbols[symbol.address] = { module.name,symbol.name, reinterpret_cast<uintptr_t>(GetProcAddress(LoadLibraryA(module.name),symbol.name)) };
			}
		};
	load_symbols(advapi32);
	load_symbols(D3DX9_43);
	load_symbols(gdi32);
	load_symbols(kernel32);
	load_symbols(msvcp140);
	load_symbols(ntdll);
	load_symbols(shell32);
	load_symbols(ucrtbase);
	load_symbols(user32);
	load_symbols(VCRUNTIME140);
	load_symbols(winmm);
	load_symbols(ws2_32);
}

void fix_iat()
{
	const uintptr_t start = static_cast<uintptr_t>(0x7fff0000u) + static_cast<uintptr_t>(0x762000u);
	const uintptr_t end = static_cast<uintptr_t>(0x7fff0000u) + static_cast<uintptr_t>(0x762650u);

	for (uintptr_t* cur = reinterpret_cast<uintptr_t*>(start); cur <= reinterpret_cast<uintptr_t*>(end); cur++)
	{
		uintptr_t address = *cur;

		if (!address)
		{
			continue;
		}

		if (auto it = dmp_symbols.find(address); it != dmp_symbols.end()) {
			*cur = it->second.address;
		}

	}
}

decltype(&GetCurrentProcessId) oGetCurrentProcessId;
decltype(&CreateFileA) oCreateFileA;
decltype(&CreateFileW) oCreateFileW;
decltype(&FindFirstFileA) oFindFirstFileA;
decltype(&FindFirstFileW) oFindFirstFileW;
decltype(&FindFirstFileExA) oFindFirstFileExA;
decltype(&FindFirstFileExW) oFindFirstFileExW;
decltype(&GetFileAttributesA) oGetFileAttributesA;
decltype(&GetFileAttributesW) oGetFileAttributesW;
decltype(&CreateDirectoryA) oCreateDirectoryA;
decltype(&CreateDirectoryW) oCreateDirectoryW;
decltype(&DeleteFileA) oDeleteFileA;
decltype(&DeleteFileW) oDeleteFileW;
decltype(&MoveFileA) oMoveFileA;
decltype(&MoveFileW) oMoveFileW;
decltype(&MoveFileExA) oMoveFileExA;
decltype(&MoveFileExW) oMoveFileExW;
decltype(&WSAStartup) oWSAStartup;
decltype(&socket) oSocket;
decltype(&connect) oConnect;
decltype(&send) oSend;
decltype(&recv) oRecv;
decltype(&WSASend) oWSASend;
decltype(&WSARecv) oWSARecv;
decltype(&closesocket) oClosesocket;

using d3dx_create_font_a_fn = HRESULT(WINAPI*)(void*, INT, UINT, UINT, UINT, BOOL, DWORD, DWORD, DWORD, DWORD, LPCSTR, void**);
using d3dx_font_draw_text_a_fn = INT(WINAPI*)(void*, void*, LPCSTR, INT, RECT*, DWORD, DWORD);
using d3dx_create_line_fn = HRESULT(WINAPI*)(void*, void**);
using d3dx_line_draw_fn = HRESULT(WINAPI*)(void*, const void*, DWORD, DWORD);
using d3d_draw_primitive_up_fn = HRESULT(WINAPI*)(void*, unsigned int, UINT, const void*, UINT);
using d3d_draw_indexed_primitive_up_fn = HRESULT(WINAPI*)(void*, unsigned int, UINT, UINT, UINT, const void*, unsigned int, const void*, UINT);
d3dx_create_font_a_fn oD3DXCreateFontA;
d3dx_font_draw_text_a_fn oD3DXFontDrawTextA;
d3dx_create_line_fn oD3DXCreateLine;
d3dx_line_draw_fn oD3DXLineDraw;
d3d_draw_primitive_up_fn oD3DDrawPrimitiveUP;
d3d_draw_indexed_primitive_up_fn oD3DDrawIndexedPrimitiveUP;
static void* g_d3dx_font_draw_text_a_target = nullptr;
static void* g_d3dx_line_draw_target = nullptr;
static void* g_d3d_draw_primitive_up_target = nullptr;
static void* g_d3d_draw_indexed_primitive_up_target = nullptr;
static bool g_d3dx_font_draw_text_a_hooked = false;
static bool g_d3dx_line_draw_hooked = false;
static bool g_d3d_draw_primitive_up_hooked = false;
static bool g_d3d_draw_indexed_primitive_up_hooked = false;
static std::atomic<DWORD> g_brand_accent_rgb = 0x00ff5555;
static thread_local int t_menu_accent_swatch_primitive_budget = 0;
static thread_local RECT t_last_full_brand_rect = {};
static thread_local DWORD t_last_full_brand_tick = 0;
static thread_local bool t_has_last_full_brand_rect = false;

static bool log_minhook_status(const char* operation, const char* target, MH_STATUS status);

using cloud_compare_fn = unsigned char(__cdecl*)(const void*, uint32_t, const void*, uint32_t);
cloud_compare_fn oCloudCompare;

using cloud_crypto_set_bytes_fn = void(__thiscall*)(void*, const void*, uint32_t);
cloud_crypto_set_bytes_fn oCloudCryptoSetBytes;

using server_status_check_fn = void*(__cdecl*)(void*);
server_status_check_fn oServerStatusCheck;

struct msvc_string_value_t
{
	std::array<uint8_t, 24> bytes = {};
};

static_assert(sizeof(msvc_string_value_t) == 24);

using config_load_handler_fn = void*(__cdecl*)(void*, msvc_string_value_t);
config_load_handler_fn oConfigLoadHandler;

using parsed_value_equal_fn = unsigned char(__thiscall*)(void*, const void*);
parsed_value_equal_fn oParsedValueEqual;

using str_equal_literal_fn = unsigned char(__cdecl*)(const void*, const char*);
str_equal_literal_fn oStrEqualLiteral;

using nt_status_t = LONG;

struct nt_unicode_string_t
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
};

struct nt_object_attributes_t
{
	ULONG Length;
	HANDLE RootDirectory;
	nt_unicode_string_t* ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
};

struct nt_io_status_block_t
{
	union
	{
		nt_status_t Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
};

using nt_create_file_t = nt_status_t(NTAPI*)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
	nt_object_attributes_t* ObjectAttributes, nt_io_status_block_t* IoStatusBlock, PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
using nt_open_file_t = nt_status_t(NTAPI*)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
	nt_object_attributes_t* ObjectAttributes, nt_io_status_block_t* IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);

nt_create_file_t oNtCreateFile;
nt_open_file_t oNtOpenFile;

static std::wstring g_local_storage_root;
static std::wstring g_pawjob_storage_root;
static std::wstring g_debug_log_path;
static std::wstring g_debug_flags_path;
static bool g_leave_server_check_original = false;
static bool g_cloud_redirect_local = false;
static bool g_crash_guard_log = false;
static bool g_crash_guard_quarantine_known = false;
static bool g_cloud_parser_trace = false;
static HANDLE g_debug_log = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_debug_log_lock;
static bool g_debug_log_lock_ready = false;
static PVOID g_crash_guard_handle = nullptr;
static DWORD g_init_thread_id = 0;
static DWORD g_oep_thread_id = 0;
static thread_local SOCKET g_tls_last_recv_socket = INVALID_SOCKET;
static thread_local uintptr_t g_tls_last_recv_buffer = 0;
static thread_local DWORD g_tls_last_recv_bytes = 0;
static thread_local DWORD g_tls_last_recv_capacity = 0;

static bool safe_copy_bytes(const void* source, void* target, size_t bytes);
static std::string bytes_to_hex(const uint8_t* bytes, size_t count);
static void log_exception_context(PEXCEPTION_POINTERS exception_info);

static void debug_log_line(const std::string& line)
{
#if PAWJOB_ENABLE_FILE_LOGGING
	if (g_debug_log == INVALID_HANDLE_VALUE)
	{
		return;
	}

	if (g_debug_log_lock_ready)
	{
		EnterCriticalSection(&g_debug_log_lock);
	}

	const std::string payload = std::format("[{}ms tid={}] {}\r\n",
		GetTickCount(), GetCurrentThreadId(), line);
	DWORD written = 0;
	WriteFile(g_debug_log, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr);
	FlushFileBuffers(g_debug_log);

	if (g_debug_log_lock_ready)
	{
		LeaveCriticalSection(&g_debug_log_lock);
	}
#else
	(void)line;
#endif
}

DWORD
WINAPI
hooked_GetCurrentProcessId(
	VOID
)
{
	return 18344;
}

static bool is_slash(wchar_t ch)
{
	return ch == L'\\' || ch == L'/';
}

static bool is_slash(char ch)
{
	return ch == '\\' || ch == '/';
}

static void trim_trailing_slashes(std::wstring& path)
{
	while (path.size() > 3 && is_slash(path.back()))
	{
		path.pop_back();
	}
}

static std::string narrow_utf8(std::wstring_view text)
{
	if (text.empty())
	{
		return {};
	}

	const int needed = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
	if (needed <= 0)
	{
		return {};
	}

	std::string out(static_cast<size_t>(needed), '\0');
	WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), needed, nullptr, nullptr);
	return out;
}

static std::string bool_text(bool value)
{
	return value ? "true" : "false";
}

static std::string handle_text(HANDLE handle)
{
	return std::format("0x{:08x}", reinterpret_cast<uintptr_t>(handle));
}

static std::string path_for_log(LPCSTR path)
{
	return path ? std::string(path) : std::string("<null>");
}

static std::string path_for_log(LPCWSTR path)
{
	return path ? narrow_utf8(path) : std::string("<null>");
}

static std::string path_for_log(const std::string& path)
{
	return path.empty() ? std::string("<empty>") : path;
}

static std::string path_for_log(const std::wstring& path)
{
	return path.empty() ? std::string("<empty>") : narrow_utf8(path);
}

static std::wstring widen_acp(std::string_view text)
{
	if (text.empty())
	{
		return {};
	}

	const int needed = MultiByteToWideChar(CP_ACP, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
	if (needed <= 0)
	{
		return {};
	}

	std::wstring out(static_cast<size_t>(needed), L'\0');
	MultiByteToWideChar(CP_ACP, 0, text.data(), static_cast<int>(text.size()), out.data(), needed);
	return out;
}

static std::string narrow_acp(std::wstring_view text)
{
	if (text.empty())
	{
		return {};
	}

	const int needed = WideCharToMultiByte(CP_ACP, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
	if (needed <= 0)
	{
		return {};
	}

	std::string out(static_cast<size_t>(needed), '\0');
	WideCharToMultiByte(CP_ACP, 0, text.data(), static_cast<int>(text.size()), out.data(), needed, nullptr, nullptr);
	return out;
}

static std::wstring process_directory()
{
	std::vector<wchar_t> path(MAX_PATH);
	for (;;)
	{
		const DWORD len = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
		if (len == 0)
		{
			return {};
		}
		if (len < path.size() - 1)
		{
			std::wstring out(path.data(), len);
			const auto slash = out.find_last_of(L"\\/");
			if (slash == std::wstring::npos)
			{
				return {};
			}
			out.resize(slash);
			trim_trailing_slashes(out);
			return out;
		}
		if (path.size() >= 32768)
		{
			return {};
		}
		path.resize(path.size() * 2);
	}
}

static std::wstring join_path(std::wstring_view root, std::wstring_view child)
{
	std::wstring out(root);
	if (!out.empty() && !is_slash(out.back()))
	{
		out.push_back(L'\\');
	}
	out.append(child);
	return out;
}

static std::wstring full_path_name(std::wstring_view path)
{
	std::wstring input(path);
	const DWORD needed = GetFullPathNameW(input.c_str(), 0, nullptr, nullptr);
	if (!needed)
	{
		return {};
	}

	std::vector<wchar_t> buffer(needed);
	const DWORD written = GetFullPathNameW(input.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
	if (!written || written >= buffer.size())
	{
		return {};
	}

	std::wstring out(buffer.data(), written);
	trim_trailing_slashes(out);
	return out;
}

static bool ensure_directory(const std::wstring& dir)
{
	std::error_code ec;
	const std::filesystem::path path(dir);
	if (std::filesystem::is_directory(path, ec))
	{
		return true;
	}

	ec.clear();
	if (std::filesystem::create_directories(path, ec) || std::filesystem::is_directory(path, ec))
	{
		debug_log_line(std::format("Local storage ready: {}", narrow_utf8(dir)));
		return true;
	}

	debug_log_line(std::format("Local storage failed: {} ({})", narrow_utf8(dir), ec.message()));
	return false;
}

static void copy_file_if_missing(const std::wstring& source, const std::wstring& target, const char* label)
{
	if (source.empty() || target.empty())
	{
		return;
	}

	std::error_code ec;
	if (!std::filesystem::exists(source, ec) || std::filesystem::exists(target, ec))
	{
		return;
	}

	if (!ensure_directory(std::filesystem::path(target).parent_path().wstring()))
	{
		debug_log_line(std::format("migration label={} result=failed_create_dir source=\"{}\" target=\"{}\"",
			label, narrow_utf8(source), narrow_utf8(target)));
		return;
	}

	ec.clear();
	const bool copied = std::filesystem::copy_file(source, target, std::filesystem::copy_options::none, ec);
	debug_log_line(std::format("migration label={} source=\"{}\" target=\"{}\" copied={} error=\"{}\"",
		label, narrow_utf8(source), narrow_utf8(target), bool_text(copied), ec.message()));
}

static bool open_debug_log()
{
#if PAWJOB_ENABLE_FILE_LOGGING
	if (g_debug_log_lock_ready)
	{
		DeleteCriticalSection(&g_debug_log_lock);
		g_debug_log_lock_ready = false;
	}
	InitializeCriticalSection(&g_debug_log_lock);
	g_debug_log_lock_ready = true;

	g_debug_log_path = join_path(g_pawjob_storage_root, L"debug_file_hooks.log");
	g_debug_log = CreateFileW(g_debug_log_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (g_debug_log == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	debug_log_line("debug logger opened path=" + path_for_log(g_debug_log_path));
	return true;
#else
	g_debug_log_path = join_path(g_pawjob_storage_root, L"debug_file_hooks.log");
	return false;
#endif
}

static std::string trim_ascii(std::string_view text)
{
	size_t first = 0;
	while (first < text.size() && std::isspace(static_cast<unsigned char>(text[first])))
	{
		++first;
	}

	size_t last = text.size();
	while (last > first && std::isspace(static_cast<unsigned char>(text[last - 1])))
	{
		--last;
	}
	return std::string(text.substr(first, last - first));
}

static std::string lower_ascii(std::string text)
{
	for (char& ch : text)
	{
		ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
	}
	return text;
}

static bool truthy_flag_value(std::string_view value)
{
	const std::string normalized = lower_ascii(trim_ascii(value));
	return normalized == "1" || normalized == "true" || normalized == "yes" || normalized == "on" ||
		normalized == "original" || normalized == "debug" || normalized == "unpatched";
}

static bool falsey_flag_value(std::string_view value)
{
	const std::string normalized = lower_ascii(trim_ascii(value));
	return normalized == "0" || normalized == "false" || normalized == "no" || normalized == "off" ||
		normalized == "nop" || normalized == "patched";
}

static const char* crash_guard_mode_text()
{
	if (g_crash_guard_quarantine_known)
	{
		return "quarantine_known";
	}
	if (g_crash_guard_log)
	{
		return "log";
	}
	return "off";
}

static void load_debug_flags()
{
	g_leave_server_check_original = true;
	g_cloud_redirect_local = true;
	g_crash_guard_log = false;
	g_crash_guard_quarantine_known = false;
	g_cloud_parser_trace = false;
	g_debug_flags_path = join_path(g_pawjob_storage_root, L"debug_flags.ini");

	std::ifstream input(std::filesystem::path(g_debug_flags_path), std::ios::binary);
	if (!input.is_open())
	{
		debug_log_line("debug_flags path=" + path_for_log(g_debug_flags_path) +
			" loaded=false server_check_mode=original cloud_redirect=local crash_guard=off cloud_parser_trace=false");
		return;
	}

	bool found_server_check_flag = false;
	bool found_cloud_redirect_flag = false;
	bool found_crash_guard_flag = false;
	bool found_cloud_parser_trace_flag = false;
	std::string line;
	while (std::getline(input, line))
	{
		const size_t comment = line.find_first_of("#;");
		if (comment != std::string::npos)
		{
			line.resize(comment);
		}

		const size_t equals = line.find('=');
		if (equals == std::string::npos)
		{
			continue;
		}

		const std::string key = lower_ascii(trim_ascii(std::string_view(line).substr(0, equals)));
		const std::string value = trim_ascii(std::string_view(line).substr(equals + 1));
		if (key == "server_check" || key == "server_check_mode" || key == "server_check_patch")
		{
			if (truthy_flag_value(value))
			{
				g_leave_server_check_original = lower_ascii(value) != "nop" && lower_ascii(value) != "patched";
				found_server_check_flag = true;
			}
			else if (falsey_flag_value(value))
			{
				g_leave_server_check_original = false;
				found_server_check_flag = true;
			}
		}
		else if (key == "server_check_original" || key == "original_server_check")
		{
			g_leave_server_check_original = truthy_flag_value(value);
			found_server_check_flag = true;
		}
		else if (key == "patch_server_check")
		{
			if (truthy_flag_value(value))
			{
				g_leave_server_check_original = false;
				found_server_check_flag = true;
			}
			else if (falsey_flag_value(value))
			{
				g_leave_server_check_original = true;
				found_server_check_flag = true;
			}
		}
		else if (key == "cloud_redirect" || key == "cloud_redirect_mode")
		{
			const std::string normalized = lower_ascii(value);
			if (normalized == "local" || normalized == "localhost" || normalized == "loopback")
			{
				g_cloud_redirect_local = true;
				found_cloud_redirect_flag = true;
			}
			else if (normalized == "none" || falsey_flag_value(value))
			{
				g_cloud_redirect_local = false;
				found_cloud_redirect_flag = true;
			}
		}
		else if (key == "crash_guard" || key == "thread_quarantine" || key == "crash_quarantine")
		{
			const std::string normalized = lower_ascii(value);
			if (normalized == "log" || normalized == "diagnostic")
			{
				g_crash_guard_log = true;
				g_crash_guard_quarantine_known = false;
				found_crash_guard_flag = true;
			}
			else if (normalized == "quarantine_known" || normalized == "known" ||
				normalized == "kill_known" || normalized == "exit_thread" || normalized == "thread")
			{
				g_crash_guard_log = true;
				g_crash_guard_quarantine_known = true;
				found_crash_guard_flag = true;
			}
			else if (normalized == "none" || falsey_flag_value(value))
			{
				g_crash_guard_log = false;
				g_crash_guard_quarantine_known = false;
				found_crash_guard_flag = true;
			}
		}
		else if (key == "cloud_parser_trace" || key == "parser_trace" || key == "cloud_trace")
		{
			g_cloud_parser_trace = truthy_flag_value(value);
			if (falsey_flag_value(value))
			{
				g_cloud_parser_trace = false;
			}
			found_cloud_parser_trace_flag = truthy_flag_value(value) || falsey_flag_value(value);
		}
	}

	debug_log_line(std::format("debug_flags path={} loaded=true server_check_mode={} server_flag_found={} cloud_redirect={} cloud_flag_found={} crash_guard={} crash_guard_found={} cloud_parser_trace={} parser_trace_found={}",
		path_for_log(g_debug_flags_path), g_leave_server_check_original ? "original" : "nop",
		bool_text(found_server_check_flag), g_cloud_redirect_local ? "local" : "none",
		bool_text(found_cloud_redirect_flag), crash_guard_mode_text(), bool_text(found_crash_guard_flag),
		bool_text(g_cloud_parser_trace), bool_text(found_cloud_parser_trace_flag)));
}

static bool is_known_cloud_crash_address(uintptr_t address)
{
	static constexpr std::array<uintptr_t, 3> addresses = {
		0x463d0523,
		0x70485d33,
		0x807467b5,
	};

	return std::ranges::find(addresses, address) != addresses.end();
}

static std::string exception_address_text(uintptr_t address)
{
	return address ? std::format("0x{:08x}", address) : std::string("<none>");
}

static LONG CALLBACK crash_guard_vectored_handler(PEXCEPTION_POINTERS exception_info)
{
	if ((!g_crash_guard_log && !g_crash_guard_quarantine_known) || !exception_info || !exception_info->ExceptionRecord)
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}

	const DWORD code = exception_info->ExceptionRecord->ExceptionCode;
	const uintptr_t exception_address = reinterpret_cast<uintptr_t>(exception_info->ExceptionRecord->ExceptionAddress);
	uintptr_t instruction_pointer = 0;
#if defined(_M_IX86)
	if (exception_info->ContextRecord)
	{
		instruction_pointer = static_cast<uintptr_t>(exception_info->ContextRecord->Eip);
	}
#endif

	const DWORD thread_id = GetCurrentThreadId();
	const bool known_cloud_crash = is_known_cloud_crash_address(exception_address) ||
		is_known_cloud_crash_address(instruction_pointer);
	const bool can_quarantine = g_crash_guard_quarantine_known && known_cloud_crash && thread_id != g_init_thread_id;
	const bool should_log = g_crash_guard_log || known_cloud_crash || can_quarantine;

	if (should_log)
	{
		debug_log_line(std::format(
			"api=Exception code=0x{:08x} address={} eip={} flags=0x{:08x} thread={} init_thread={} oep_thread={} known_cloud_crash={} crash_guard={} action={}",
			static_cast<unsigned long>(code), exception_address_text(exception_address),
			exception_address_text(instruction_pointer),
			static_cast<unsigned long>(exception_info->ExceptionRecord->ExceptionFlags),
			thread_id, g_init_thread_id, g_oep_thread_id, bool_text(known_cloud_crash),
			crash_guard_mode_text(), can_quarantine ? "ExitThread" : "continue_search"));
		if (g_cloud_parser_trace)
		{
			log_exception_context(exception_info);
		}
	}

	if (can_quarantine)
	{
		ExitThread(0);
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

static bool install_crash_guard()
{
	if (!g_crash_guard_log && !g_crash_guard_quarantine_known)
	{
		debug_log_line("crash_guard install=skipped mode=off");
		return true;
	}

	if (g_crash_guard_handle)
	{
		debug_log_line(std::format("crash_guard install=already_installed mode={}", crash_guard_mode_text()));
		return true;
	}

	g_crash_guard_handle = AddVectoredExceptionHandler(1, crash_guard_vectored_handler);
	debug_log_line(std::format("crash_guard install={} mode={} handler={}",
		g_crash_guard_handle ? "ok" : "failed", crash_guard_mode_text(), handle_text(g_crash_guard_handle)));
	return g_crash_guard_handle != nullptr;
}

static bool path_is_under_root(std::wstring_view root, std::wstring_view candidate)
{
	std::wstring root_text(root);
	std::wstring candidate_text(candidate);
	trim_trailing_slashes(root_text);
	trim_trailing_slashes(candidate_text);

	if (candidate_text.size() < root_text.size())
	{
		return false;
	}

	for (size_t i = 0; i < root_text.size(); ++i)
	{
		if (std::towlower(candidate_text[i]) != std::towlower(root_text[i]))
		{
			return false;
		}
	}

	return candidate_text.size() == root_text.size() || is_slash(candidate_text[root_text.size()]);
}

static bool is_absolute_or_device_path(std::wstring_view path)
{
	if (path.size() >= 2 && path[1] == L':')
	{
		return true;
	}
	return !path.empty() && is_slash(path[0]);
}

static bool is_absolute_or_device_path(std::string_view path)
{
	if (path.size() >= 2 && path[1] == ':')
	{
		return true;
	}
	return !path.empty() && is_slash(path[0]);
}

static bool ascii_equal_lower(wchar_t lhs, wchar_t rhs)
{
	return std::towlower(lhs) == rhs;
}

static bool ascii_equal_lower(char lhs, char rhs)
{
	return static_cast<char>(std::tolower(static_cast<unsigned char>(lhs))) == rhs;
}

template <typename Char, size_t Size>
static size_t relative_prefix_len(std::basic_string_view<Char> path, const std::array<Char, Size>& prefix)
{
	if (path.size() < prefix.size())
	{
		return 0;
	}

	for (size_t i = 0; i < prefix.size(); ++i)
	{
		if (!ascii_equal_lower(path[i], prefix[i]))
		{
			return 0;
		}
	}

	if (path.size() == prefix.size() || is_slash(path[prefix.size()]))
	{
		return prefix.size();
	}
	return 0;
}

static size_t relative_pawjob_prefix_len(std::wstring_view path)
{
	static constexpr std::array<wchar_t, 6> primary = { L'p', L'a', L'w', L'j', L'o', L'b' };
	static constexpr std::array<wchar_t, 8> legacy = {
		static_cast<wchar_t>(0x6d), static_cast<wchar_t>(0x6f), static_cast<wchar_t>(0x6e), static_cast<wchar_t>(0x65),
		static_cast<wchar_t>(0x79), static_cast<wchar_t>(0x62), static_cast<wchar_t>(0x6f), static_cast<wchar_t>(0x74)
	};

	if (const size_t len = relative_prefix_len(path, primary))
		return len;
	return relative_prefix_len(path, legacy);
}

static size_t relative_pawjob_prefix_len(std::string_view path)
{
	static constexpr std::array<char, 6> primary = { 'p', 'a', 'w', 'j', 'o', 'b' };
	static constexpr std::array<char, 8> legacy = {
		static_cast<char>(0x6d), static_cast<char>(0x6f), static_cast<char>(0x6e), static_cast<char>(0x65),
		static_cast<char>(0x79), static_cast<char>(0x62), static_cast<char>(0x6f), static_cast<char>(0x74)
	};

	if (const size_t len = relative_prefix_len(path, primary))
		return len;
	return relative_prefix_len(path, legacy);
}

enum class path_rewrite_status
{
	no_match,
	rewritten,
	blocked,
};

static std::string path_status_text(path_rewrite_status status)
{
	switch (status)
	{
	case path_rewrite_status::no_match:
		return "no_match";
	case path_rewrite_status::rewritten:
		return "rewritten";
	case path_rewrite_status::blocked:
		return "blocked";
	default:
		return "unknown";
	}
}

struct wide_rewrite_result
{
	path_rewrite_status status;
	std::wstring path;
};

struct narrow_rewrite_result
{
	path_rewrite_status status;
	std::string path;
};

struct nt_path_rewrite_result
{
	path_rewrite_status status;
	std::wstring dos_path;
	std::wstring nt_path;
};

static nt_path_rewrite_result rewrite_nt_pawjob_path(const std::wstring& object_name);
static bool make_rewritten_nt_object_attributes(nt_object_attributes_t* original, const std::wstring& nt_path,
	nt_object_attributes_t* rewritten, nt_unicode_string_t* rewritten_name);

static bool contains_keyword(std::wstring_view text)
{
	static constexpr std::array<std::wstring_view, 11> keywords = {
		L"pawjob", L"database", L"config", L"cfg", L"preset",
		L"smoke1", L"moneycfg", L"lua", L"skins", L"playerlist", L"acupthz"
	};

	for (size_t i = 0; i + 1 <= text.size(); ++i)
	{
		for (const auto keyword : keywords)
		{
			if (i + keyword.size() > text.size())
			{
				continue;
			}

			bool match = true;
			for (size_t k = 0; k < keyword.size(); ++k)
			{
				if (std::towlower(text[i + k]) != keyword[k])
				{
					match = false;
					break;
				}
			}
			if (match)
			{
				return true;
			}
		}
	}
	return false;
}

static bool contains_keyword(std::string_view text)
{
	static constexpr std::array<std::string_view, 11> keywords = {
		"pawjob", "database", "config", "cfg", "preset",
		"smoke1", "moneycfg", "lua", "skins", "playerlist", "acupthz"
	};

	for (size_t i = 0; i + 1 <= text.size(); ++i)
	{
		for (const auto keyword : keywords)
		{
			if (i + keyword.size() > text.size())
			{
				continue;
			}

			bool match = true;
			for (size_t k = 0; k < keyword.size(); ++k)
			{
				if (static_cast<char>(std::tolower(static_cast<unsigned char>(text[i + k]))) != keyword[k])
				{
					match = false;
					break;
				}
			}
			if (match)
			{
				return true;
			}
		}
	}
	return false;
}

static bool should_log_path(LPCSTR path)
{
	return path && contains_keyword(std::string_view(path));
}

static bool should_log_path(LPCWSTR path)
{
	return path && contains_keyword(std::wstring_view(path));
}

static std::string rewritten_path_for_log(const narrow_rewrite_result& rewritten)
{
	if (rewritten.status == path_rewrite_status::rewritten)
	{
		return path_for_log(rewritten.path);
	}
	if (rewritten.status == path_rewrite_status::blocked)
	{
		return "<blocked>";
	}
	return "<unchanged>";
}

static std::string rewritten_path_for_log(const wide_rewrite_result& rewritten)
{
	if (rewritten.status == path_rewrite_status::rewritten)
	{
		return path_for_log(rewritten.path);
	}
	if (rewritten.status == path_rewrite_status::blocked)
	{
		return "<blocked>";
	}
	return "<unchanged>";
}

static void log_path_api_result(const char* api, const std::string& original, const std::string& rewritten,
	path_rewrite_status status, const std::string& result, bool failed, DWORD last_error)
{
	debug_log_line(std::format(
		"api={} original=\"{}\" rewritten=\"{}\" rewrite={} result={} failed={} gle={}",
		api, original, rewritten, path_status_text(status), result, bool_text(failed), last_error));
}

static void log_move_api_result(const char* api, const std::string& old_original, const std::string& old_rewritten,
	path_rewrite_status old_status, const std::string& new_original, const std::string& new_rewritten,
	path_rewrite_status new_status, const std::string& result, bool failed, DWORD last_error)
{
	debug_log_line(std::format(
		"api={} old_original=\"{}\" old_rewritten=\"{}\" old_rewrite={} new_original=\"{}\" new_rewritten=\"{}\" new_rewrite={} result={} failed={} gle={}",
		api, old_original, old_rewritten, path_status_text(old_status), new_original, new_rewritten,
		path_status_text(new_status), result, bool_text(failed), last_error));
}

struct nt_object_name_snapshot
{
	USHORT length;
	USHORT maximum_length;
	PWSTR buffer;
	HANDLE root_directory;
	ULONG attributes;
};

static bool snapshot_nt_object_name(nt_object_attributes_t* object_attributes, nt_object_name_snapshot* snapshot)
{
	if (!object_attributes || !snapshot)
	{
		return false;
	}

	bool ok = false;
	__try
	{
		if (object_attributes->ObjectName)
		{
			snapshot->length = object_attributes->ObjectName->Length;
			snapshot->maximum_length = object_attributes->ObjectName->MaximumLength;
			snapshot->buffer = object_attributes->ObjectName->Buffer;
			snapshot->root_directory = object_attributes->RootDirectory;
			snapshot->attributes = object_attributes->Attributes;
			ok = true;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ok = false;
	}
	return ok;
}

static bool copy_nt_object_name_buffer(PWSTR source, wchar_t* target, USHORT bytes)
{
	if (!source || !target || !bytes)
	{
		return false;
	}

	bool ok = false;
	__try
	{
		std::memcpy(target, source, bytes);
		ok = true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ok = false;
	}
	return ok;
}

static bool read_handle_value(PHANDLE source, HANDLE* target)
{
	if (!source || !target)
	{
		return false;
	}

	bool ok = false;
	__try
	{
		*target = *source;
		ok = true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ok = false;
	}
	return ok;
}

static std::wstring nt_object_name_for_log(nt_object_attributes_t* object_attributes, nt_object_name_snapshot* snapshot)
{
	nt_object_name_snapshot local_snapshot = {};
	if (!snapshot_nt_object_name(object_attributes, &local_snapshot))
	{
		return L"<null>";
	}
	if (!local_snapshot.buffer || !local_snapshot.length)
	{
		if (snapshot)
		{
			*snapshot = local_snapshot;
		}
		return L"<empty>";
	}
	if (local_snapshot.length > local_snapshot.maximum_length ||
		local_snapshot.length % sizeof(wchar_t) != 0 ||
		local_snapshot.length > 32766)
	{
		if (snapshot)
		{
			*snapshot = local_snapshot;
		}
		return L"<invalid>";
	}

	std::wstring out(static_cast<size_t>(local_snapshot.length / sizeof(wchar_t)), L'\0');
	if (!copy_nt_object_name_buffer(local_snapshot.buffer, out.data(), local_snapshot.length))
	{
		if (snapshot)
		{
			*snapshot = local_snapshot;
		}
		return L"<unreadable>";
	}

	if (snapshot)
	{
		*snapshot = local_snapshot;
	}
	return out;
}

static std::string nt_status_text(nt_status_t status)
{
	return std::format("0x{:08x}", static_cast<unsigned long>(status));
}

static bool nt_success(nt_status_t status)
{
	return status >= 0;
}

static std::string successful_file_handle_text(nt_status_t status, PHANDLE file_handle)
{
	if (!nt_success(status))
	{
		return "<none>";
	}

	HANDLE handle = nullptr;
	if (!read_handle_value(file_handle, &handle))
	{
		return "<unreadable>";
	}
	return handle_text(handle);
}

static void log_nt_create_file_result(const std::string& original, const nt_object_name_snapshot& snapshot,
	ACCESS_MASK desired_access, ULONG create_options, ULONG create_disposition, nt_status_t status,
	const std::string& file_handle)
{
	debug_log_line(std::format(
		"api=NtCreateFile original_nt=\"{}\" root={} attributes=0x{:08x} desired_access=0x{:08x} create_options=0x{:08x} create_disposition=0x{:08x} status={} file_handle={}",
		original, handle_text(snapshot.root_directory), static_cast<unsigned long>(snapshot.attributes),
		static_cast<unsigned long>(desired_access), static_cast<unsigned long>(create_options),
		static_cast<unsigned long>(create_disposition), nt_status_text(status), file_handle));
}

static void log_nt_open_file_result(const std::string& original, const nt_object_name_snapshot& snapshot,
	ACCESS_MASK desired_access, ULONG open_options, nt_status_t status, const std::string& file_handle)
{
	debug_log_line(std::format(
		"api=NtOpenFile original_nt=\"{}\" root={} attributes=0x{:08x} desired_access=0x{:08x} open_options=0x{:08x} status={} file_handle={}",
		original, handle_text(snapshot.root_directory), static_cast<unsigned long>(snapshot.attributes),
		static_cast<unsigned long>(desired_access), static_cast<unsigned long>(open_options),
		nt_status_text(status), file_handle));
}

static void log_nt_path_rewrite(const char* api, const std::string& original, const nt_path_rewrite_result& rewritten)
{
	if (rewritten.status == path_rewrite_status::rewritten)
	{
		debug_log_line(std::format("api={} nt_path_rewrite original_nt=\"{}\" rewritten_nt=\"{}\" rewrite=rewritten",
			api, original, path_for_log(rewritten.nt_path)));
	}
	else if (rewritten.status == path_rewrite_status::blocked)
	{
		debug_log_line(std::format("api={} nt_path_rewrite original_nt=\"{}\" rewritten_nt=\"<blocked>\" rewrite=blocked",
			api, original));
	}
}

static void set_nt_io_status(nt_io_status_block_t* io_status_block, nt_status_t status)
{
	if (!io_status_block)
	{
		return;
	}

	__try
	{
		io_status_block->Status = status;
		io_status_block->Information = 0;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
}

nt_status_t NTAPI hooked_NtCreateFile(PHANDLE file_handle, ACCESS_MASK desired_access,
	nt_object_attributes_t* object_attributes, nt_io_status_block_t* io_status_block, PLARGE_INTEGER allocation_size,
	ULONG file_attributes, ULONG share_access, ULONG create_disposition, ULONG create_options, PVOID ea_buffer, ULONG ea_length)
{
	nt_object_name_snapshot snapshot = {};
	const std::wstring original_path = nt_object_name_for_log(object_attributes, &snapshot);
	const nt_path_rewrite_result rewritten = rewrite_nt_pawjob_path(original_path);
	const bool should_log = contains_keyword(original_path) || rewritten.status != path_rewrite_status::no_match;

	constexpr nt_status_t access_denied = static_cast<nt_status_t>(0xC0000022);
	nt_object_attributes_t rewritten_attributes = {};
	nt_unicode_string_t rewritten_name = {};
	nt_object_attributes_t* call_attributes = object_attributes;
	nt_status_t status = access_denied;
	if (rewritten.status == path_rewrite_status::blocked)
	{
		set_nt_io_status(io_status_block, status);
	}
	else
	{
		if (rewritten.status == path_rewrite_status::rewritten)
		{
			if (!make_rewritten_nt_object_attributes(object_attributes, rewritten.nt_path, &rewritten_attributes, &rewritten_name))
			{
				set_nt_io_status(io_status_block, status);
				if (should_log)
				{
					log_nt_path_rewrite("NtCreateFile", path_for_log(original_path),
						{ path_rewrite_status::blocked, {}, {} });
					log_nt_create_file_result(path_for_log(original_path), snapshot, desired_access, create_options,
						create_disposition, status, "<none>");
				}
				return status;
			}
			call_attributes = &rewritten_attributes;
		}

		status = oNtCreateFile(file_handle, desired_access, call_attributes, io_status_block,
			allocation_size, file_attributes, share_access, create_disposition, create_options, ea_buffer, ea_length);
	}

	if (should_log)
	{
		log_nt_path_rewrite("NtCreateFile", path_for_log(original_path), rewritten);
		log_nt_create_file_result(path_for_log(original_path), snapshot, desired_access, create_options,
			create_disposition, status, successful_file_handle_text(status, file_handle));
	}
	return status;
}

nt_status_t NTAPI hooked_NtOpenFile(PHANDLE file_handle, ACCESS_MASK desired_access,
	nt_object_attributes_t* object_attributes, nt_io_status_block_t* io_status_block, ULONG share_access, ULONG open_options)
{
	nt_object_name_snapshot snapshot = {};
	const std::wstring original_path = nt_object_name_for_log(object_attributes, &snapshot);
	const nt_path_rewrite_result rewritten = rewrite_nt_pawjob_path(original_path);
	const bool should_log = contains_keyword(original_path) || rewritten.status != path_rewrite_status::no_match;

	constexpr nt_status_t access_denied = static_cast<nt_status_t>(0xC0000022);
	nt_object_attributes_t rewritten_attributes = {};
	nt_unicode_string_t rewritten_name = {};
	nt_object_attributes_t* call_attributes = object_attributes;
	nt_status_t status = access_denied;
	if (rewritten.status == path_rewrite_status::blocked)
	{
		set_nt_io_status(io_status_block, status);
	}
	else
	{
		if (rewritten.status == path_rewrite_status::rewritten)
		{
			if (!make_rewritten_nt_object_attributes(object_attributes, rewritten.nt_path, &rewritten_attributes, &rewritten_name))
			{
				set_nt_io_status(io_status_block, status);
				if (should_log)
				{
					log_nt_path_rewrite("NtOpenFile", path_for_log(original_path),
						{ path_rewrite_status::blocked, {}, {} });
					log_nt_open_file_result(path_for_log(original_path), snapshot, desired_access, open_options, status,
						"<none>");
				}
				return status;
			}
			call_attributes = &rewritten_attributes;
		}

		status = oNtOpenFile(file_handle, desired_access, call_attributes, io_status_block, share_access, open_options);
	}

	if (should_log)
	{
		log_nt_path_rewrite("NtOpenFile", path_for_log(original_path), rewritten);
		log_nt_open_file_result(path_for_log(original_path), snapshot, desired_access, open_options, status,
			successful_file_handle_text(status, file_handle));
	}
	return status;
}

static bool safe_copy_bytes(const void* source, void* target, size_t bytes)
{
	if (!source || !target || !bytes)
	{
		return false;
	}

	bool ok = false;
	__try
	{
		std::memcpy(target, source, bytes);
		ok = true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ok = false;
	}
	return ok;
}

static bool safe_ascii_equals(LPCSTR text, INT count, const char* expected)
{
	if (!text || !expected)
	{
		return false;
	}

	const size_t expected_length = std::strlen(expected);
	if (count >= 0 && static_cast<size_t>(count) != expected_length)
	{
		return false;
	}

	for (size_t i = 0; i < expected_length; ++i)
	{
		char ch = 0;
		if (!safe_copy_bytes(text + i, &ch, sizeof(ch)) || ch != expected[i])
		{
			return false;
		}
	}

	if (count < 0)
	{
		char terminator = 0;
		if (!safe_copy_bytes(text + expected_length, &terminator, sizeof(terminator)) || terminator != '\0')
		{
			return false;
		}
	}
	return true;
}

static std::string safe_ascii_preview(LPCSTR text, INT count, size_t limit = 32)
{
	if (!text)
	{
		return "<null>";
	}

	std::string preview;
	const size_t max_count = count >= 0 ? static_cast<size_t>(count) : limit;
	const size_t bytes_to_read = (std::min)(max_count, limit);
	preview.reserve(bytes_to_read);
	for (size_t i = 0; i < bytes_to_read; ++i)
	{
		char ch = 0;
		if (!safe_copy_bytes(text + i, &ch, sizeof(ch)))
		{
			preview += "<unreadable>";
			break;
		}
		if (count < 0 && ch == '\0')
		{
			break;
		}
		preview.push_back(ch >= 0x20 && ch < 0x7f ? ch : '.');
	}
	return preview;
}

enum class render_brand_match
{
	none,
	full,
	prefix,
	suffix
};

static render_brand_match classify_brand_text(LPCSTR text, INT count)
{
	if (safe_ascii_equals(text, count, "moneybot") || safe_ascii_equals(text, count, "Moneybot") ||
		safe_ascii_equals(text, count, "MoneyBot") || safe_ascii_equals(text, count, "MONEYBOT") ||
		safe_ascii_equals(text, count, "pawjob") || safe_ascii_equals(text, count, "Pawjob") ||
		safe_ascii_equals(text, count, "PawJob") || safe_ascii_equals(text, count, "PAWJOB"))
	{
		return render_brand_match::full;
	}
	if (safe_ascii_equals(text, count, "money") || safe_ascii_equals(text, count, "Money") ||
		safe_ascii_equals(text, count, "MONEY") || safe_ascii_equals(text, count, "paw") ||
		safe_ascii_equals(text, count, "Paw") || safe_ascii_equals(text, count, "PAW"))
	{
		return render_brand_match::prefix;
	}
	if (safe_ascii_equals(text, count, "bot") || safe_ascii_equals(text, count, "Bot") ||
		safe_ascii_equals(text, count, "BOT") || safe_ascii_equals(text, count, "job") ||
		safe_ascii_equals(text, count, "Job") || safe_ascii_equals(text, count, "JOB"))
	{
		return render_brand_match::suffix;
	}
	return render_brand_match::none;
}

static const char* brand_match_name(render_brand_match match)
{
	switch (match)
	{
	case render_brand_match::full:
		return "full";
	case render_brand_match::prefix:
		return "prefix";
	case render_brand_match::suffix:
		return "suffix";
	default:
		return "none";
	}
}

static std::string rect_for_log(const RECT* rect)
{
	if (!rect)
	{
		return "<null>";
	}
	return std::format("{},{},{},{}", rect->left, rect->top, rect->right, rect->bottom);
}

static DWORD color_with_original_alpha(DWORD original, DWORD rgb)
{
	DWORD alpha = original & 0xff000000;
	if (!alpha)
	{
		alpha = 0xff000000;
	}
	return alpha | (rgb & 0x00ffffff);
}

static bool is_candidate_menu_accent(DWORD color)
{
	const DWORD rgb = color & 0x00ffffff;
	const DWORD red = (rgb >> 16) & 0xff;
	const DWORD green = (rgb >> 8) & 0xff;
	const DWORD blue = rgb & 0xff;
	const DWORD max_channel = red > green ? (red > blue ? red : blue) : (green > blue ? green : blue);
	const DWORD min_channel = red < green ? (red < blue ? red : blue) : (green < blue ? green : blue);
	return max_channel >= 120 && max_channel - min_channel >= 48;
}

static DWORD brand_accent_color(DWORD original_color)
{
	return color_with_original_alpha(original_color, g_brand_accent_rgb.load());
}

static bool is_likely_shadow_text_color(DWORD color)
{
	const DWORD alpha = (color >> 24) & 0xff;
	if (alpha && alpha < 96)
	{
		return true;
	}

	const DWORD rgb = color & 0x00ffffff;
	const DWORD red = (rgb >> 16) & 0xff;
	const DWORD green = (rgb >> 8) & 0xff;
	const DWORD blue = rgb & 0xff;
	const DWORD max_channel = red > green ? (red > blue ? red : blue) : (green > blue ? green : blue);
	return max_channel < 96;
}

static void cache_menu_accent_rgb(DWORD rgb, DWORD logged_color, uintptr_t caller, const char* source)
{
	rgb &= 0x00ffffff;
	const DWORD previous = g_brand_accent_rgb.exchange(rgb);
	static std::atomic_int log_count = 0;
	if (previous != rgb && log_count.fetch_add(1) < 16)
	{
		debug_log_line(std::format("render_branding accent_cache source={} color=0x{:08x} rgb=0x{:06x} caller={}",
			source, logged_color, rgb, exception_address_text(caller)));
	}
}

static void maybe_cache_menu_accent_color(DWORD color, uintptr_t caller, const char* source)
{
	if (!is_candidate_menu_accent(color))
	{
		return;
	}

	cache_menu_accent_rgb(color & 0x00ffffff, color, caller, source);
}

static bool read_vertex_color(const void* vertex_data, UINT stride, UINT index, size_t color_offset, DWORD* color)
{
	if (!vertex_data || !color || stride < color_offset + sizeof(*color))
	{
		return false;
	}

	const auto* base = static_cast<const uint8_t*>(vertex_data);
	return safe_copy_bytes(base + static_cast<size_t>(index) * stride + color_offset, color, sizeof(*color));
}

static bool read_uniform_candidate_vertex_color(const void* vertex_data, UINT stride, DWORD* color)
{
	const size_t offsets[] = { 16, 12 };
	for (size_t color_offset : offsets)
	{
		DWORD first = 0;
		DWORD second = 0;
		if (!read_vertex_color(vertex_data, stride, 0, color_offset, &first) ||
			!read_vertex_color(vertex_data, stride, 1, color_offset, &second))
		{
			continue;
		}
		if ((first & 0x00ffffff) == (second & 0x00ffffff) && is_candidate_menu_accent(first))
		{
			*color = first;
			return true;
		}
	}
	return false;
}

static void maybe_cache_menu_accent_swatch_primitive(const void* vertex_data, UINT stride, uintptr_t caller, const char* source)
{
	if (t_menu_accent_swatch_primitive_budget <= 0)
	{
		return;
	}

	--t_menu_accent_swatch_primitive_budget;
	DWORD color = 0;
	if (!read_uniform_candidate_vertex_color(vertex_data, stride, &color))
	{
		return;
	}

	t_menu_accent_swatch_primitive_budget = 0;
	cache_menu_accent_rgb(color & 0x00ffffff, color, caller, source);
}

static void log_brand_render_rewrite_once(render_brand_match match)
{
	static std::atomic_bool logged_full = false;
	static std::atomic_bool logged_prefix = false;
	static std::atomic_bool logged_suffix = false;

	std::atomic_bool* flag = &logged_full;
	const char* label = "full";
	if (match == render_brand_match::prefix)
	{
		flag = &logged_prefix;
		label = "prefix";
	}
	else if (match == render_brand_match::suffix)
	{
		flag = &logged_suffix;
		label = "suffix";
	}

	bool expected = false;
	if (flag->compare_exchange_strong(expected, true))
	{
		debug_log_line(std::format("render_branding rewrite match={} accent_rgb=0x{:06x} caller={}",
			label, g_brand_accent_rgb.load(), exception_address_text(reinterpret_cast<uintptr_t>(_ReturnAddress()))));
	}
}

static void log_brand_render_draw(render_brand_match match, LPCSTR text, INT count, RECT* rect, DWORD format,
	DWORD color, uintptr_t caller, const char* action)
{
	static std::atomic_int budget = 96;
	const int previous = budget.fetch_sub(1);
	if (previous <= 0)
	{
		return;
	}

	debug_log_line(std::format(
		"render_branding draw match={} action={} text=\"{}\" count={} format=0x{:08x} color=0x{:08x} rect={} caller={}",
		brand_match_name(match), action, safe_ascii_preview(text, count), count,
		static_cast<unsigned long>(format), static_cast<unsigned long>(color),
		rect_for_log(rect), exception_address_text(caller)));
}

static LONG abs_delta(LONG a, LONG b)
{
	return a > b ? a - b : b - a;
}

static bool rect_line_near(const RECT& a, const RECT& b)
{
	return abs_delta(a.top, b.top) <= 4 && abs_delta(a.bottom, b.bottom) <= 4;
}

static bool rect_inside_or_near(const RECT& outer, const RECT& inner)
{
	return rect_line_near(outer, inner) &&
		inner.left >= outer.left - 8 &&
		inner.right <= outer.right + 32;
}

static void remember_full_brand_draw(const RECT* rect)
{
	if (!rect)
	{
		return;
	}

	t_last_full_brand_rect = *rect;
	t_last_full_brand_tick = GetTickCount();
	t_has_last_full_brand_rect = true;
}

static bool follows_recent_full_brand_draw(const RECT* rect)
{
	if (!rect)
	{
		return false;
	}

	if (!t_has_last_full_brand_rect)
	{
		return false;
	}

	const DWORD now = GetTickCount();
	return now - t_last_full_brand_tick <= 5 && rect_inside_or_near(t_last_full_brand_rect, *rect);
}

static DWORD left_aligned_format(DWORD format)
{
	return (format & ~(DT_CENTER | DT_RIGHT)) | DT_LEFT;
}

static int measure_d3dx_text_width(void* font, void* sprite, const char* text, DWORD format)
{
	RECT measure_rect = { 0, 0, 0, 0 };
	const DWORD measure_format = left_aligned_format(format) | DT_CALCRECT;
	oD3DXFontDrawTextA(font, sprite, text, -1, &measure_rect, measure_format, 0xffffffff);
	const LONG width = measure_rect.right - measure_rect.left;
	return width > 0 ? width : 0;
}

static INT draw_split_brand_text(void* font, void* sprite, RECT* rect, DWORD format, DWORD original_color)
{
	if (!rect)
	{
		return oD3DXFontDrawTextA(font, sprite, "pawjob", -1, rect, format, color_with_original_alpha(original_color, 0x00ffffff));
	}

	const int paw_width = measure_d3dx_text_width(font, sprite, "paw", format);
	const int job_width = measure_d3dx_text_width(font, sprite, "job", format);
	const int full_width = paw_width + job_width;

	LONG left = rect->left;
	if (format & DT_CENTER)
	{
		const LONG centered_offset = (rect->right - rect->left - full_width) / 2;
		left = rect->left + (centered_offset > 0 ? centered_offset : 0);
	}
	else if (format & DT_RIGHT)
	{
		left = rect->right - full_width;
	}

	RECT paw_rect = *rect;
	paw_rect.left = left;
	paw_rect.right = left + paw_width;

	RECT job_rect = *rect;
	job_rect.left = left + paw_width;
	job_rect.right = left + full_width;

	const DWORD draw_format = left_aligned_format(format);
	const INT paw_result = oD3DXFontDrawTextA(font, sprite, "paw", -1, &paw_rect, draw_format,
		color_with_original_alpha(original_color, 0x00ffffff));
	const INT job_result = oD3DXFontDrawTextA(font, sprite, "job", -1, &job_rect, draw_format,
		brand_accent_color(original_color));
	return paw_result > job_result ? paw_result : job_result;
}

static INT suppress_duplicate_brand_segment(void* font, void* sprite, LPCSTR text, INT count, RECT* rect, DWORD format, DWORD color)
{
	if (!rect)
	{
		return 0;
	}

	RECT measure_rect = *rect;
	return oD3DXFontDrawTextA(font, sprite, text, count, &measure_rect, left_aligned_format(format) | DT_CALCRECT, color);
}

INT WINAPI hooked_D3DXFontDrawTextA(void* font, void* sprite, LPCSTR text, INT count, RECT* rect, DWORD format, DWORD color)
{
	const uintptr_t caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
	if (safe_ascii_equals(text, count, "Menu Accent"))
	{
		t_menu_accent_swatch_primitive_budget = 32;
	}

	const render_brand_match match = classify_brand_text(text, count);
	if (match == render_brand_match::full)
	{
		log_brand_render_rewrite_once(match);
		log_brand_render_draw(match, text, count, rect, format, color, caller,
			(format & DT_CALCRECT) ? "measure_full" : "draw_full");
		if (format & DT_CALCRECT)
		{
			return oD3DXFontDrawTextA(font, sprite, "pawjob", -1, rect, format, color);
		}
		if (is_likely_shadow_text_color(color))
		{
			log_brand_render_draw(match, text, count, rect, format, color, caller, "suppress_shadow");
			return suppress_duplicate_brand_segment(font, sprite, text, count, rect, format, color);
		}
		const INT result = draw_split_brand_text(font, sprite, rect, format, color);
		remember_full_brand_draw(rect);
		return result;
	}
	if (match == render_brand_match::prefix)
	{
		log_brand_render_rewrite_once(match);
		log_brand_render_draw(match, text, count, rect, format, color, caller,
			(format & DT_CALCRECT) ? "measure_prefix" : "draw_prefix");
		if (format & DT_CALCRECT)
		{
			return oD3DXFontDrawTextA(font, sprite, "paw", -1, rect, format,
				color_with_original_alpha(color, 0x00ffffff));
		}
		if (is_likely_shadow_text_color(color))
		{
			log_brand_render_draw(match, text, count, rect, format, color, caller, "suppress_shadow");
			return suppress_duplicate_brand_segment(font, sprite, text, count, rect, format, color);
		}
		if (follows_recent_full_brand_draw(rect))
		{
			log_brand_render_draw(match, text, count, rect, format, color, caller, "suppress_after_full");
			return suppress_duplicate_brand_segment(font, sprite, text, count, rect, format, color);
		}
		return oD3DXFontDrawTextA(font, sprite, "paw", -1, rect, format,
			color_with_original_alpha(color, 0x00ffffff));
	}
	if (match == render_brand_match::suffix)
	{
		log_brand_render_rewrite_once(match);
		maybe_cache_menu_accent_color(color, caller, "brand_suffix_draw");
		log_brand_render_draw(match, text, count, rect, format, color, caller,
			(format & DT_CALCRECT) ? "measure_suffix" : "draw_suffix");
		if (format & DT_CALCRECT)
		{
			return oD3DXFontDrawTextA(font, sprite, "job", -1, rect, format, brand_accent_color(color));
		}
		if (is_likely_shadow_text_color(color))
		{
			log_brand_render_draw(match, text, count, rect, format, color, caller, "suppress_shadow");
			return suppress_duplicate_brand_segment(font, sprite, text, count, rect, format, color);
		}
		if (follows_recent_full_brand_draw(rect))
		{
			log_brand_render_draw(match, text, count, rect, format, color, caller, "suppress_after_full");
			return suppress_duplicate_brand_segment(font, sprite, text, count, rect, format, color);
		}
		return oD3DXFontDrawTextA(font, sprite, "job", -1, rect, format, color);
	}
	return oD3DXFontDrawTextA(font, sprite, text, count, rect, format, color);
}

static void try_install_d3dx_font_draw_text_hook(void* font)
{
	if (!font || g_d3dx_font_draw_text_a_hooked)
	{
		return;
	}

	void** vtable = nullptr;
	if (!safe_copy_bytes(font, &vtable, sizeof(vtable)) || !vtable)
	{
		debug_log_line(std::format("render_branding font={} result=missing_vtable",
			exception_address_text(reinterpret_cast<uintptr_t>(font))));
		return;
	}

	void* draw_text_a = nullptr;
	if (!safe_copy_bytes(vtable + 14, &draw_text_a, sizeof(draw_text_a)) || !draw_text_a)
	{
		debug_log_line(std::format("render_branding font={} vtable={} result=missing_draw_text_a",
			exception_address_text(reinterpret_cast<uintptr_t>(font)),
			exception_address_text(reinterpret_cast<uintptr_t>(vtable))));
		return;
	}

	if (g_d3dx_font_draw_text_a_target && g_d3dx_font_draw_text_a_target != draw_text_a)
	{
		debug_log_line(std::format("render_branding draw_text_a={} result=target_changed existing={}",
			exception_address_text(reinterpret_cast<uintptr_t>(draw_text_a)),
			exception_address_text(reinterpret_cast<uintptr_t>(g_d3dx_font_draw_text_a_target))));
		return;
	}

	g_d3dx_font_draw_text_a_target = draw_text_a;
	MH_STATUS status = MH_CreateHook(draw_text_a, hooked_D3DXFontDrawTextA, reinterpret_cast<void**>(&oD3DXFontDrawTextA));
	if (status == MH_ERROR_ALREADY_CREATED)
	{
		status = MH_OK;
	}
	log_minhook_status("MH_CreateHook", "ID3DXFont::DrawTextA", status);
	if (status != MH_OK)
	{
		return;
	}

	status = MH_EnableHook(draw_text_a);
	log_minhook_status("MH_EnableHook", "ID3DXFont::DrawTextA", status);
	g_d3dx_font_draw_text_a_hooked = status == MH_OK || status == MH_ERROR_ENABLED;
}

HRESULT WINAPI hooked_D3DDrawPrimitiveUP(void* device, unsigned int primitive_type, UINT primitive_count,
	const void* vertex_stream_zero_data, UINT vertex_stream_zero_stride)
{
	maybe_cache_menu_accent_swatch_primitive(vertex_stream_zero_data, vertex_stream_zero_stride,
		reinterpret_cast<uintptr_t>(_ReturnAddress()), "IDirect3DDevice9::DrawPrimitiveUP");
	return oD3DDrawPrimitiveUP(device, primitive_type, primitive_count, vertex_stream_zero_data, vertex_stream_zero_stride);
}

HRESULT WINAPI hooked_D3DDrawIndexedPrimitiveUP(void* device, unsigned int primitive_type, UINT min_vertex_index,
	UINT num_vertices, UINT primitive_count, const void* index_data, unsigned int index_data_format,
	const void* vertex_stream_zero_data, UINT vertex_stream_zero_stride)
{
	maybe_cache_menu_accent_swatch_primitive(vertex_stream_zero_data, vertex_stream_zero_stride,
		reinterpret_cast<uintptr_t>(_ReturnAddress()), "IDirect3DDevice9::DrawIndexedPrimitiveUP");
	return oD3DDrawIndexedPrimitiveUP(device, primitive_type, min_vertex_index, num_vertices, primitive_count,
		index_data, index_data_format, vertex_stream_zero_data, vertex_stream_zero_stride);
}

static void try_install_d3d_device_hooks(void* device)
{
	if (!device)
	{
		return;
	}

	void** vtable = nullptr;
	if (!safe_copy_bytes(device, &vtable, sizeof(vtable)) || !vtable)
	{
		debug_log_line(std::format("render_branding device={} result=missing_vtable",
			exception_address_text(reinterpret_cast<uintptr_t>(device))));
		return;
	}

	if (!g_d3d_draw_primitive_up_hooked)
	{
		void* draw_primitive_up = nullptr;
		if (safe_copy_bytes(vtable + 83, &draw_primitive_up, sizeof(draw_primitive_up)) && draw_primitive_up)
		{
			if (!g_d3d_draw_primitive_up_target || g_d3d_draw_primitive_up_target == draw_primitive_up)
			{
				g_d3d_draw_primitive_up_target = draw_primitive_up;
				MH_STATUS status = MH_CreateHook(draw_primitive_up, hooked_D3DDrawPrimitiveUP,
					reinterpret_cast<void**>(&oD3DDrawPrimitiveUP));
				if (status == MH_ERROR_ALREADY_CREATED)
				{
					status = MH_OK;
				}
				log_minhook_status("MH_CreateHook", "IDirect3DDevice9::DrawPrimitiveUP", status);
				if (status == MH_OK)
				{
					status = MH_EnableHook(draw_primitive_up);
					log_minhook_status("MH_EnableHook", "IDirect3DDevice9::DrawPrimitiveUP", status);
					g_d3d_draw_primitive_up_hooked = status == MH_OK || status == MH_ERROR_ENABLED;
				}
			}
		}
	}

	if (!g_d3d_draw_indexed_primitive_up_hooked)
	{
		void* draw_indexed_primitive_up = nullptr;
		if (safe_copy_bytes(vtable + 84, &draw_indexed_primitive_up, sizeof(draw_indexed_primitive_up)) &&
			draw_indexed_primitive_up)
		{
			if (!g_d3d_draw_indexed_primitive_up_target || g_d3d_draw_indexed_primitive_up_target == draw_indexed_primitive_up)
			{
				g_d3d_draw_indexed_primitive_up_target = draw_indexed_primitive_up;
				MH_STATUS status = MH_CreateHook(draw_indexed_primitive_up, hooked_D3DDrawIndexedPrimitiveUP,
					reinterpret_cast<void**>(&oD3DDrawIndexedPrimitiveUP));
				if (status == MH_ERROR_ALREADY_CREATED)
				{
					status = MH_OK;
				}
				log_minhook_status("MH_CreateHook", "IDirect3DDevice9::DrawIndexedPrimitiveUP", status);
				if (status == MH_OK)
				{
					status = MH_EnableHook(draw_indexed_primitive_up);
					log_minhook_status("MH_EnableHook", "IDirect3DDevice9::DrawIndexedPrimitiveUP", status);
					g_d3d_draw_indexed_primitive_up_hooked = status == MH_OK || status == MH_ERROR_ENABLED;
				}
			}
		}
	}
}

HRESULT WINAPI hooked_D3DXCreateFontA(void* device, INT height, UINT width, UINT weight, UINT mip_levels,
	BOOL italic, DWORD char_set, DWORD output_precision, DWORD quality, DWORD pitch_and_family,
	LPCSTR face_name, void** font)
{
	const HRESULT result = oD3DXCreateFontA(device, height, width, weight, mip_levels, italic, char_set,
		output_precision, quality, pitch_and_family, face_name, font);
	try_install_d3d_device_hooks(device);
	debug_log_line(std::format("api=D3DXCreateFontA result=0x{:08x} font={}",
		static_cast<unsigned long>(result), font && SUCCEEDED(result) ? handle_text(*font) : "<none>"));
	if (SUCCEEDED(result) && font && *font)
	{
		try_install_d3dx_font_draw_text_hook(*font);
	}
	return result;
}

HRESULT WINAPI hooked_D3DXLineDraw(void* line, const void* vertex_list, DWORD vertex_count, DWORD color)
{
	maybe_cache_menu_accent_color(color, reinterpret_cast<uintptr_t>(_ReturnAddress()), "ID3DXLine::Draw");
	return oD3DXLineDraw(line, vertex_list, vertex_count, color);
}

static void try_install_d3dx_line_draw_hook(void* line)
{
	if (!line || g_d3dx_line_draw_hooked)
	{
		return;
	}

	void** vtable = nullptr;
	if (!safe_copy_bytes(line, &vtable, sizeof(vtable)) || !vtable)
	{
		debug_log_line(std::format("render_branding line={} result=missing_vtable",
			exception_address_text(reinterpret_cast<uintptr_t>(line))));
		return;
	}

	void* draw = nullptr;
	if (!safe_copy_bytes(vtable + 5, &draw, sizeof(draw)) || !draw)
	{
		debug_log_line(std::format("render_branding line={} vtable={} result=missing_line_draw",
			exception_address_text(reinterpret_cast<uintptr_t>(line)),
			exception_address_text(reinterpret_cast<uintptr_t>(vtable))));
		return;
	}

	if (g_d3dx_line_draw_target && g_d3dx_line_draw_target != draw)
	{
		debug_log_line(std::format("render_branding line_draw={} result=target_changed existing={}",
			exception_address_text(reinterpret_cast<uintptr_t>(draw)),
			exception_address_text(reinterpret_cast<uintptr_t>(g_d3dx_line_draw_target))));
		return;
	}

	g_d3dx_line_draw_target = draw;
	MH_STATUS status = MH_CreateHook(draw, hooked_D3DXLineDraw, reinterpret_cast<void**>(&oD3DXLineDraw));
	if (status == MH_ERROR_ALREADY_CREATED)
	{
		status = MH_OK;
	}
	log_minhook_status("MH_CreateHook", "ID3DXLine::Draw", status);
	if (status != MH_OK)
	{
		return;
	}

	status = MH_EnableHook(draw);
	log_minhook_status("MH_EnableHook", "ID3DXLine::Draw", status);
	g_d3dx_line_draw_hooked = status == MH_OK || status == MH_ERROR_ENABLED;
}

HRESULT WINAPI hooked_D3DXCreateLine(void* device, void** line)
{
	const HRESULT result = oD3DXCreateLine(device, line);
	try_install_d3d_device_hooks(device);
	debug_log_line(std::format("api=D3DXCreateLine result=0x{:08x} line={}",
		static_cast<unsigned long>(result), line && SUCCEEDED(result) ? handle_text(*line) : "<none>"));
	if (SUCCEEDED(result) && line && *line)
	{
		try_install_d3dx_line_draw_hook(*line);
	}
	return result;
}

static bool safe_read_dword_value(LPDWORD source, DWORD* target)
{
	return safe_copy_bytes(source, target, sizeof(*target));
}

static bool safe_read_wsabuf_item(LPWSABUF buffers, DWORD index, ULONG* length, CHAR** buffer)
{
	if (!buffers || !length || !buffer)
	{
		return false;
	}

	bool ok = false;
	__try
	{
		*length = buffers[index].len;
		*buffer = buffers[index].buf;
		ok = true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ok = false;
	}
	return ok;
}

static std::string socket_text(SOCKET socket_value)
{
	return std::format("0x{:08x}", static_cast<uintptr_t>(socket_value));
}

static std::string bytes_to_hex(const uint8_t* bytes, size_t count)
{
	if (!bytes || !count)
	{
		return "<empty>";
	}

	static constexpr char digits[] = "0123456789abcdef";
	std::string out;
	out.reserve(count * 3);
	for (size_t i = 0; i < count; ++i)
	{
		if (i)
		{
			out.push_back(' ');
		}
		out.push_back(digits[(bytes[i] >> 4) & 0x0F]);
		out.push_back(digits[bytes[i] & 0x0F]);
	}
	return out;
}

static std::string buffer_preview_hex(const char* buffer, int length)
{
	if (!buffer)
	{
		return "<null>";
	}
	if (length <= 0)
	{
		return "<empty>";
	}

	std::array<uint8_t, 64> preview = {};
	const size_t bytes_to_copy = std::min<size_t>(static_cast<size_t>(length), preview.size());
	if (!safe_copy_bytes(buffer, preview.data(), bytes_to_copy))
	{
		return "<unreadable>";
	}
	return bytes_to_hex(preview.data(), bytes_to_copy);
}

static std::string bytes_to_ascii_for_log(const uint8_t* bytes, size_t count)
{
	if (!bytes || !count)
	{
		return "<empty>";
	}

	std::string out;
	out.reserve(count);
	for (size_t i = 0; i < count; ++i)
	{
		const uint8_t ch = bytes[i];
		if (ch >= 0x20 && ch <= 0x7e && ch != '"' && ch != '\\')
		{
			out.push_back(static_cast<char>(ch));
		}
		else
		{
			out.push_back('.');
		}
	}
	return out;
}

static std::string pointer_preview_hex(const void* buffer, size_t length, size_t limit)
{
	if (!buffer)
	{
		return "<null>";
	}
	if (!length || !limit)
	{
		return "<empty>";
	}

	std::array<uint8_t, 256> preview = {};
	const size_t bytes_to_copy = std::min<size_t>(std::min<size_t>(length, limit), preview.size());
	if (!safe_copy_bytes(buffer, preview.data(), bytes_to_copy))
	{
		return "<unreadable>";
	}
	return bytes_to_hex(preview.data(), bytes_to_copy);
}

static std::string pointer_preview_ascii(const void* buffer, size_t length, size_t limit)
{
	if (!buffer)
	{
		return "<null>";
	}
	if (!length || !limit)
	{
		return "<empty>";
	}

	std::array<uint8_t, 256> preview = {};
	const size_t bytes_to_copy = std::min<size_t>(std::min<size_t>(length, limit), preview.size());
	if (!safe_copy_bytes(buffer, preview.data(), bytes_to_copy))
	{
		return "<unreadable>";
	}
	return bytes_to_ascii_for_log(preview.data(), bytes_to_copy);
}

static std::string msvc_string_summary(const void* string_object, size_t preview_limit)
{
	if (!string_object)
	{
		return "object=<null>";
	}

	const auto base = reinterpret_cast<uintptr_t>(string_object);
	uint32_t size = 0;
	uint32_t capacity = 0;
	if (!safe_copy_bytes(reinterpret_cast<const void*>(base + 0x10), &size, sizeof(size)) ||
		!safe_copy_bytes(reinterpret_cast<const void*>(base + 0x14), &capacity, sizeof(capacity)))
	{
		return std::format("object={} unreadable_header=true", exception_address_text(base));
	}

	if (size > 1024 * 1024 || capacity > 1024 * 1024)
	{
		return std::format("object={} invalid_header=true size={} capacity={}",
			exception_address_text(base), size, capacity);
	}

	uintptr_t data = base;
	if (capacity >= 0x10)
	{
		if (!safe_copy_bytes(string_object, &data, sizeof(data)) || !data)
		{
			return std::format("object={} size={} capacity={} data=<unreadable>",
				exception_address_text(base), size, capacity);
		}
	}

	return std::format("object={} size={} capacity={} data={} hex=\"{}\" ascii=\"{}\"",
		exception_address_text(base), size, capacity, exception_address_text(data),
		pointer_preview_hex(reinterpret_cast<const void*>(data), size, preview_limit),
		pointer_preview_ascii(reinterpret_cast<const void*>(data), size, preview_limit));
}

static std::string c_string_summary(const char* text, size_t preview_limit)
{
	if (!text)
	{
		return "ptr=<null>";
	}

	size_t length = 0;
	bool terminated = false;
	const size_t scan_limit = std::min<size_t>(preview_limit, 1024);
	for (; length < scan_limit; ++length)
	{
		char ch = 0;
		if (!safe_copy_bytes(text + length, &ch, sizeof(ch)))
		{
			return std::format("ptr={} unreadable=true length_scanned={}",
				exception_address_text(reinterpret_cast<uintptr_t>(text)), length);
		}
		if (ch == '\0')
		{
			terminated = true;
			break;
		}
	}

	return std::format("ptr={} length={} terminated={} hex=\"{}\" ascii=\"{}\"",
		exception_address_text(reinterpret_cast<uintptr_t>(text)), length, bool_text(terminated),
		pointer_preview_hex(text, length, preview_limit), pointer_preview_ascii(text, length, preview_limit));
}

static bool address_in_range(uintptr_t address, uintptr_t start, uintptr_t size)
{
	return address >= start && address < start + size;
}

static bool is_cloud_parser_address(uintptr_t address)
{
	return address_in_range(address, 0x4bf60000, 0x8000) ||
		address_in_range(address, 0x50370000, 0xd000) ||
		address_in_range(address, 0x65980000, 0x9000) ||
		address_in_range(address, 0x7aae0000, 0xe000) ||
		address_in_range(address, 0x7ead0000, 0xd000) ||
		address_in_range(address, 0x45ae0000, 0x14000);
}

static const char* known_dump_region_label(uintptr_t address)
{
	if (address_in_range(address, 0x4bf60000, 0x8000))
	{
		return "cloud_parser";
	}
	if (address_in_range(address, 0x50370000, 0xd000))
	{
		return "cloud_frame";
	}
	if (address_in_range(address, 0x65980000, 0x9000))
	{
		return "config_load_handler";
	}
	if (address_in_range(address, 0x7aae0000, 0xe000))
	{
		return "cloud_command_sender";
	}
	if (address_in_range(address, 0x7ead0000, 0xd000))
	{
		return "config_list_handler";
	}
	if (address_in_range(address, 0x45ae0000, 0x14000))
	{
		return "config_load_apply";
	}
	if (address_in_range(address, 0x44a50000, 0xc000))
	{
		return "cloud_compare";
	}
	if (address_in_range(address, 0x70480000, 0xb000))
	{
		return "known_breakpoint_region";
	}
	if (address_in_range(address, 0x7fff0000, 0x1a76000))
	{
		return "main_hack_region";
	}
	return nullptr;
}

static void log_memory_snapshot(const char* label, uintptr_t address, size_t bytes)
{
	if (!address || !bytes)
	{
		debug_log_line(std::format("{} address={} bytes=0 hex=\"<empty>\" ascii=\"<empty>\"",
			label, exception_address_text(address)));
		return;
	}

	std::array<uint8_t, 256> preview = {};
	const size_t bytes_to_copy = std::min<size_t>(bytes, preview.size());
	if (!safe_copy_bytes(reinterpret_cast<const void*>(address), preview.data(), bytes_to_copy))
	{
		debug_log_line(std::format("{} address={} bytes={} hex=\"<unreadable>\" ascii=\"<unreadable>\"",
			label, exception_address_text(address), bytes_to_copy));
		return;
	}

	debug_log_line(std::format("{} address={} bytes={} hex=\"{}\" ascii=\"{}\"",
		label, exception_address_text(address), bytes_to_copy,
		bytes_to_hex(preview.data(), bytes_to_copy), bytes_to_ascii_for_log(preview.data(), bytes_to_copy)));
}

static void log_stack_code_references(uintptr_t esp)
{
	if (!esp)
	{
		return;
	}

	size_t logged = 0;
	for (size_t slot = 0; slot < 160 && logged < 40; ++slot)
	{
		uintptr_t value = 0;
		if (!safe_copy_bytes(reinterpret_cast<const void*>(esp + slot * sizeof(uintptr_t)), &value, sizeof(value)))
		{
			continue;
		}

		const char* label = known_dump_region_label(value);
		if (!label)
		{
			continue;
		}

		debug_log_line(std::format("exception_stack_ref slot={} stack_address={} value={} region={}",
			slot, exception_address_text(esp + slot * sizeof(uintptr_t)), exception_address_text(value), label));
		++logged;
	}
}

static void log_exception_context(PEXCEPTION_POINTERS exception_info)
{
	if (!exception_info || !exception_info->ContextRecord)
	{
		return;
	}

#if defined(_M_IX86)
	const CONTEXT* context = exception_info->ContextRecord;
	debug_log_line(std::format(
		"exception_context eax={} ebx={} ecx={} edx={} esi={} edi={} esp={} ebp={} eflags=0x{:08x} last_recv_socket={} last_recv_buffer={} last_recv_bytes={} last_recv_capacity={}",
		exception_address_text(context->Eax), exception_address_text(context->Ebx),
		exception_address_text(context->Ecx), exception_address_text(context->Edx),
		exception_address_text(context->Esi), exception_address_text(context->Edi),
		exception_address_text(context->Esp), exception_address_text(context->Ebp),
		static_cast<unsigned long>(context->EFlags), socket_text(g_tls_last_recv_socket),
		exception_address_text(g_tls_last_recv_buffer), g_tls_last_recv_bytes, g_tls_last_recv_capacity));

	log_memory_snapshot("exception_esp_bytes", context->Esp, 160);
	if (context->Ebp > 0x80)
	{
		log_memory_snapshot("exception_ebp_minus_0x80", context->Ebp - 0x80, 256);
	}
	if (g_tls_last_recv_buffer && g_tls_last_recv_bytes)
	{
		log_memory_snapshot("exception_last_recv_buffer", g_tls_last_recv_buffer,
			std::min<DWORD>(g_tls_last_recv_capacity, 1024));
	}
	log_stack_code_references(context->Esp);
#endif
}

unsigned char __cdecl hooked_cloud_compare(const void* lhs, uint32_t lhs_length, const void* rhs, uint32_t rhs_length)
{
	const uintptr_t caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
	const unsigned char result = oCloudCompare ? oCloudCompare(lhs, lhs_length, rhs, rhs_length) : 0;
	if (g_cloud_parser_trace && is_cloud_parser_address(caller))
	{
		const char* caller_region = known_dump_region_label(caller);
		debug_log_line(std::format(
			"api=cloud_compare caller={} caller_region={} lhs={} lhs_len={} lhs_hex=\"{}\" lhs_ascii=\"{}\" rhs={} rhs_len={} rhs_hex=\"{}\" rhs_ascii=\"{}\" result={}",
			exception_address_text(caller), caller_region ? caller_region : "<unknown>",
			exception_address_text(reinterpret_cast<uintptr_t>(lhs)), lhs_length,
			pointer_preview_hex(lhs, lhs_length, 96), pointer_preview_ascii(lhs, lhs_length, 96),
			exception_address_text(reinterpret_cast<uintptr_t>(rhs)), rhs_length,
			pointer_preview_hex(rhs, rhs_length, 96), pointer_preview_ascii(rhs, rhs_length, 96),
			static_cast<unsigned int>(result)));
	}
	return result;
}

void __fastcall hooked_cloud_crypto_set_bytes(void* self, void* /*edx*/, const void* data, uint32_t length)
{
	const uintptr_t caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
	if (g_cloud_parser_trace && is_cloud_parser_address(caller))
	{
		uintptr_t vtable = 0;
		if (self)
		{
			(void)safe_copy_bytes(self, &vtable, sizeof(vtable));
		}

		debug_log_line(std::format(
			"api=cloud_crypto_set_bytes caller={} self={} vtable={} data={} length={} data_hex=\"{}\" data_ascii=\"{}\"",
			exception_address_text(caller), exception_address_text(reinterpret_cast<uintptr_t>(self)),
			exception_address_text(vtable), exception_address_text(reinterpret_cast<uintptr_t>(data)), length,
			pointer_preview_hex(data, length, 128), pointer_preview_ascii(data, length, 128)));
	}

	if (oCloudCryptoSetBytes)
	{
		oCloudCryptoSetBytes(self, data, length);
	}
}

static bool read_server_status_string(const void* status, uint32_t* code, std::string* message)
{
	if (code)
	{
		*code = 0;
	}
	if (message)
	{
		*message = "<null>";
	}
	if (!status)
	{
		return false;
	}

	const auto* base = static_cast<const uint8_t*>(status);
	uint32_t local_code = 0;
	uint32_t size = 0;
	uint32_t capacity = 0;
	if (!safe_copy_bytes(base, &local_code, sizeof(local_code)) ||
		!safe_copy_bytes(base + 20, &size, sizeof(size)) ||
		!safe_copy_bytes(base + 24, &capacity, sizeof(capacity)))
	{
		if (message)
		{
			*message = "<unreadable-header>";
		}
		return false;
	}

	if (code)
	{
		*code = local_code;
	}

	if (!message)
	{
		return true;
	}

	if (size > 512)
	{
		*message = std::format("<invalid-size:{} capacity:{}>", size, capacity);
		return false;
	}

	const void* data = base + 4;
	if (capacity >= 16)
	{
		if (!safe_copy_bytes(base + 4, &data, sizeof(data)) || !data)
		{
			*message = "<unreadable-data-pointer>";
			return false;
		}
	}

	*message = pointer_preview_ascii(data, size, 256);
	return true;
}

void* __cdecl hooked_server_status_check(void* status)
{
	void* result = oServerStatusCheck ? oServerStatusCheck(status) : nullptr;
	if (g_cloud_parser_trace)
	{
		uint32_t code = 0;
		std::string message;
		const bool parsed = read_server_status_string(status, &code, &message);
		debug_log_line(std::format(
			"api=server_status_check target=0x7c710a30 out={} result={} parsed={} code={} message=\"{}\"",
			exception_address_text(reinterpret_cast<uintptr_t>(status)),
			exception_address_text(reinterpret_cast<uintptr_t>(result)),
			bool_text(parsed), code, message));
	}
	return result;
}

void* __cdecl hooked_config_load_handler(void* out, msvc_string_value_t config_name)
{
	const uintptr_t caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
	if (g_cloud_parser_trace)
	{
		const char* caller_region = known_dump_region_label(caller);
		debug_log_line(std::format(
			"api=config_load_handler_enter target=0x65985360 caller={} caller_region={} out={} config_name=[{}]",
			exception_address_text(caller), caller_region ? caller_region : "<unknown>",
			exception_address_text(reinterpret_cast<uintptr_t>(out)),
			msvc_string_summary(&config_name, 128)));
	}

	void* result = oConfigLoadHandler ? oConfigLoadHandler(out, config_name) : out;
	if (g_cloud_parser_trace)
	{
		uint8_t ok = 0xff;
		bool ok_read = false;
		if (out)
		{
			ok_read = safe_copy_bytes(out, &ok, sizeof(ok));
		}

		const auto base = reinterpret_cast<uintptr_t>(out);
		debug_log_line(std::format(
			"api=config_load_handler_exit target=0x65985360 caller={} out={} result={} ok_read={} ok={} status=[{}] field0=[{}] field1=[{}] field2=[{}]",
			exception_address_text(caller), exception_address_text(base),
			exception_address_text(reinterpret_cast<uintptr_t>(result)), bool_text(ok_read),
			static_cast<unsigned int>(ok),
			msvc_string_summary(reinterpret_cast<const void*>(base + 0x04), 160),
			msvc_string_summary(reinterpret_cast<const void*>(base + 0x1c), 160),
			msvc_string_summary(reinterpret_cast<const void*>(base + 0x34), 160),
			msvc_string_summary(reinterpret_cast<const void*>(base + 0x4c), 256)));
	}
	return result;
}

unsigned char __fastcall hooked_parsed_value_equal(void* self, void* /*edx*/, const void* other)
{
	const uintptr_t caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
	const unsigned char result = oParsedValueEqual ? oParsedValueEqual(self, other) : 0;
	if (g_cloud_parser_trace && is_cloud_parser_address(caller))
	{
		const char* caller_region = known_dump_region_label(caller);
		debug_log_line(std::format(
			"api=parsed_value_equal target=0x4fbd42c0 caller={} caller_region={} self={} other={} self_hex=\"{}\" other_hex=\"{}\" result={}",
			exception_address_text(caller), caller_region ? caller_region : "<unknown>",
			exception_address_text(reinterpret_cast<uintptr_t>(self)),
			exception_address_text(reinterpret_cast<uintptr_t>(other)),
			pointer_preview_hex(self, 32, 32), pointer_preview_hex(other, 32, 32),
			static_cast<unsigned int>(result)));
	}
	return result;
}

unsigned char __cdecl hooked_str_equal_literal(const void* string_object, const char* literal)
{
	const uintptr_t caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
	const unsigned char result = oStrEqualLiteral ? oStrEqualLiteral(string_object, literal) : 0;
	if (g_cloud_parser_trace && is_cloud_parser_address(caller))
	{
		const char* caller_region = known_dump_region_label(caller);
		debug_log_line(std::format(
			"api=str_equal_literal target=0x49f84d90 caller={} caller_region={} string=[{}] literal=[{}] result={}",
			exception_address_text(caller), caller_region ? caller_region : "<unknown>",
			msvc_string_summary(string_object, 160), c_string_summary(literal, 160),
			static_cast<unsigned int>(result)));
	}
	return result;
}

static std::string wsabuf_preview_hex(LPWSABUF buffers, DWORD buffer_count, DWORD byte_limit, DWORD* total_capacity)
{
	if (total_capacity)
	{
		*total_capacity = 0;
	}
	if (!buffers || !buffer_count || !byte_limit)
	{
		return "<empty>";
	}

	std::array<uint8_t, 64> preview = {};
	size_t preview_used = 0;
	DWORD total = 0;
	const DWORD capped_count = std::min<DWORD>(buffer_count, 32);
	for (DWORD i = 0; i < capped_count; ++i)
	{
		ULONG length = 0;
		CHAR* buffer = nullptr;
		if (!safe_read_wsabuf_item(buffers, i, &length, &buffer))
		{
			if (total_capacity)
			{
				*total_capacity = total;
			}
			return preview_used ? bytes_to_hex(preview.data(), preview_used) : "<unreadable>";
		}

		total = (length > MAXDWORD - total) ? MAXDWORD : total + length;
		if (!buffer || !length || preview_used >= preview.size() || preview_used >= byte_limit)
		{
			continue;
		}

		const size_t remaining_preview = std::min<size_t>(preview.size() - preview_used,
			static_cast<size_t>(byte_limit) - preview_used);
		const size_t bytes_to_copy = std::min<size_t>(static_cast<size_t>(length), remaining_preview);
		if (!safe_copy_bytes(buffer, preview.data() + preview_used, bytes_to_copy))
		{
			if (total_capacity)
			{
				*total_capacity = total;
			}
			return preview_used ? bytes_to_hex(preview.data(), preview_used) : "<unreadable>";
		}
		preview_used += bytes_to_copy;
	}

	if (total_capacity)
	{
		*total_capacity = total;
	}
	return preview_used ? bytes_to_hex(preview.data(), preview_used) : "<empty>";
}

static std::string sockaddr_destination_text(const sockaddr* address, int address_length)
{
	if (!address)
	{
		return "<null>";
	}
	if (address_length < static_cast<int>(sizeof(ADDRESS_FAMILY)))
	{
		return "<invalid>";
	}

	sockaddr_storage storage = {};
	const size_t copy_size = std::min<size_t>(static_cast<size_t>(address_length), sizeof(storage));
	if (!safe_copy_bytes(address, &storage, copy_size))
	{
		return "<unreadable>";
	}

	char ip[INET6_ADDRSTRLEN] = {};
	if (storage.ss_family == AF_INET && copy_size >= sizeof(sockaddr_in))
	{
		const auto* in = reinterpret_cast<const sockaddr_in*>(&storage);
		const char* converted = InetNtopA(AF_INET, const_cast<IN_ADDR*>(&in->sin_addr), ip, static_cast<DWORD>(sizeof(ip)));
		return std::format("{}:{}", converted ? converted : "<inet_ntop_failed>", ntohs(in->sin_port));
	}
	if (storage.ss_family == AF_INET6 && copy_size >= sizeof(sockaddr_in6))
	{
		const auto* in6 = reinterpret_cast<const sockaddr_in6*>(&storage);
		const char* converted = InetNtopA(AF_INET6, const_cast<IN6_ADDR*>(&in6->sin6_addr), ip, static_cast<DWORD>(sizeof(ip)));
		return std::format("[{}]:{}", converted ? converted : "<inet_ntop_failed>", ntohs(in6->sin6_port));
	}
	return std::format("<family:{} length:{}>", static_cast<int>(storage.ss_family), address_length);
}

static bool build_local_cloud_redirect(const sockaddr* address, int address_length,
	sockaddr_storage* redirected_address, int* redirected_length, std::string* rewritten_destination)
{
	if (!g_cloud_redirect_local || !address || !redirected_address || !redirected_length || !rewritten_destination)
	{
		return false;
	}
	if (address_length < static_cast<int>(sizeof(sockaddr_in)))
	{
		return false;
	}

	sockaddr_storage original_storage = {};
	const size_t copy_size = std::min<size_t>(static_cast<size_t>(address_length), sizeof(original_storage));
	if (!safe_copy_bytes(address, &original_storage, copy_size))
	{
		return false;
	}
	if (original_storage.ss_family != AF_INET || copy_size < sizeof(sockaddr_in))
	{
		return false;
	}

	const auto* original = reinterpret_cast<const sockaddr_in*>(&original_storage);
	IN_ADDR pawjob_cloud_ip = {};
	IN_ADDR local_cloud_ip = {};
	if (InetPtonA(AF_INET, "51.222.158.143", &pawjob_cloud_ip) != 1 ||
		InetPtonA(AF_INET, "127.0.0.1", &local_cloud_ip) != 1)
	{
		return false;
	}
	if (original->sin_addr.S_un.S_addr != pawjob_cloud_ip.S_un.S_addr || ntohs(original->sin_port) != 5444)
	{
		return false;
	}

	sockaddr_in local = *original;
	local.sin_family = AF_INET;
	local.sin_addr = local_cloud_ip;
	local.sin_port = htons(5444);

	std::memset(redirected_address, 0, sizeof(*redirected_address));
	std::memcpy(redirected_address, &local, sizeof(local));
	*redirected_length = sizeof(local);
	*rewritten_destination = "127.0.0.1:5444";
	return true;
}

int WSAAPI hooked_WSAStartup(WORD version_requested, LPWSADATA data)
{
	const int result = oWSAStartup(version_requested, data);
	const bool failed = result != 0;
	const int wsa_error = failed ? WSAGetLastError() : 0;
	debug_log_line(std::format("api=WSAStartup version=0x{:04x} result={} failed={} wsa_error={}",
		version_requested, result, bool_text(failed), wsa_error));
	return result;
}

SOCKET WSAAPI hooked_socket(int af, int type, int protocol)
{
	const SOCKET result = oSocket(af, type, protocol);
	const bool failed = result == INVALID_SOCKET;
	const int wsa_error = failed ? WSAGetLastError() : 0;
	debug_log_line(std::format("api=socket af={} type={} protocol={} result={} failed={} wsa_error={}",
		af, type, protocol, socket_text(result), bool_text(failed), wsa_error));
	return result;
}

int WSAAPI hooked_connect(SOCKET s, const sockaddr* name, int namelen)
{
	const uintptr_t caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
	const std::string original_destination = sockaddr_destination_text(name, namelen);
	sockaddr_storage redirected_address = {};
	int redirected_length = 0;
	std::string rewritten_destination = "<unchanged>";
	const bool redirected = build_local_cloud_redirect(name, namelen, &redirected_address, &redirected_length, &rewritten_destination);

	const sockaddr* connect_name = redirected ? reinterpret_cast<const sockaddr*>(&redirected_address) : name;
	const int connect_length = redirected ? redirected_length : namelen;
	const int result = oConnect(s, connect_name, connect_length);
	const bool failed = result == SOCKET_ERROR;
	const int wsa_error = failed ? WSAGetLastError() : 0;
	debug_log_line(std::format(
		"api=connect caller={} socket={} original_destination=\"{}\" rewritten_destination=\"{}\" redirected={} result={} failed={} wsa_error={}",
		exception_address_text(caller), socket_text(s), original_destination, rewritten_destination, bool_text(redirected), result, bool_text(failed), wsa_error));
	return result;
}

int WSAAPI hooked_send(SOCKET s, const char* buffer, int length, int flags)
{
	const uintptr_t caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
	const std::string preview = buffer_preview_hex(buffer, length);
	const int result = oSend(s, buffer, length, flags);
	const bool failed = result == SOCKET_ERROR;
	const int wsa_error = failed ? WSAGetLastError() : 0;
	debug_log_line(std::format(
		"api=send caller={} socket={} requested={} result={} bytes={} flags=0x{:08x} failed={} wsa_error={} preview64=\"{}\"",
		exception_address_text(caller), socket_text(s), length, result, failed ? 0 : result, flags, bool_text(failed), wsa_error, preview));
	return result;
}

int WSAAPI hooked_recv(SOCKET s, char* buffer, int length, int flags)
{
	const uintptr_t caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
	const int result = oRecv(s, buffer, length, flags);
	const bool failed = result == SOCKET_ERROR;
	const int wsa_error = failed ? WSAGetLastError() : 0;
	if (!failed && result > 0)
	{
		g_tls_last_recv_socket = s;
		g_tls_last_recv_buffer = reinterpret_cast<uintptr_t>(buffer);
		g_tls_last_recv_bytes = static_cast<DWORD>(result);
		g_tls_last_recv_capacity = length > 0 ? static_cast<DWORD>(length) : 0;
	}
	const std::string preview = !failed && result > 0 ? buffer_preview_hex(buffer, result) : "<empty>";
	debug_log_line(std::format(
		"api=recv caller={} socket={} requested={} result={} bytes={} flags=0x{:08x} failed={} wsa_error={} preview64=\"{}\"",
		exception_address_text(caller), socket_text(s), length, result, failed ? 0 : result, flags, bool_text(failed), wsa_error, preview));
	return result;
}

int WSAAPI hooked_WSASend(SOCKET s, LPWSABUF buffers, DWORD buffer_count, LPDWORD bytes_sent,
	DWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine)
{
	const uintptr_t caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
	DWORD requested_bytes = 0;
	const std::string preview = wsabuf_preview_hex(buffers, buffer_count, 64, &requested_bytes);
	const int result = oWSASend(s, buffers, buffer_count, bytes_sent, flags, overlapped, completion_routine);
	const bool failed = result == SOCKET_ERROR;
	const int wsa_error = failed ? WSAGetLastError() : 0;
	DWORD sent_value = 0;
	const bool has_sent_value = safe_read_dword_value(bytes_sent, &sent_value);
	debug_log_line(std::format(
		"api=WSASend caller={} socket={} buffers={} requested={} result={} bytes_sent={} flags=0x{:08x} overlapped={} failed={} wsa_error={} preview64=\"{}\"",
		exception_address_text(caller), socket_text(s), buffer_count, requested_bytes, result, has_sent_value ? std::format("{}", sent_value) : "<unavailable>",
		flags, overlapped ? "true" : "false", bool_text(failed), wsa_error, preview));
	return result;
}

int WSAAPI hooked_WSARecv(SOCKET s, LPWSABUF buffers, DWORD buffer_count, LPDWORD bytes_received,
	LPDWORD flags, LPWSAOVERLAPPED overlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine)
{
	const uintptr_t caller = reinterpret_cast<uintptr_t>(_ReturnAddress());
	const int result = oWSARecv(s, buffers, buffer_count, bytes_received, flags, overlapped, completion_routine);
	const bool failed = result == SOCKET_ERROR;
	const int wsa_error = failed ? WSAGetLastError() : 0;

	DWORD received_value = 0;
	const bool has_received_value = safe_read_dword_value(bytes_received, &received_value);
	if (!failed && has_received_value && received_value > 0 && buffers && buffer_count)
	{
		ULONG first_length = 0;
		CHAR* first_buffer = nullptr;
		if (safe_read_wsabuf_item(buffers, 0, &first_length, &first_buffer))
		{
			g_tls_last_recv_socket = s;
			g_tls_last_recv_buffer = reinterpret_cast<uintptr_t>(first_buffer);
			g_tls_last_recv_bytes = received_value;
			g_tls_last_recv_capacity = first_length;
		}
	}
	DWORD capacity = 0;
	const DWORD preview_limit = !failed && has_received_value ? std::min<DWORD>(received_value, 64) : 0;
	const std::string preview = wsabuf_preview_hex(buffers, buffer_count, preview_limit, &capacity);
	debug_log_line(std::format(
		"api=WSARecv caller={} socket={} buffers={} capacity={} result={} bytes_received={} overlapped={} failed={} wsa_error={} preview64=\"{}\"",
		exception_address_text(caller), socket_text(s), buffer_count, capacity, result, has_received_value ? std::format("{}", received_value) : "<unavailable>",
		overlapped ? "true" : "false", bool_text(failed), wsa_error, preview));
	return result;
}

int WSAAPI hooked_closesocket(SOCKET s)
{
	const int result = oClosesocket(s);
	const bool failed = result == SOCKET_ERROR;
	const int wsa_error = failed ? WSAGetLastError() : 0;
	debug_log_line(std::format("api=closesocket socket={} result={} failed={} wsa_error={}",
		socket_text(s), result, bool_text(failed), wsa_error));
	return result;
}

static bool ascii_iequals(std::wstring_view lhs, std::wstring_view rhs)
{
	if (lhs.size() != rhs.size())
	{
		return false;
	}
	for (size_t i = 0; i < lhs.size(); ++i)
	{
		if (std::towlower(lhs[i]) != std::towlower(rhs[i]))
		{
			return false;
		}
	}
	return true;
}

static void normalize_pawjob_relative_path(std::wstring& relative)
{
	for (wchar_t& ch : relative)
	{
		if (ch == L'/')
		{
			ch = L'\\';
		}
	}

	if (ascii_iequals(relative, L"pawjob\\skins.mb"))
	{
		relative = L"pawjob\\skins\\skins.mb";
	}
	else if (ascii_iequals(relative, L"pawjob\\playerlist.mb"))
	{
		relative = L"pawjob\\playerlist\\playerlist.mb";
	}
}

static wide_rewrite_result rewrite_pawjob_path_w(LPCWSTR path)
{
	if (!path || g_local_storage_root.empty() || g_pawjob_storage_root.empty())
	{
		return { path_rewrite_status::no_match, {} };
	}

	std::wstring_view view(path);
	if (is_absolute_or_device_path(view))
	{
		return { path_rewrite_status::no_match, {} };
	}

	while (view.size() >= 2 && view[0] == L'.' && is_slash(view[1]))
	{
		view.remove_prefix(2);
	}

	const size_t prefix_len = relative_pawjob_prefix_len(view);
	if (!prefix_len)
	{
		return { path_rewrite_status::no_match, {} };
	}

	std::wstring relative = L"pawjob";
	relative.append(view.substr(prefix_len));
	normalize_pawjob_relative_path(relative);

	const std::wstring normalized = full_path_name(join_path(g_local_storage_root, relative));
	if (normalized.empty() || !path_is_under_root(g_pawjob_storage_root, normalized))
	{
		return { path_rewrite_status::blocked, {} };
	}
	return { path_rewrite_status::rewritten, normalized };
}

static narrow_rewrite_result rewrite_pawjob_path_a(LPCSTR path)
{
	if (!path || g_local_storage_root.empty() || g_pawjob_storage_root.empty())
	{
		return { path_rewrite_status::no_match, {} };
	}

	std::string_view view(path);
	if (is_absolute_or_device_path(view))
	{
		return { path_rewrite_status::no_match, {} };
	}

	while (view.size() >= 2 && view[0] == '.' && is_slash(view[1]))
	{
		view.remove_prefix(2);
	}

	const size_t prefix_len = relative_pawjob_prefix_len(view);
	if (!prefix_len)
	{
		return { path_rewrite_status::no_match, {} };
	}

	std::string relative = "pawjob";
	relative.append(view.substr(prefix_len));
	for (char& ch : relative)
	{
		if (ch == '/')
		{
			ch = '\\';
		}
	}

	std::wstring wide_relative = widen_acp(relative);
	if (wide_relative.empty())
	{
		return { path_rewrite_status::blocked, {} };
	}
	normalize_pawjob_relative_path(wide_relative);

	const std::wstring normalized = full_path_name(join_path(g_local_storage_root, wide_relative));
	if (normalized.empty() || !path_is_under_root(g_pawjob_storage_root, normalized))
	{
		return { path_rewrite_status::blocked, {} };
	}

	const std::string rewritten = narrow_acp(normalized);
	if (rewritten.empty())
	{
		return { path_rewrite_status::blocked, {} };
	}
	return { path_rewrite_status::rewritten, rewritten };
}

static std::wstring strip_nt_dos_prefix(std::wstring_view path)
{
	constexpr std::wstring_view nt_dos_prefix = L"\\??\\";
	if (path.rfind(nt_dos_prefix, 0) == 0)
	{
		return std::wstring(path.substr(nt_dos_prefix.size()));
	}
	return std::wstring(path);
}

static std::wstring nt_path_from_dos_path(const std::wstring& path)
{
	if (path.rfind(L"\\??\\", 0) == 0)
	{
		return path;
	}
	return L"\\??\\" + path;
}

static wide_rewrite_result rewrite_absolute_pawjob_path_w(std::wstring_view path)
{
	if (g_local_storage_root.empty() || g_pawjob_storage_root.empty())
	{
		return { path_rewrite_status::no_match, {} };
	}

	const std::wstring normalized = full_path_name(path);
	if (normalized.empty())
	{
		return { path_rewrite_status::no_match, {} };
	}

	const std::wstring legacy_root = full_path_name(join_path(g_local_storage_root, L"moneybot"));
	const std::wstring roots[] = { legacy_root, g_pawjob_storage_root };
	for (const std::wstring& root : roots)
	{
		if (root.empty() || !path_is_under_root(root, normalized))
		{
			continue;
		}

		std::wstring relative = L"pawjob";
		if (normalized.size() > root.size())
		{
			relative.append(normalized.substr(root.size()));
		}
		normalize_pawjob_relative_path(relative);

		const std::wstring rewritten = full_path_name(join_path(g_local_storage_root, relative));
		if (rewritten.empty() || !path_is_under_root(g_pawjob_storage_root, rewritten))
		{
			return { path_rewrite_status::blocked, {} };
		}
		if (ascii_iequals(rewritten, normalized))
		{
			return { path_rewrite_status::no_match, {} };
		}
		return { path_rewrite_status::rewritten, rewritten };
	}
	return { path_rewrite_status::no_match, {} };
}

static nt_path_rewrite_result rewrite_nt_pawjob_path(const std::wstring& object_name)
{
	if (object_name.empty() || object_name[0] == L'<')
	{
		return { path_rewrite_status::no_match, {}, {} };
	}

	const std::wstring dos_name = strip_nt_dos_prefix(object_name);
	wide_rewrite_result rewritten = {};
	if (is_absolute_or_device_path(std::wstring_view(dos_name)))
	{
		rewritten = rewrite_absolute_pawjob_path_w(dos_name);
	}
	else
	{
		rewritten = rewrite_pawjob_path_w(dos_name.c_str());
	}

	if (rewritten.status != path_rewrite_status::rewritten)
	{
		return { rewritten.status, rewritten.path, {} };
	}
	return { path_rewrite_status::rewritten, rewritten.path, nt_path_from_dos_path(rewritten.path) };
}

static bool make_rewritten_nt_object_attributes(nt_object_attributes_t* original, const std::wstring& nt_path,
	nt_object_attributes_t* rewritten, nt_unicode_string_t* rewritten_name)
{
	if (!original || !rewritten || !rewritten_name || nt_path.empty() ||
		nt_path.size() > (USHRT_MAX - sizeof(wchar_t)) / sizeof(wchar_t))
	{
		return false;
	}

	bool copied = false;
	__try
	{
		*rewritten = *original;
		copied = true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		copied = false;
	}
	if (!copied)
	{
		return false;
	}

	rewritten_name->Length = static_cast<USHORT>(nt_path.size() * sizeof(wchar_t));
	rewritten_name->MaximumLength = static_cast<USHORT>((nt_path.size() + 1) * sizeof(wchar_t));
	rewritten_name->Buffer = const_cast<PWSTR>(nt_path.c_str());
	rewritten->RootDirectory = nullptr;
	rewritten->ObjectName = rewritten_name;
	return true;
}

static std::wstring strip_final_path_prefix(std::wstring path)
{
	constexpr std::wstring_view dos_prefix = L"\\\\?\\";
	constexpr std::wstring_view unc_prefix = L"\\\\?\\UNC\\";
	if (path.rfind(unc_prefix, 0) == 0)
	{
		return L"\\\\" + path.substr(unc_prefix.size());
	}
	if (path.rfind(dos_prefix, 0) == 0)
	{
		return path.substr(dos_prefix.size());
	}
	return path;
}

static bool opened_handle_is_under_pawjob_root(HANDLE handle)
{
	if (handle == INVALID_HANDLE_VALUE || !handle)
	{
		return false;
	}

	std::vector<wchar_t> path(MAX_PATH);
	for (;;)
	{
		const DWORD written = GetFinalPathNameByHandleW(handle, path.data(), static_cast<DWORD>(path.size()),
			FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
		if (!written)
		{
			return false;
		}
		if (written < path.size())
		{
			path.resize(written);
			std::wstring final_path = strip_final_path_prefix(std::wstring(path.begin(), path.end()));
			trim_trailing_slashes(final_path);
			return path_is_under_root(g_pawjob_storage_root, final_path);
		}
		if (path.size() >= 32768)
		{
			return false;
		}
		path.resize(path.size() * 2);
	}
}

static bool ensure_local_storage_layout()
{
	const std::wstring proc_dir = process_directory();
	if (proc_dir.empty())
	{
		debug_log_line("Failed to resolve process directory.");
		return false;
	}

	g_local_storage_root = full_path_name(proc_dir);
	if (g_local_storage_root.empty())
	{
		debug_log_line("Failed to resolve local storage root.");
		return false;
	}

	g_pawjob_storage_root = full_path_name(join_path(g_local_storage_root, L"pawjob"));
	if (g_pawjob_storage_root.empty())
	{
		debug_log_line("Failed to resolve pawjob storage root.");
		return false;
	}

	bool ok = true;
	ok &= ensure_directory(g_pawjob_storage_root);
	ok &= ensure_directory(join_path(g_pawjob_storage_root, L"database"));
	ok &= ensure_directory(join_path(g_pawjob_storage_root, L"lua"));
	ok &= ensure_directory(join_path(g_pawjob_storage_root, L"configs"));
	ok &= ensure_directory(join_path(g_pawjob_storage_root, L"skins"));
	ok &= ensure_directory(join_path(g_pawjob_storage_root, L"playerlist"));

	if (ok)
	{
		if (open_debug_log())
		{
			debug_log_line("resolved process dir=" + path_for_log(proc_dir));
			debug_log_line("resolved local storage root=" + path_for_log(g_local_storage_root));
			debug_log_line("resolved pawjob storage root=" + path_for_log(g_pawjob_storage_root));
		}
		copy_file_if_missing(join_path(join_path(join_path(g_local_storage_root, L"moneybot"), L"skins"), L"skins.mb"),
			join_path(join_path(g_pawjob_storage_root, L"skins"), L"skins.mb"), "legacy_skins");
		load_debug_flags();
	}
	return ok;
}

HANDLE WINAPI hooked_CreateFileA(LPCSTR file_name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES security,
	DWORD creation, DWORD flags, HANDLE template_file)
{
	const auto rewritten = rewrite_pawjob_path_a(file_name);
	const bool should_log = should_log_path(file_name);
	if (rewritten.status == path_rewrite_status::blocked)
	{
		SetLastError(ERROR_ACCESS_DENIED);
		if (should_log)
		{
			log_path_api_result("CreateFileA", path_for_log(file_name), rewritten_path_for_log(rewritten),
				rewritten.status, handle_text(INVALID_HANDLE_VALUE), true, ERROR_ACCESS_DENIED);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		return INVALID_HANDLE_VALUE;
	}

	const HANDLE handle = oCreateFileA(rewritten.status == path_rewrite_status::rewritten ? rewritten.path.c_str() : file_name,
		access, share, security, creation, flags, template_file);
	DWORD last_error = GetLastError();
	if (rewritten.status == path_rewrite_status::rewritten && handle != INVALID_HANDLE_VALUE &&
		!opened_handle_is_under_pawjob_root(handle))
	{
		CloseHandle(handle);
		SetLastError(ERROR_ACCESS_DENIED);
		if (should_log)
		{
			log_path_api_result("CreateFileA", path_for_log(file_name), rewritten_path_for_log(rewritten),
				rewritten.status, handle_text(INVALID_HANDLE_VALUE), true, ERROR_ACCESS_DENIED);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		return INVALID_HANDLE_VALUE;
	}
	if (should_log)
	{
		log_path_api_result("CreateFileA", path_for_log(file_name), rewritten_path_for_log(rewritten),
			rewritten.status, handle_text(handle), handle == INVALID_HANDLE_VALUE, last_error);
		SetLastError(last_error);
	}
	return handle;
}

HANDLE WINAPI hooked_CreateFileW(LPCWSTR file_name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES security,
	DWORD creation, DWORD flags, HANDLE template_file)
{
	const auto rewritten = rewrite_pawjob_path_w(file_name);
	const bool should_log = should_log_path(file_name);
	if (rewritten.status == path_rewrite_status::blocked)
	{
		SetLastError(ERROR_ACCESS_DENIED);
		if (should_log)
		{
			log_path_api_result("CreateFileW", path_for_log(file_name), rewritten_path_for_log(rewritten),
				rewritten.status, handle_text(INVALID_HANDLE_VALUE), true, ERROR_ACCESS_DENIED);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		return INVALID_HANDLE_VALUE;
	}

	const HANDLE handle = oCreateFileW(rewritten.status == path_rewrite_status::rewritten ? rewritten.path.c_str() : file_name,
		access, share, security, creation, flags, template_file);
	DWORD last_error = GetLastError();
	if (rewritten.status == path_rewrite_status::rewritten && handle != INVALID_HANDLE_VALUE &&
		!opened_handle_is_under_pawjob_root(handle))
	{
		CloseHandle(handle);
		SetLastError(ERROR_ACCESS_DENIED);
		if (should_log)
		{
			log_path_api_result("CreateFileW", path_for_log(file_name), rewritten_path_for_log(rewritten),
				rewritten.status, handle_text(INVALID_HANDLE_VALUE), true, ERROR_ACCESS_DENIED);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		return INVALID_HANDLE_VALUE;
	}
	if (should_log)
	{
		log_path_api_result("CreateFileW", path_for_log(file_name), rewritten_path_for_log(rewritten),
			rewritten.status, handle_text(handle), handle == INVALID_HANDLE_VALUE, last_error);
		SetLastError(last_error);
	}
	return handle;
}

HANDLE WINAPI hooked_FindFirstFileA(LPCSTR file_name, LPWIN32_FIND_DATAA find_data)
{
	const auto rewritten = rewrite_pawjob_path_a(file_name);
	const bool should_log = should_log_path(file_name);
	if (rewritten.status == path_rewrite_status::blocked)
	{
		SetLastError(ERROR_ACCESS_DENIED);
		if (should_log)
		{
			log_path_api_result("FindFirstFileA", path_for_log(file_name), rewritten_path_for_log(rewritten),
				rewritten.status, handle_text(INVALID_HANDLE_VALUE), true, ERROR_ACCESS_DENIED);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		return INVALID_HANDLE_VALUE;
	}
	const HANDLE handle = oFindFirstFileA(rewritten.status == path_rewrite_status::rewritten ? rewritten.path.c_str() : file_name, find_data);
	const DWORD last_error = GetLastError();
	if (should_log)
	{
		log_path_api_result("FindFirstFileA", path_for_log(file_name), rewritten_path_for_log(rewritten),
			rewritten.status, handle_text(handle), handle == INVALID_HANDLE_VALUE, last_error);
		SetLastError(last_error);
	}
	return handle;
}

HANDLE WINAPI hooked_FindFirstFileW(LPCWSTR file_name, LPWIN32_FIND_DATAW find_data)
{
	const auto rewritten = rewrite_pawjob_path_w(file_name);
	const bool should_log = should_log_path(file_name);
	if (rewritten.status == path_rewrite_status::blocked)
	{
		SetLastError(ERROR_ACCESS_DENIED);
		if (should_log)
		{
			log_path_api_result("FindFirstFileW", path_for_log(file_name), rewritten_path_for_log(rewritten),
				rewritten.status, handle_text(INVALID_HANDLE_VALUE), true, ERROR_ACCESS_DENIED);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		return INVALID_HANDLE_VALUE;
	}
	const HANDLE handle = oFindFirstFileW(rewritten.status == path_rewrite_status::rewritten ? rewritten.path.c_str() : file_name, find_data);
	const DWORD last_error = GetLastError();
	if (should_log)
	{
		log_path_api_result("FindFirstFileW", path_for_log(file_name), rewritten_path_for_log(rewritten),
			rewritten.status, handle_text(handle), handle == INVALID_HANDLE_VALUE, last_error);
		SetLastError(last_error);
	}
	return handle;
}

HANDLE WINAPI hooked_FindFirstFileExA(LPCSTR file_name, FINDEX_INFO_LEVELS info_level, LPVOID find_data,
	FINDEX_SEARCH_OPS search_op, LPVOID search_filter, DWORD additional_flags)
{
	const auto rewritten = rewrite_pawjob_path_a(file_name);
	const bool should_log = should_log_path(file_name);
	if (rewritten.status == path_rewrite_status::blocked)
	{
		SetLastError(ERROR_ACCESS_DENIED);
		if (should_log)
		{
			log_path_api_result("FindFirstFileExA", path_for_log(file_name), rewritten_path_for_log(rewritten),
				rewritten.status, handle_text(INVALID_HANDLE_VALUE), true, ERROR_ACCESS_DENIED);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		return INVALID_HANDLE_VALUE;
	}
	const HANDLE handle = oFindFirstFileExA(rewritten.status == path_rewrite_status::rewritten ? rewritten.path.c_str() : file_name,
		info_level, find_data, search_op, search_filter, additional_flags);
	const DWORD last_error = GetLastError();
	if (should_log)
	{
		log_path_api_result("FindFirstFileExA", path_for_log(file_name), rewritten_path_for_log(rewritten),
			rewritten.status, handle_text(handle), handle == INVALID_HANDLE_VALUE, last_error);
		SetLastError(last_error);
	}
	return handle;
}

HANDLE WINAPI hooked_FindFirstFileExW(LPCWSTR file_name, FINDEX_INFO_LEVELS info_level, LPVOID find_data,
	FINDEX_SEARCH_OPS search_op, LPVOID search_filter, DWORD additional_flags)
{
	const auto rewritten = rewrite_pawjob_path_w(file_name);
	const bool should_log = should_log_path(file_name);
	if (rewritten.status == path_rewrite_status::blocked)
	{
		SetLastError(ERROR_ACCESS_DENIED);
		if (should_log)
		{
			log_path_api_result("FindFirstFileExW", path_for_log(file_name), rewritten_path_for_log(rewritten),
				rewritten.status, handle_text(INVALID_HANDLE_VALUE), true, ERROR_ACCESS_DENIED);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		return INVALID_HANDLE_VALUE;
	}
	const HANDLE handle = oFindFirstFileExW(rewritten.status == path_rewrite_status::rewritten ? rewritten.path.c_str() : file_name,
		info_level, find_data, search_op, search_filter, additional_flags);
	const DWORD last_error = GetLastError();
	if (should_log)
	{
		log_path_api_result("FindFirstFileExW", path_for_log(file_name), rewritten_path_for_log(rewritten),
			rewritten.status, handle_text(handle), handle == INVALID_HANDLE_VALUE, last_error);
		SetLastError(last_error);
	}
	return handle;
}

DWORD WINAPI hooked_GetFileAttributesA(LPCSTR file_name)
{
	const auto rewritten = rewrite_pawjob_path_a(file_name);
	const bool should_log = should_log_path(file_name);
	if (rewritten.status == path_rewrite_status::blocked)
	{
		SetLastError(ERROR_ACCESS_DENIED);
		if (should_log)
		{
			log_path_api_result("GetFileAttributesA", path_for_log(file_name), rewritten_path_for_log(rewritten),
				rewritten.status, std::format("0x{:08x}", INVALID_FILE_ATTRIBUTES), true, ERROR_ACCESS_DENIED);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		return INVALID_FILE_ATTRIBUTES;
	}
	const DWORD result = oGetFileAttributesA(rewritten.status == path_rewrite_status::rewritten ? rewritten.path.c_str() : file_name);
	const DWORD last_error = GetLastError();
	if (should_log)
	{
		log_path_api_result("GetFileAttributesA", path_for_log(file_name), rewritten_path_for_log(rewritten),
			rewritten.status, std::format("0x{:08x}", result), result == INVALID_FILE_ATTRIBUTES, last_error);
		SetLastError(last_error);
	}
	return result;
}

DWORD WINAPI hooked_GetFileAttributesW(LPCWSTR file_name)
{
	const auto rewritten = rewrite_pawjob_path_w(file_name);
	const bool should_log = should_log_path(file_name);
	if (rewritten.status == path_rewrite_status::blocked)
	{
		SetLastError(ERROR_ACCESS_DENIED);
		if (should_log)
		{
			log_path_api_result("GetFileAttributesW", path_for_log(file_name), rewritten_path_for_log(rewritten),
				rewritten.status, std::format("0x{:08x}", INVALID_FILE_ATTRIBUTES), true, ERROR_ACCESS_DENIED);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		return INVALID_FILE_ATTRIBUTES;
	}
	const DWORD result = oGetFileAttributesW(rewritten.status == path_rewrite_status::rewritten ? rewritten.path.c_str() : file_name);
	const DWORD last_error = GetLastError();
	if (should_log)
	{
		log_path_api_result("GetFileAttributesW", path_for_log(file_name), rewritten_path_for_log(rewritten),
			rewritten.status, std::format("0x{:08x}", result), result == INVALID_FILE_ATTRIBUTES, last_error);
		SetLastError(last_error);
	}
	return result;
}

BOOL WINAPI hooked_CreateDirectoryA(LPCSTR path_name, LPSECURITY_ATTRIBUTES security)
{
	const auto rewritten = rewrite_pawjob_path_a(path_name);
	const bool should_log = should_log_path(path_name);
	if (rewritten.status == path_rewrite_status::blocked)
	{
		SetLastError(ERROR_ACCESS_DENIED);
		if (should_log)
		{
			log_path_api_result("CreateDirectoryA", path_for_log(path_name), rewritten_path_for_log(rewritten),
				rewritten.status, "0", true, ERROR_ACCESS_DENIED);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		return FALSE;
	}
	const BOOL result = oCreateDirectoryA(rewritten.status == path_rewrite_status::rewritten ? rewritten.path.c_str() : path_name, security);
	const DWORD last_error = GetLastError();
	if (should_log)
	{
		log_path_api_result("CreateDirectoryA", path_for_log(path_name), rewritten_path_for_log(rewritten),
			rewritten.status, std::format("{}", result), !result, last_error);
		SetLastError(last_error);
	}
	return result;
}

BOOL WINAPI hooked_CreateDirectoryW(LPCWSTR path_name, LPSECURITY_ATTRIBUTES security)
{
	const auto rewritten = rewrite_pawjob_path_w(path_name);
	const bool should_log = should_log_path(path_name);
	if (rewritten.status == path_rewrite_status::blocked)
	{
		SetLastError(ERROR_ACCESS_DENIED);
		if (should_log)
		{
			log_path_api_result("CreateDirectoryW", path_for_log(path_name), rewritten_path_for_log(rewritten),
				rewritten.status, "0", true, ERROR_ACCESS_DENIED);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		return FALSE;
	}
	const BOOL result = oCreateDirectoryW(rewritten.status == path_rewrite_status::rewritten ? rewritten.path.c_str() : path_name, security);
	const DWORD last_error = GetLastError();
	if (should_log)
	{
		log_path_api_result("CreateDirectoryW", path_for_log(path_name), rewritten_path_for_log(rewritten),
			rewritten.status, std::format("{}", result), !result, last_error);
		SetLastError(last_error);
	}
	return result;
}

BOOL WINAPI hooked_DeleteFileA(LPCSTR file_name)
{
	const auto rewritten = rewrite_pawjob_path_a(file_name);
	const bool should_log = should_log_path(file_name);
	if (rewritten.status == path_rewrite_status::blocked)
	{
		SetLastError(ERROR_ACCESS_DENIED);
		if (should_log)
		{
			log_path_api_result("DeleteFileA", path_for_log(file_name), rewritten_path_for_log(rewritten),
				rewritten.status, "0", true, ERROR_ACCESS_DENIED);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		return FALSE;
	}
	const BOOL result = oDeleteFileA(rewritten.status == path_rewrite_status::rewritten ? rewritten.path.c_str() : file_name);
	const DWORD last_error = GetLastError();
	if (should_log)
	{
		log_path_api_result("DeleteFileA", path_for_log(file_name), rewritten_path_for_log(rewritten),
			rewritten.status, std::format("{}", result), !result, last_error);
		SetLastError(last_error);
	}
	return result;
}

BOOL WINAPI hooked_DeleteFileW(LPCWSTR file_name)
{
	const auto rewritten = rewrite_pawjob_path_w(file_name);
	const bool should_log = should_log_path(file_name);
	if (rewritten.status == path_rewrite_status::blocked)
	{
		SetLastError(ERROR_ACCESS_DENIED);
		if (should_log)
		{
			log_path_api_result("DeleteFileW", path_for_log(file_name), rewritten_path_for_log(rewritten),
				rewritten.status, "0", true, ERROR_ACCESS_DENIED);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		return FALSE;
	}
	const BOOL result = oDeleteFileW(rewritten.status == path_rewrite_status::rewritten ? rewritten.path.c_str() : file_name);
	const DWORD last_error = GetLastError();
	if (should_log)
	{
		log_path_api_result("DeleteFileW", path_for_log(file_name), rewritten_path_for_log(rewritten),
			rewritten.status, std::format("{}", result), !result, last_error);
		SetLastError(last_error);
	}
	return result;
}

BOOL WINAPI hooked_MoveFileA(LPCSTR existing_name, LPCSTR new_name)
{
	const auto rewritten_existing = rewrite_pawjob_path_a(existing_name);
	const auto rewritten_new = rewrite_pawjob_path_a(new_name);
	const bool should_log = should_log_path(existing_name) || should_log_path(new_name);
	if (rewritten_existing.status == path_rewrite_status::blocked || rewritten_new.status == path_rewrite_status::blocked ||
		(rewritten_existing.status == path_rewrite_status::rewritten) != (rewritten_new.status == path_rewrite_status::rewritten))
	{
		SetLastError(ERROR_ACCESS_DENIED);
		if (should_log)
		{
			log_move_api_result("MoveFileA", path_for_log(existing_name), rewritten_path_for_log(rewritten_existing),
				rewritten_existing.status, path_for_log(new_name), rewritten_path_for_log(rewritten_new),
				rewritten_new.status, "0", true, ERROR_ACCESS_DENIED);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		return FALSE;
	}
	const BOOL result = oMoveFileA(
		rewritten_existing.status == path_rewrite_status::rewritten ? rewritten_existing.path.c_str() : existing_name,
		rewritten_new.status == path_rewrite_status::rewritten ? rewritten_new.path.c_str() : new_name);
	const DWORD last_error = GetLastError();
	if (should_log)
	{
		log_move_api_result("MoveFileA", path_for_log(existing_name), rewritten_path_for_log(rewritten_existing),
			rewritten_existing.status, path_for_log(new_name), rewritten_path_for_log(rewritten_new),
			rewritten_new.status, std::format("{}", result), !result, last_error);
		SetLastError(last_error);
	}
	return result;
}

BOOL WINAPI hooked_MoveFileW(LPCWSTR existing_name, LPCWSTR new_name)
{
	const auto rewritten_existing = rewrite_pawjob_path_w(existing_name);
	const auto rewritten_new = rewrite_pawjob_path_w(new_name);
	const bool should_log = should_log_path(existing_name) || should_log_path(new_name);
	if (rewritten_existing.status == path_rewrite_status::blocked || rewritten_new.status == path_rewrite_status::blocked ||
		(rewritten_existing.status == path_rewrite_status::rewritten) != (rewritten_new.status == path_rewrite_status::rewritten))
	{
		SetLastError(ERROR_ACCESS_DENIED);
		if (should_log)
		{
			log_move_api_result("MoveFileW", path_for_log(existing_name), rewritten_path_for_log(rewritten_existing),
				rewritten_existing.status, path_for_log(new_name), rewritten_path_for_log(rewritten_new),
				rewritten_new.status, "0", true, ERROR_ACCESS_DENIED);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		return FALSE;
	}
	const BOOL result = oMoveFileW(
		rewritten_existing.status == path_rewrite_status::rewritten ? rewritten_existing.path.c_str() : existing_name,
		rewritten_new.status == path_rewrite_status::rewritten ? rewritten_new.path.c_str() : new_name);
	const DWORD last_error = GetLastError();
	if (should_log)
	{
		log_move_api_result("MoveFileW", path_for_log(existing_name), rewritten_path_for_log(rewritten_existing),
			rewritten_existing.status, path_for_log(new_name), rewritten_path_for_log(rewritten_new),
			rewritten_new.status, std::format("{}", result), !result, last_error);
		SetLastError(last_error);
	}
	return result;
}

BOOL WINAPI hooked_MoveFileExA(LPCSTR existing_name, LPCSTR new_name, DWORD flags)
{
	const auto rewritten_existing = rewrite_pawjob_path_a(existing_name);
	const auto rewritten_new = rewrite_pawjob_path_a(new_name);
	const bool should_log = should_log_path(existing_name) || should_log_path(new_name);
	if (rewritten_existing.status == path_rewrite_status::blocked || rewritten_new.status == path_rewrite_status::blocked ||
		(rewritten_existing.status == path_rewrite_status::rewritten) != (rewritten_new.status == path_rewrite_status::rewritten))
	{
		SetLastError(ERROR_ACCESS_DENIED);
		if (should_log)
		{
			log_move_api_result("MoveFileExA", path_for_log(existing_name), rewritten_path_for_log(rewritten_existing),
				rewritten_existing.status, path_for_log(new_name), rewritten_path_for_log(rewritten_new),
				rewritten_new.status, "0", true, ERROR_ACCESS_DENIED);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		return FALSE;
	}
	const BOOL result = oMoveFileExA(
		rewritten_existing.status == path_rewrite_status::rewritten ? rewritten_existing.path.c_str() : existing_name,
		rewritten_new.status == path_rewrite_status::rewritten ? rewritten_new.path.c_str() : new_name,
		flags);
	const DWORD last_error = GetLastError();
	if (should_log)
	{
		log_move_api_result("MoveFileExA", path_for_log(existing_name), rewritten_path_for_log(rewritten_existing),
			rewritten_existing.status, path_for_log(new_name), rewritten_path_for_log(rewritten_new),
			rewritten_new.status, std::format("{}", result), !result, last_error);
		SetLastError(last_error);
	}
	return result;
}

BOOL WINAPI hooked_MoveFileExW(LPCWSTR existing_name, LPCWSTR new_name, DWORD flags)
{
	const auto rewritten_existing = rewrite_pawjob_path_w(existing_name);
	const auto rewritten_new = rewrite_pawjob_path_w(new_name);
	const bool should_log = should_log_path(existing_name) || should_log_path(new_name);
	if (rewritten_existing.status == path_rewrite_status::blocked || rewritten_new.status == path_rewrite_status::blocked ||
		(rewritten_existing.status == path_rewrite_status::rewritten) != (rewritten_new.status == path_rewrite_status::rewritten))
	{
		SetLastError(ERROR_ACCESS_DENIED);
		if (should_log)
		{
			log_move_api_result("MoveFileExW", path_for_log(existing_name), rewritten_path_for_log(rewritten_existing),
				rewritten_existing.status, path_for_log(new_name), rewritten_path_for_log(rewritten_new),
				rewritten_new.status, "0", true, ERROR_ACCESS_DENIED);
			SetLastError(ERROR_ACCESS_DENIED);
		}
		return FALSE;
	}
	const BOOL result = oMoveFileExW(
		rewritten_existing.status == path_rewrite_status::rewritten ? rewritten_existing.path.c_str() : existing_name,
		rewritten_new.status == path_rewrite_status::rewritten ? rewritten_new.path.c_str() : new_name,
		flags);
	const DWORD last_error = GetLastError();
	if (should_log)
	{
		log_move_api_result("MoveFileExW", path_for_log(existing_name), rewritten_path_for_log(rewritten_existing),
			rewritten_existing.status, path_for_log(new_name), rewritten_path_for_log(rewritten_new),
			rewritten_new.status, std::format("{}", result), !result, last_error);
		SetLastError(last_error);
	}
	return result;
}

static bool log_minhook_status(const char* operation, const char* target, MH_STATUS status)
{
	debug_log_line(std::format("{} target={} status={} ({})",
		operation, target, static_cast<int>(status), MH_StatusToString(status)));
	return status == MH_OK;
}

static void* resolve_ntdll_export(const char* export_name)
{
	HMODULE ntdll_module = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll_module)
	{
		debug_log_line(std::format("resolve target={} failed=missing_ntdll gle={}", export_name, GetLastError()));
		return nullptr;
	}

	void* export_address = reinterpret_cast<void*>(GetProcAddress(ntdll_module, export_name));
	if (!export_address)
	{
		debug_log_line(std::format("resolve target={} failed=missing_export gle={}", export_name, GetLastError()));
		return nullptr;
	}
	return export_address;
}

static void* resolve_ws2_export(const char* export_name)
{
	HMODULE ws2_module = GetModuleHandleW(L"ws2_32.dll");
	if (!ws2_module)
	{
		ws2_module = LoadLibraryW(L"ws2_32.dll");
	}
	if (!ws2_module)
	{
		debug_log_line(std::format("resolve target={} module=ws2_32.dll failed=missing_module gle={}",
			export_name, GetLastError()));
		return nullptr;
	}

	void* export_address = reinterpret_cast<void*>(GetProcAddress(ws2_module, export_name));
	if (!export_address)
	{
		debug_log_line(std::format("resolve target={} module=ws2_32.dll failed=missing_export gle={}",
			export_name, GetLastError()));
		return nullptr;
	}
	return export_address;
}

static void* resolve_d3dx9_export(const char* export_name)
{
	HMODULE d3dx_module = GetModuleHandleW(L"D3DX9_43.dll");
	if (!d3dx_module)
	{
		d3dx_module = LoadLibraryW(L"D3DX9_43.dll");
	}
	if (!d3dx_module)
	{
		debug_log_line(std::format("resolve target={} module=D3DX9_43.dll failed=missing_module gle={}",
			export_name, GetLastError()));
		return nullptr;
	}

	void* export_address = reinterpret_cast<void*>(GetProcAddress(d3dx_module, export_name));
	if (!export_address)
	{
		debug_log_line(std::format("resolve target={} module=D3DX9_43.dll failed=missing_export gle={}",
			export_name, GetLastError()));
		return nullptr;
	}
	return export_address;
}

static bool install_render_branding_hooks()
{
	bool ok = true;

	void* target = resolve_d3dx9_export("D3DXCreateFontA");
	if (target)
	{
		const MH_STATUS status = MH_CreateHook(target, hooked_D3DXCreateFontA, reinterpret_cast<void**>(&oD3DXCreateFontA));
		ok &= log_minhook_status("MH_CreateHook", "D3DXCreateFontA", status);
	}
	else
	{
		ok = false;
	}

	target = resolve_d3dx9_export("D3DXCreateLine");
	if (target)
	{
		const MH_STATUS status = MH_CreateHook(target, hooked_D3DXCreateLine, reinterpret_cast<void**>(&oD3DXCreateLine));
		ok &= log_minhook_status("MH_CreateHook", "D3DXCreateLine", status);
	}
	else
	{
		ok = false;
	}
	return ok;
}

static bool install_local_storage_hooks()
{
	bool ok = true;
	MH_STATUS status = MH_CreateHook(&CreateFileA, hooked_CreateFileA, reinterpret_cast<void**>(&oCreateFileA));
	ok &= log_minhook_status("MH_CreateHook", "CreateFileA", status);
	status = MH_CreateHook(&CreateFileW, hooked_CreateFileW, reinterpret_cast<void**>(&oCreateFileW));
	ok &= log_minhook_status("MH_CreateHook", "CreateFileW", status);
	status = MH_CreateHook(&FindFirstFileA, hooked_FindFirstFileA, reinterpret_cast<void**>(&oFindFirstFileA));
	ok &= log_minhook_status("MH_CreateHook", "FindFirstFileA", status);
	status = MH_CreateHook(&FindFirstFileW, hooked_FindFirstFileW, reinterpret_cast<void**>(&oFindFirstFileW));
	ok &= log_minhook_status("MH_CreateHook", "FindFirstFileW", status);
	status = MH_CreateHook(&FindFirstFileExA, hooked_FindFirstFileExA, reinterpret_cast<void**>(&oFindFirstFileExA));
	ok &= log_minhook_status("MH_CreateHook", "FindFirstFileExA", status);
	status = MH_CreateHook(&FindFirstFileExW, hooked_FindFirstFileExW, reinterpret_cast<void**>(&oFindFirstFileExW));
	ok &= log_minhook_status("MH_CreateHook", "FindFirstFileExW", status);
	status = MH_CreateHook(&GetFileAttributesA, hooked_GetFileAttributesA, reinterpret_cast<void**>(&oGetFileAttributesA));
	ok &= log_minhook_status("MH_CreateHook", "GetFileAttributesA", status);
	status = MH_CreateHook(&GetFileAttributesW, hooked_GetFileAttributesW, reinterpret_cast<void**>(&oGetFileAttributesW));
	ok &= log_minhook_status("MH_CreateHook", "GetFileAttributesW", status);
	status = MH_CreateHook(&CreateDirectoryA, hooked_CreateDirectoryA, reinterpret_cast<void**>(&oCreateDirectoryA));
	ok &= log_minhook_status("MH_CreateHook", "CreateDirectoryA", status);
	status = MH_CreateHook(&CreateDirectoryW, hooked_CreateDirectoryW, reinterpret_cast<void**>(&oCreateDirectoryW));
	ok &= log_minhook_status("MH_CreateHook", "CreateDirectoryW", status);
	status = MH_CreateHook(&DeleteFileA, hooked_DeleteFileA, reinterpret_cast<void**>(&oDeleteFileA));
	ok &= log_minhook_status("MH_CreateHook", "DeleteFileA", status);
	status = MH_CreateHook(&DeleteFileW, hooked_DeleteFileW, reinterpret_cast<void**>(&oDeleteFileW));
	ok &= log_minhook_status("MH_CreateHook", "DeleteFileW", status);
	status = MH_CreateHook(&MoveFileA, hooked_MoveFileA, reinterpret_cast<void**>(&oMoveFileA));
	ok &= log_minhook_status("MH_CreateHook", "MoveFileA", status);
	status = MH_CreateHook(&MoveFileW, hooked_MoveFileW, reinterpret_cast<void**>(&oMoveFileW));
	ok &= log_minhook_status("MH_CreateHook", "MoveFileW", status);
	status = MH_CreateHook(&MoveFileExA, hooked_MoveFileExA, reinterpret_cast<void**>(&oMoveFileExA));
	ok &= log_minhook_status("MH_CreateHook", "MoveFileExA", status);
	status = MH_CreateHook(&MoveFileExW, hooked_MoveFileExW, reinterpret_cast<void**>(&oMoveFileExW));
	ok &= log_minhook_status("MH_CreateHook", "MoveFileExW", status);

	void* nt_create_file = resolve_ntdll_export("NtCreateFile");
	if (nt_create_file)
	{
		status = MH_CreateHook(nt_create_file, hooked_NtCreateFile, reinterpret_cast<void**>(&oNtCreateFile));
		ok &= log_minhook_status("MH_CreateHook", "NtCreateFile", status);
	}
	else
	{
		ok = false;
	}

	void* nt_open_file = resolve_ntdll_export("NtOpenFile");
	if (nt_open_file)
	{
		status = MH_CreateHook(nt_open_file, hooked_NtOpenFile, reinterpret_cast<void**>(&oNtOpenFile));
		ok &= log_minhook_status("MH_CreateHook", "NtOpenFile", status);
	}
	else
	{
		ok = false;
	}
	return ok;
}

static bool install_winsock_logging_hooks()
{
	bool ok = true;
	MH_STATUS status = MH_UNKNOWN;
	void* target = resolve_ws2_export("WSAStartup");
	if (target)
	{
		status = MH_CreateHook(target, hooked_WSAStartup, reinterpret_cast<void**>(&oWSAStartup));
		ok &= log_minhook_status("MH_CreateHook", "WSAStartup", status);
	}
	else
	{
		ok = false;
	}

	target = resolve_ws2_export("socket");
	if (target)
	{
		status = MH_CreateHook(target, hooked_socket, reinterpret_cast<void**>(&oSocket));
		ok &= log_minhook_status("MH_CreateHook", "socket", status);
	}
	else
	{
		ok = false;
	}

	target = resolve_ws2_export("connect");
	if (target)
	{
		status = MH_CreateHook(target, hooked_connect, reinterpret_cast<void**>(&oConnect));
		ok &= log_minhook_status("MH_CreateHook", "connect", status);
	}
	else
	{
		ok = false;
	}

	target = resolve_ws2_export("send");
	if (target)
	{
		status = MH_CreateHook(target, hooked_send, reinterpret_cast<void**>(&oSend));
		ok &= log_minhook_status("MH_CreateHook", "send", status);
	}
	else
	{
		ok = false;
	}

	target = resolve_ws2_export("recv");
	if (target)
	{
		status = MH_CreateHook(target, hooked_recv, reinterpret_cast<void**>(&oRecv));
		ok &= log_minhook_status("MH_CreateHook", "recv", status);
	}
	else
	{
		ok = false;
	}

	target = resolve_ws2_export("WSASend");
	if (target)
	{
		status = MH_CreateHook(target, hooked_WSASend, reinterpret_cast<void**>(&oWSASend));
		ok &= log_minhook_status("MH_CreateHook", "WSASend", status);
	}
	else
	{
		ok = false;
	}

	target = resolve_ws2_export("WSARecv");
	if (target)
	{
		status = MH_CreateHook(target, hooked_WSARecv, reinterpret_cast<void**>(&oWSARecv));
		ok &= log_minhook_status("MH_CreateHook", "WSARecv", status);
	}
	else
	{
		ok = false;
	}

	target = resolve_ws2_export("closesocket");
	if (target)
	{
		status = MH_CreateHook(target, hooked_closesocket, reinterpret_cast<void**>(&oClosesocket));
		ok &= log_minhook_status("MH_CreateHook", "closesocket", status);
	}
	else
	{
		ok = false;
	}
	return ok;
}

static bool install_cloud_parser_trace_hooks()
{
	if (!g_cloud_parser_trace)
	{
		debug_log_line("cloud_parser_trace install=skipped mode=off");
		return true;
	}

	bool ok = true;
	debug_log_line("MH_CreateHook target=cloud_compare_0x44a56970 status=skipped (mixed calling convention)");

	auto* target = reinterpret_cast<void*>(0x4CEADA70);
	MH_STATUS status = MH_CreateHook(target, hooked_cloud_crypto_set_bytes, reinterpret_cast<void**>(&oCloudCryptoSetBytes));
	ok &= log_minhook_status("MH_CreateHook", "cloud_crypto_set_bytes_0x4ceada70", status);

	target = reinterpret_cast<void*>(0x7C710A30);
	status = MH_CreateHook(target, hooked_server_status_check, reinterpret_cast<void**>(&oServerStatusCheck));
	ok &= log_minhook_status("MH_CreateHook", "server_status_check_0x7c710a30", status);

	target = reinterpret_cast<void*>(0x65985360);
	status = MH_CreateHook(target, hooked_config_load_handler, reinterpret_cast<void**>(&oConfigLoadHandler));
	ok &= log_minhook_status("MH_CreateHook", "config_load_handler_0x65985360", status);

	target = reinterpret_cast<void*>(0x4FBD42C0);
	status = MH_CreateHook(target, hooked_parsed_value_equal, reinterpret_cast<void**>(&oParsedValueEqual));
	ok &= log_minhook_status("MH_CreateHook", "parsed_value_equal_0x4fbd42c0", status);

	target = reinterpret_cast<void*>(0x49F84D90);
	status = MH_CreateHook(target, hooked_str_equal_literal, reinterpret_cast<void**>(&oStrEqualLiteral));
	ok &= log_minhook_status("MH_CreateHook", "str_equal_literal_0x49f84d90", status);
	return ok;
}

static bool patch_server_connection_check()
{
	static constexpr std::array<uint8_t, 9> original = {
		0x50, 0xE8, 0x66, 0x61, 0x01, 0x00, 0x83, 0xC4, 0x04
	};
	static constexpr std::array<uint8_t, 9> patched = {
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
	};

	auto* target = reinterpret_cast<uint8_t*>(0x804E39C4);
	DWORD old_protect = 0;
	if (!VirtualProtect(target, patched.size(), PAGE_EXECUTE_READWRITE, &old_protect))
	{
		debug_log_line(std::format("Failed to unprotect server connection check: {}", GetLastError()));
		return false;
	}

	const bool already_patched = std::memcmp(target, patched.data(), patched.size()) == 0;
	const bool matches_original = std::memcmp(target, original.data(), original.size()) == 0;
	if (!already_patched && !matches_original)
	{
		DWORD ignored = 0;
		VirtualProtect(target, patched.size(), old_protect, &ignored);
		debug_log_line("Server connection check bytes did not match expected baseline.");
		return false;
	}

	const char* mode = g_leave_server_check_original ? "original" : "nop";
	const bool changed = g_leave_server_check_original ? already_patched : !already_patched;
	if (g_leave_server_check_original)
	{
		if (already_patched)
		{
			std::memcpy(target, original.data(), original.size());
			FlushInstructionCache(GetCurrentProcess(), target, original.size());
		}
	}
	else if (!already_patched)
	{
		std::memcpy(target, patched.data(), patched.size());
		FlushInstructionCache(GetCurrentProcess(), target, patched.size());
	}

	DWORD ignored = 0;
	VirtualProtect(target, patched.size(), old_protect, &ignored);
	debug_log_line(std::format("server_check_patch mode={} changed={} target=0x{:08x}",
		mode, bool_text(changed), reinterpret_cast<uintptr_t>(target)));
	return true;
}

static bool is_readable_protection(DWORD protect)
{
	const DWORD base = protect & 0xff;
	return base == PAGE_READONLY || base == PAGE_READWRITE || base == PAGE_WRITECOPY ||
		base == PAGE_EXECUTE_READ || base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
}

static bool is_probably_path_context(const uint8_t* begin, const uint8_t* match, const uint8_t* end)
{
	const uint8_t* context_begin = match > begin + 32 ? match - 32 : begin;
	const uint8_t* context_end = (end - match) > 40 ? match + 40 : end;
	for (const uint8_t* p = context_begin; p < context_end; ++p)
	{
		if (*p == '\\' || *p == '/' || *p == ':')
		{
			return true;
		}
	}
	return false;
}

static bool patch_branding_match(uint8_t* address, const std::array<uint8_t, 8>& expected,
	const std::array<uint8_t, 8>& replacement)
{
	std::array<uint8_t, 8> current = {};
	if (!safe_copy_bytes(address, current.data(), current.size()) ||
		std::memcmp(current.data(), expected.data(), expected.size()) != 0)
	{
		return false;
	}

	DWORD old_protect = 0;
	if (!VirtualProtect(address, expected.size(), PAGE_EXECUTE_READWRITE, &old_protect))
	{
		debug_log_line(std::format("branding_patch address=0x{:08x} result=protect_failed gle={}",
			reinterpret_cast<uintptr_t>(address), GetLastError()));
		return false;
	}

	std::memcpy(address, replacement.data(), replacement.size());
	FlushInstructionCache(GetCurrentProcess(), address, replacement.size());

	DWORD ignored = 0;
	VirtualProtect(address, expected.size(), old_protect, &ignored);
	debug_log_line(std::format("branding_patch address=0x{:08x} result=patched",
		reinterpret_cast<uintptr_t>(address)));
	return true;
}

static int patch_branding_region(uint8_t* base, size_t size)
{
	static constexpr std::array<uint8_t, 8> lower = {
		0x6d, 0x6f, 0x6e, 0x65, 0x79, 0x62, 0x6f, 0x74
	};
	static constexpr std::array<uint8_t, 8> title = {
		0x4d, 0x6f, 0x6e, 0x65, 0x79, 0x62, 0x6f, 0x74
	};
	static constexpr std::array<uint8_t, 8> upper = {
		0x4d, 0x4f, 0x4e, 0x45, 0x59, 0x42, 0x4f, 0x54
	};
	static constexpr std::array<uint8_t, 8> lower_replacement = {
		'p', 'a', 'w', 'j', 'o', 'b', 0x00, 0x00
	};
	static constexpr std::array<uint8_t, 8> title_replacement = {
		'P', 'a', 'w', 'j', 'o', 'b', 0x00, 0x00
	};
	static constexpr std::array<uint8_t, 8> upper_replacement = {
		'P', 'A', 'W', 'J', 'O', 'B', 0x00, 0x00
	};

	int patched = 0;
	if (size < lower.size())
	{
		return 0;
	}

	constexpr size_t chunk_size = 0x10000;
	constexpr size_t overlap = 7;
	std::vector<uint8_t> snapshot;
	snapshot.resize(std::min<size_t>(chunk_size, size));

	for (size_t offset = 0; offset < size;)
	{
		const size_t bytes_to_copy = std::min<size_t>(snapshot.size(), size - offset);
		uint8_t* const chunk_base = base + offset;
		if (!safe_copy_bytes(chunk_base, snapshot.data(), bytes_to_copy))
		{
			offset += bytes_to_copy;
			continue;
		}

		for (size_t i = 0; i + lower.size() <= bytes_to_copy; ++i)
		{
			if (is_probably_path_context(snapshot.data(), snapshot.data() + i, snapshot.data() + bytes_to_copy))
			{
				continue;
			}

			uint8_t* const target = chunk_base + i;
			if (patch_branding_match(target, lower, lower_replacement) ||
				patch_branding_match(target, title, title_replacement) ||
				patch_branding_match(target, upper, upper_replacement))
			{
				++patched;
			}
		}

		if (bytes_to_copy <= overlap)
		{
			break;
		}
		offset += bytes_to_copy - overlap;
	}
	return patched;
}

DWORD WINAPI branding_patch_thread(LPVOID)
{
	debug_log_line("branding_patch thread=start");
	int total_patched = 0;
	for (int pass = 0; pass < 30; ++pass)
	{
		int pass_patched = 0;
		uintptr_t address = 0x10000;
		while (address < 0x82000000)
		{
			MEMORY_BASIC_INFORMATION mbi = {};
			if (VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(mbi)) != sizeof(mbi))
			{
				break;
			}

			const uintptr_t region_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
			const uintptr_t region_end = region_base + mbi.RegionSize;
			if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
				is_readable_protection(mbi.Protect))
			{
				pass_patched += patch_branding_region(reinterpret_cast<uint8_t*>(region_base), mbi.RegionSize);
			}

			if (region_end <= address)
			{
				break;
			}
			address = region_end;
		}

		total_patched += pass_patched;
		if (pass_patched)
		{
			debug_log_line(std::format("branding_patch pass={} patched={} total={}", pass, pass_patched, total_patched));
		}
		Sleep(500);
	}

	debug_log_line(std::format("branding_patch complete total={}", total_patched));
	return 0;
}

void init()
{
	g_init_thread_id = GetCurrentThreadId();

	if (!ensure_local_storage_layout())
	{
		debug_log_line("Failed to prepare local config storage; refusing to start.");
		return;
	}

	debug_log_line("Waiting for serverbrowser.dll ...");
	while (!GetModuleHandleA("serverbrowser.dll")) {
		Sleep(1000);
	}
	debug_log_line("Found serverbrowser.dll !");

	debug_log_line("Loading symbols...");
	load_modules();
	debug_log_line(std::format("Loaded {} symbols!", dmp_symbols.size()));

	debug_log_line("Fixing iat...");
	fix_iat();
	debug_log_line("Fixed iat!");

	debug_log_line("Patching...");

	if (!init_obfuscation_hooks(obfuscated_calls, obfuscated_jmps))
	{
		debug_log_line("Failed to create obfuscation hooks!");
		debug_log_line("Exiting...");
		return;
	}

	debug_log_line(std::format("Patched {} obfuscated calls at {}!", obfuscated_calls.size(), (void*)obfuscated_call_hooks));
	debug_log_line(std::format("Patched {} obfuscated jmps at {}!", obfuscated_jmps.size(), (void*)obfuscated_jmp_hooks));

	if (!patch_server_connection_check())
	{
		debug_log_line("Failed to patch server connection; refusing to start.");
		return;
	}

	debug_log_line(std::format("Server connection check mode: {}", g_leave_server_check_original ? "original" : "nop"));

	debug_log_line("Patched!");

	if (!install_crash_guard())
	{
		debug_log_line("Failed to install crash guard; refusing to start.");
		return;
	}

	debug_log_line("Enabling hooks...");

	const MH_STATUS initialize_status = MH_Initialize();
	log_minhook_status("MH_Initialize", "all", initialize_status);
    if (initialize_status != MH_OK)
    {
        MessageBoxA(NULL, "Failed to initialize hook", "FAIL", MB_ICONERROR | MB_OK);
        return;
    }

	const MH_STATUS pid_hook_status = MH_CreateHook(&GetCurrentProcessId, hooked_GetCurrentProcessId, reinterpret_cast<void**>(&oGetCurrentProcessId));
	if (!log_minhook_status("MH_CreateHook", "GetCurrentProcessId", pid_hook_status))
	{
		debug_log_line("Failed to create hook at GetCurrentProcessId");
		return;
	}

	if (!install_local_storage_hooks())
	{
		debug_log_line("Failed to create local config filesystem hooks");
		return;
	}

	if (!install_winsock_logging_hooks())
	{
		debug_log_line("Failed to create Winsock logging hooks");
		return;
	}

	if (!install_cloud_parser_trace_hooks())
	{
		debug_log_line("Failed to create cloud parser trace hooks");
		return;
	}

	if (!install_render_branding_hooks())
	{
		debug_log_line("Branding render hook unavailable; continuing with patched dump strings.");
	}
	else
	{
		debug_log_line("Branding render hook installed.");
	}

	const MH_STATUS enable_status = MH_EnableHook(MH_ALL_HOOKS);
	log_minhook_status("MH_EnableHook", "MH_ALL_HOOKS", enable_status);
    if (enable_status != MH_OK)
    {
        MessageBoxA(NULL, "Failed to enable hook", "FAIL", MB_ICONERROR | MB_OK);
        return;
    }

	debug_log_line("Enabled hooks!");

    debug_log_line("Calling OEP @ 0x1380000");

	HANDLE oep_thread = CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(0x1380000), nullptr, 0, &g_oep_thread_id);
	debug_log_line(std::format("oep_thread handle={} thread_id={} start=0x{:08x}",
		handle_text(oep_thread), g_oep_thread_id, 0x1380000));
	if (oep_thread)
	{
		CloseHandle(oep_thread);
	}

	debug_log_line("OEP launched");
}

BOOL __stdcall DllMain([[maybe_unused]] HMODULE hModule, DWORD ulReason, [[maybe_unused]] LPVOID lpReserved)
{
	if (ulReason != DLL_PROCESS_ATTACH) {
		return 0;
	}

    CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(init), nullptr, 0, nullptr);
    return 1;
}
