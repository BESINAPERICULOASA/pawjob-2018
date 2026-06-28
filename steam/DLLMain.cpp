#include <windows.h>
#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <format>
#include <filesystem>
#include <system_error>

#include <minhook/MinHook.h>

#include "emulator_core.h"

// Steam is now a 64-bit process, while CS:GO is still 32-bit (WOW64). This
// loader must therefore be built as x64 so it can be injected into steam.exe,
// yet the memory it carves out of the csgo.exe child still lives in the low 4
// GiB. Link the matching MinHook static lib for the target architecture.
#if defined(_M_X64) || defined(__x86_64__)
	#pragma comment(lib, "minhook/libMinHook.x64.lib")
#else
	#pragma comment(lib, "minhook/libMinHook.x86.lib")
#endif

#ifndef STEAM_ENABLE_FILE_LOGGING
#define STEAM_ENABLE_FILE_LOGGING 0
#endif

#ifndef STEAM_ENABLE_CARVE_DIAGNOSTICS
#define STEAM_ENABLE_CARVE_DIAGNOSTICS 0
#endif

#ifndef STEAM_ENABLE_EMULATOR_LOG
#define STEAM_ENABLE_EMULATOR_LOG 0
#endif

using CreateProcessW_t = BOOL(__stdcall*) (LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
CreateProcessW_t o_CreateProcessW = nullptr;
CreateProcessW_t o_CreateProcessW_kernel32 = nullptr;

static HMODULE g_module_handle = nullptr;
// The emulator now runs in-process inside steam.dll (see emulator_core.cpp);
// there is no child process or job object anymore. This flag keeps the
// historical "start once" guarantee across multiple csgo-launch detections.
static bool g_emulator_started = false;

static bool read_binary_file(const std::filesystem::path& path, std::vector<uint8_t>& out)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return false;

    file.seekg(0, std::ios::end);
    const std::streamoff size = file.tellg();
    if (size <= 0)
        return false;

    file.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(out.data()), size);
    return file.good();
}

static std::string narrow_for_search(std::wstring_view source)
{
    std::string out;
    out.resize(source.size());
    std::transform(source.begin(), source.end(), out.begin(), [](wchar_t ch) {
        const int narrowed = wctob(ch);
        return narrowed == EOF ? '?' : static_cast<char>(narrowed);
    });
    return out;
}

static std::string lowercase_ascii(std::string value)
{
    for (char& ch : value)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return value;
}

static bool is_csgo_launch(LPCWSTR lpApplicationName, LPCWSTR lpCommandLine, std::string& launch_text)
{
    std::wstring combined;
    if (lpApplicationName && *lpApplicationName)
    {
        combined += lpApplicationName;
        combined += L' ';
    }
    if (lpCommandLine && *lpCommandLine)
        combined += lpCommandLine;

    launch_text = narrow_for_search(combined);
    return lowercase_ascii(launch_text).find("csgo.exe") != std::string::npos;
}

#if STEAM_ENABLE_FILE_LOGGING
// Pretty-print a GetLastError() code as "<message> (<code>)".
static std::string last_error_string(DWORD err)
{
    LPSTR buf = nullptr;
    DWORD n = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPSTR>(&buf), 0, nullptr);
    std::string s;
    if (buf && n)
        s.assign(buf, n);
    if (buf)
        LocalFree(buf);
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' '))
        s.pop_back();
    if (s.empty())
        s = "error " + std::to_string(err);
    else
        s += " (" + std::to_string(err) + ")";
    return s;
}
#endif

// ===========================================================================
// Diagnostic instrumentation (carve phase, runs inside steam.exe).
// Durable, per-line-flushed log so it survives a hard crash of csgo. The last
// line written is the operation that detonated. Mirrors pawjob's mb_log.
// ===========================================================================
#ifndef STEAM_LOG_NAME
#define STEAM_LOG_NAME "pawjob_steam_debug.log"
#endif

#if STEAM_ENABLE_FILE_LOGGING
static std::ofstream g_slog;
static void slog_open()
{
    if (g_slog.is_open())
        g_slog.close();
    g_slog.clear();
    std::error_code ec;
    const auto log_path = std::filesystem::temp_directory_path(ec) / STEAM_LOG_NAME;
    if (!ec)
        g_slog.open(log_path, std::ios::out | std::ios::trunc);
    if (!g_slog.is_open())
        g_slog.open(STEAM_LOG_NAME, std::ios::out | std::ios::trunc);
}
static void slog(const std::string& line)
{
    if (g_slog.is_open())
        g_slog << line << '\n' << std::flush;   // flush -> survives the crash
}
#else
static void slog_open()
{
}
#define slog(line) ((void)0)
#endif

static const char* state_str(DWORD s)
{
    return s == MEM_COMMIT ? "COMMIT" : s == MEM_RESERVE ? "RESERVE" : s == MEM_FREE ? "FREE" : "?";
}
static const char* type_str(DWORD t)
{
    return t == MEM_IMAGE ? "IMAGE" : t == MEM_MAPPED ? "MAPPED" : t == MEM_PRIVATE ? "PRIVATE" : "-";
}

#if STEAM_ENABLE_CARVE_DIAGNOSTICS
// Walk the target's whole 32-bit address space and log every non-free region,
// including the Type field (MEM_IMAGE/MAPPED/PRIVATE) the old diagnostics never
// captured. This is the ground-truth layout steam's hook sees at carve time.
static void dump_vamap(HANDLE h)
{
    slog("=== pre-carve VA map of csgo (every non-free region) ===");
    uintptr_t addr = 0;
    int regions = 0;
    while (addr < 0x100000000ull)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(h, reinterpret_cast<void*>(addr), &mbi, sizeof(mbi)) != sizeof(mbi))
            break;
        if (mbi.State != MEM_FREE)
        {
            slog(std::format("  0x{:08x} size=0x{:<8x} {:<7} prot=0x{:<3x} {:<7} alloc=0x{:08x} allocprot=0x{:x}",
                reinterpret_cast<uintptr_t>(mbi.BaseAddress), mbi.RegionSize, state_str(mbi.State),
                mbi.Protect, type_str(mbi.Type), reinterpret_cast<uintptr_t>(mbi.AllocationBase), mbi.AllocationProtect));
            ++regions;
        }
        uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }
    slog(std::format("=== end VA map ({} non-free regions) ===", regions));
}
#endif

// Try to make [base, base+size) present + RWX in the target, mirroring every
// option the cheat has. Returns true if the whole span ends up committed+RWX.
static bool carve_region(HANDLE h, uintptr_t base, size_t size, std::string& detail)
{
    MEMORY_BASIC_INFORMATION pre{};
    VirtualQueryEx(h, reinterpret_cast<void*>(base), &pre, sizeof(pre));
    std::string prestr = std::format("pre[state={} prot=0x{:x} type={} alloc=0x{:08x} rsize=0x{:x}]",
        state_str(pre.State), pre.Protect, type_str(pre.Type),
        reinterpret_cast<uintptr_t>(pre.AllocationBase), pre.RegionSize);

    if (VirtualAllocEx(h, reinterpret_cast<void*>(base), size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))
    {
        detail = prestr + " -> RESERVE|COMMIT OK";
        return true;
    }
    DWORD g1 = GetLastError();
    if (VirtualAllocEx(h, reinterpret_cast<void*>(base), size, MEM_COMMIT, PAGE_EXECUTE_READWRITE))
    {
        detail = prestr + std::format(" -> RES|COM fail {} ; COMMIT OK", g1);
        return true;
    }
    DWORD g2 = GetLastError();
    DWORD oldp = 0;
    if (VirtualProtectEx(h, reinterpret_cast<void*>(base), size, PAGE_EXECUTE_READWRITE, &oldp))
    {
        detail = prestr + std::format(" -> RES|COM fail {} ; COMMIT fail {} ; PROTECT OK (old=0x{:x})", g1, g2, oldp);
        return true;
    }
    DWORD g3 = GetLastError();
    // per-page state-aware: commit reserved/free pages, protect committed ones.
    int ok = 0, tot = 0;
    for (uintptr_t p = base; p < base + size; p += 0x1000)
    {
        ++tot;
        MEMORY_BASIC_INFORMATION m{};
        if (VirtualQueryEx(h, reinterpret_cast<void*>(p), &m, sizeof(m)) != sizeof(m)) continue;
        if (m.State == MEM_FREE)      { if (VirtualAllocEx(h, reinterpret_cast<void*>(p), 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)) ++ok; }
        else if (m.State == MEM_RESERVE){ if (VirtualAllocEx(h, reinterpret_cast<void*>(p), 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) ++ok; }
        else                          { DWORD o; if (VirtualProtectEx(h, reinterpret_cast<void*>(p), 0x1000, PAGE_EXECUTE_READWRITE, &o)) ++ok; }
    }
    detail = prestr + std::format(" -> RES|COM fail {} ; COMMIT fail {} ; PROTECT fail {} ; per-page {}/{} RWX",
        g1, g2, g3, ok, tot);
    return ok == tot && tot > 0;
}

struct region_t { uintptr_t base; size_t size; std::string path, name; };

static bool parse_dump_region_filename(const std::filesystem::path& path, uintptr_t& base, size_t& size)
{
    const std::string name = path.filename().string();
    const size_t size_marker = name.rfind("_0x");
    if (size_marker == std::string::npos)
        return false;
    if (size_marker == 0)
        return false;

    const size_t base_marker = name.rfind("_0x", size_marker - 1);
    if (base_marker == std::string::npos)
        return false;

    const size_t ext_marker = name.find('.', size_marker);
    const std::string base_text = name.substr(base_marker + 1, size_marker - base_marker - 1);
    const std::string size_text = name.substr(size_marker + 1, ext_marker == std::string::npos ? std::string::npos : ext_marker - size_marker - 1);
    try
    {
        base = static_cast<uintptr_t>(std::stoull(base_text, nullptr, 16));
        size = static_cast<size_t>(std::stoull(size_text, nullptr, 16));
        return size > 0;
    }
    catch (const std::exception&)
    {
        return false;
    }
}

static std::filesystem::path module_directory()
{
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;)
    {
        const DWORD count = GetModuleFileNameW(g_module_handle, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (count == 0)
            return {};
        if (count < buffer.size() - 1)
        {
            buffer.resize(count);
            return std::filesystem::path(buffer).parent_path();
        }
        if (buffer.size() >= 32768)
            return {};
        buffer.resize(buffer.size() * 2);
    }
}

static std::filesystem::path find_repo_root()
{
    // Resolve the repo root from steam.dll's location. The Python emulator used
    // to be the marker (tools/runtime/local_cloud_emulator.py); now that the
    // emulator is compiled in, fall back to the AGENTS.md entry at the repo
    // root, which is the stable top-level descriptor.
    for (std::filesystem::path path = module_directory(); !path.empty(); path = path.parent_path())
    {
        if (std::filesystem::exists(path / "AGENTS.md"))
            return path;

        const auto parent = path.parent_path();
        if (parent.empty() || parent == path)
            break;
    }
    return {};
}

static std::filesystem::path process_image_directory(HANDLE process)
{
    std::wstring buffer(32768, L'\0');
    DWORD size = static_cast<DWORD>(buffer.size());
    if (!QueryFullProcessImageNameW(process, 0, buffer.data(), &size) || size == 0)
        return {};
    buffer.resize(size);
    return std::filesystem::path(buffer).parent_path();
}

static std::filesystem::path infer_game_directory(
    LPCWSTR application_name,
    LPCWSTR current_directory,
    HANDLE process)
{
    if (current_directory && *current_directory)
        return std::filesystem::path(current_directory);

    if (application_name && *application_name)
        return std::filesystem::path(application_name).parent_path();

    return process_image_directory(process);
}

static void start_local_cloud_emulator(const std::filesystem::path& game_dir)
{
    // Start-once guard: subsequent csgo-launch detections reuse the single
    // in-process listener. emulator_start() is also idempotent internally.
    if (g_emulator_started)
        return;

    // The emulator runs on the carve thread (the CreateProcessW hook), which
    // is a steam.exe thread. An uncaught C++ exception here would call
    // std::terminate() and take steam.exe down with it, so the whole body is
    // guarded: any failure is logged and the carve path continues regardless.
    try {
        // The runtime dir sits beside the .py the old helper used to spawn, so
        // the persisted key path is identical to what tools/runtime/ produced.
        // The key file is reused across launches — load_or_generate_key() handles
        // the exists/regenerate branches.
        const std::filesystem::path repo_root = find_repo_root();
        const std::filesystem::path runtime_dir = !repo_root.empty()
            ? repo_root / "build" / "runtime"
            : std::filesystem::path("build") / "runtime";
        const std::filesystem::path config_dir = game_dir / "pawjob" / "configs";
        std::error_code ec;
        std::filesystem::create_directories(runtime_dir, ec);
        std::filesystem::create_directories(config_dir, ec);

        const std::filesystem::path key_path = runtime_dir / "local_cloud_spki1024_private.pem";

        EmulatorConfig cfg;
        cfg.key_path = key_path;
        cfg.config_dir = config_dir;
        cfg.quiet = false;
        // The emulator log is ON by default so a fault or protocol mismatch is
        // visible in build\runtime\local_cloud_emulator.log without a special
        // build. STEAM_ENABLE_EMULATOR_LOG no longer gates this; it's always on.
        cfg.log_path = runtime_dir / "local_cloud_emulator.log";

        slog("starting local cloud emulator for config dir: " + config_dir.string());
        // A failed emulator must never tear down the carve path. emulator_start()
        // returns false on bind/CNG failure; we log and move on.
        if (!emulator_start(cfg))
        {
            slog("cloud emulator failed to start (bind or CNG error); carve continues");
            return;
        }
        g_emulator_started = true;
        slog("cloud emulator listener running in-process on 127.0.0.1:5444");
    } catch (const std::exception& exc) {
        const std::string msg = std::format("cloud emulator init exception: {} (carve continues)", exc.what());
        slog(msg);
        OutputDebugStringA(("steam: " + msg + "\n").c_str());
    } catch (...) {
        slog("cloud emulator init unknown exception (carve continues)");
        OutputDebugStringA("steam: cloud emulator init unknown exception (carve continues)\n");
    }
}

static void stop_local_cloud_emulator()
{
    // emulator_stop() sets the stop flag and closesocket()s the listener so
    // accept() returns. Client threads die with steam.exe on process exit —
    // no joins (loader-lock safe from DLL_PROCESS_DETACH). The old job object
    // / separate-process handles are gone since there is no child process.
    if (!g_emulator_started)
        return;
    emulator_stop();
    g_emulator_started = false;
}

static std::filesystem::path legacy_dump_region_dir()
{
    std::wstring dir = L"C:\\";
    constexpr std::array<wchar_t, 8> legacy = {
        static_cast<wchar_t>(0x6d), static_cast<wchar_t>(0x6f), static_cast<wchar_t>(0x6e), static_cast<wchar_t>(0x65),
        static_cast<wchar_t>(0x79), static_cast<wchar_t>(0x62), static_cast<wchar_t>(0x6f), static_cast<wchar_t>(0x74)
    };
    dir.append(legacy.begin(), legacy.end());
    return dir;
}

static std::filesystem::path dump_region_dir()
{
    const std::filesystem::path primary{ "C:\\pawjob" };
    if (std::filesystem::exists(primary))
        return primary;

    const auto legacy = legacy_dump_region_dir();
    if (std::filesystem::exists(legacy))
        return legacy;

    return primary;
}

BOOL __stdcall hooked_CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcAttr,
    LPSECURITY_ATTRIBUTES lpThreadAttr, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCWSTR lpCurrentDir, LPSTARTUPINFOW pStartupInfo, LPPROCESS_INFORMATION pProcessInfo)
{
    if (!o_CreateProcessW)
    {
        SetLastError(ERROR_INVALID_FUNCTION);
        return FALSE;
    }

    std::string launch_text;
    if (!is_csgo_launch(lpApplicationName, lpCommandLine, launch_text)) {
        return o_CreateProcessW(lpApplicationName, lpCommandLine, lpProcAttr, lpThreadAttr, bInheritHandles,
            dwCreationFlags, lpEnvironment, lpCurrentDir, pStartupInfo, pProcessInfo);
    }

    slog_open();
    slog(std::format("csgo launch detected: dwCreationFlags=0x{:x} (SUSPENDED={}, UNICODE_ENV={}) bInheritHandles={} appname={} cmdlen={}",
        dwCreationFlags,
        (dwCreationFlags & CREATE_SUSPENDED) ? 1 : 0,
        (dwCreationFlags & CREATE_UNICODE_ENVIRONMENT) ? 1 : 0,
        bInheritHandles,
        lpApplicationName ? "(set)" : "(null)",
        lpCommandLine ? wcslen(lpCommandLine) : 0));
    slog("launch text: " + launch_text);

    BOOL result = o_CreateProcessW(lpApplicationName, lpCommandLine, lpProcAttr, lpThreadAttr, bInheritHandles,
        dwCreationFlags, lpEnvironment, lpCurrentDir, pStartupInfo, pProcessInfo);

    if (!result) {
        slog(std::format("CreateProcessW for csgo FAILED: {}", last_error_string(GetLastError())));
        return result;
    }

    if (HANDLE handle = pProcessInfo->hProcess; handle) {
        slog(std::format("csgo created pid={} hProcess=0x{:p} -- carve phase begins (process is {})",
            pProcessInfo->dwProcessId, static_cast<void*>(handle),
            (dwCreationFlags & CREATE_SUSPENDED) ? "SUSPENDED" : "RUNNING"));

        const auto game_dir = infer_game_directory(lpApplicationName, lpCurrentDir, handle);
        start_local_cloud_emulator(game_dir);

#if STEAM_ENABLE_CARVE_DIAGNOSTICS
        dump_vamap(handle);
#endif

        const std::filesystem::path path = dump_region_dir();
        std::vector<region_t> regions;
        for (const auto& file : std::filesystem::directory_iterator{ path }) {
            if (file.path().extension() != ".bin")
                continue;

            uintptr_t base = 0;
            size_t size = 0;
            if (parse_dump_region_filename(file.path(), base, size)) {
                regions.push_back({ base, size, file.path().string(), file.path().filename().string() });
            } else {
                slog(std::format("unparseable region {}", file.path().string()));
            }
        }
        std::sort(regions.begin(), regions.end(), [](const region_t& lhs, const region_t& rhs) {
            return lhs.base < rhs.base;
        });

        slog(std::format("=== carving {} dumped regions ===", regions.size()));
        int carved = 0, carve_fail = 0, written = 0, write_fail = 0;
        std::vector<std::string> failed_bases;
        for (const auto& r : regions) {
            std::string detail;
            bool ok = carve_region(handle, r.base, r.size, detail);
            slog(std::format("{} {}  base=0x{:08x} size=0x{:<6x}  {}",
                ok ? "  OK  " : "!FAIL!", r.name, r.base, r.size, detail));
            if (!ok) { ++carve_fail; failed_bases.push_back(std::format("0x{:08x}({})", r.base, r.name)); continue; }
            ++carved;

            std::vector<uint8_t> hack{};
            if (!read_binary_file(r.path, hack)) {
                slog(std::format("       {} read FAILED (empty) -- permission? run steam as admin", r.name));
                continue;
            }
            if (WriteProcessMemory(handle, reinterpret_cast<void*>(static_cast<uintptr_t>(r.base)), hack.data(), hack.size(), nullptr)) {
                ++written;
            } else {
                ++write_fail;
                slog(std::format("       {} WriteProcessMemory FAILED base=0x{:08x} -> {}",
                    r.name, r.base, last_error_string(GetLastError())));
            }
        }

        slog(std::format("=== carve summary: carved={} carve_fail={} written={} write_fail={} (of {}) ===",
            carved, carve_fail, written, write_fail, regions.size()));
        if (!failed_bases.empty()) {
            std::string joined;
            for (auto& b : failed_bases) { joined += b; joined += ' '; }
            slog("FAILED regions: " + joined);
        }
        slog("carve phase complete");
    }

    return result;
}

void init()
{
    if (!std::filesystem::exists(dump_region_dir())) {
        MessageBoxA(0, "Please put the folder pawjob into C: -- Exiting", "Failure", 0);
        TerminateProcess(reinterpret_cast<HANDLE>(-1), 0);
        return;
    }

    slog_open();
    slog("steam helper initialized; waiting on game launch...");

    const MH_STATUS init_status = MH_Initialize();
    if (init_status != MH_OK && init_status != MH_ERROR_ALREADY_INITIALIZED)
    {
        MessageBoxA(NULL, "Failed to initialize hook", "FAIL", MB_ICONERROR | MB_OK);
        return;
    }

    const MH_STATUS kernelbase_status = MH_CreateHookApi(
        L"kernelbase.dll", "CreateProcessW", hooked_CreateProcessW, reinterpret_cast<void**>(&o_CreateProcessW));
    if (kernelbase_status != MH_OK && kernelbase_status != MH_ERROR_ALREADY_CREATED)
    {
        MessageBoxA(NULL, "Failed to create hook", "FAIL", MB_ICONERROR | MB_OK);
        return;
    }

    if (o_CreateProcessW)
    {
        const MH_STATUS kernel32_status = MH_CreateHookApi(
            L"kernel32.dll", "CreateProcessW", hooked_CreateProcessW, reinterpret_cast<void**>(&o_CreateProcessW_kernel32));
        if (kernel32_status != MH_OK && kernel32_status != MH_ERROR_ALREADY_CREATED &&
            kernel32_status != MH_ERROR_MODULE_NOT_FOUND && kernel32_status != MH_ERROR_FUNCTION_NOT_FOUND &&
            kernel32_status != MH_ERROR_UNSUPPORTED_FUNCTION)
        {
            slog(std::format("Optional kernel32 CreateProcessW hook failed with MinHook status {}; continuing with kernelbase hook.",
                static_cast<int>(kernel32_status)));
        }
    }

    const MH_STATUS enable_status = MH_EnableHook(MH_ALL_HOOKS);
    if (enable_status != MH_OK && enable_status != MH_ERROR_ENABLED)
    {
        MessageBoxA(NULL, "Failed to enable hook", "FAIL", MB_ICONERROR | MB_OK);
        return;
    }

    slog("Waiting on game launch...");
}

BOOL __stdcall DllMain(HMODULE hModule, DWORD ulReason, [[maybe_unused]] LPVOID lpReserved)
{
    if (ulReason == DLL_PROCESS_DETACH)
    {
        stop_local_cloud_emulator();
        return TRUE;
    }

    if (ulReason != DLL_PROCESS_ATTACH)
        return TRUE;

    g_module_handle = hModule;
    DisableThreadLibraryCalls(hModule);
    if (HANDLE thread = CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(init), nullptr, 0, nullptr))
        CloseHandle(thread);
    return TRUE;
}
