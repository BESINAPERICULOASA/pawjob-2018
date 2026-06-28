// emulator_core.h — localhost config/cloud emulator embedded in steam.dll.
//
// This replaces the former tools/runtime/local_cloud_emulator.py. The RSA/AES
// session exchange, the post-login frame machine, and config persistence all
// run on a 127.0.0.1 listener thread spawned inside the Steam helper process,
// so the runtime surface is exactly two DLLs (steam.dll + pawjob.dll) with no
// external Python dependency.
//
// Crypto comes only from Windows CNG (bcrypt.lib). The DER/PEM/Base64 wire
// formats are produced by the tiny codec in emulator_der.*. No third-party
// crypto library is linked.
#pragma once

#include <filesystem>
#include <string>

struct EmulatorConfig {
    std::filesystem::path key_path;     // e.g. build\runtime\local_cloud_spki1024_private.pem
    std::filesystem::path config_dir;    // e.g. <game>\pawjob\configs
    std::filesystem::path log_path;      // optional; mirrors the old --log path
    bool quiet = true;                  // when true and log_path empty, emits nothing
};

// Spawn the listener thread (idempotent; subsequent calls reuse the running
// listener). Returns false if the listener could not start (bind failure etc.)
// — never throws into the carve path that invoked it.
bool emulator_start(const EmulatorConfig& cfg);

// Signal the listener to stop and closesocket()s the listener socket. Does NOT
// join client threads (dies with steam.exe on process exit). Safe to call from
// DllMain DLL_PROCESS_DETACH (no loader-lock hazard).
void emulator_stop();
