<p align="center">
  <img src="favicon.svg" width="120" height="120" alt="pawjob">
</p>

<h1 align="center">pawjob</h1>

<p align="center">
  <b>Cheat for archived 2018 CS:GO</b>
</p>

---

<p align="center">
  <a href="#what-is-this">What is this?</a> &nbsp;·&nbsp;
  <a href="#why-2018-csgo">Why 2018 CS:GO?</a> &nbsp;·&nbsp;
  <a href="#building">Building</a> &nbsp;·&nbsp;
  <a href="#how-it-works">How it works</a> &nbsp;·&nbsp;
  <a href="#network">Network</a> &nbsp;·&nbsp;
  <a href="#credits">Credits</a>
</p>

---

## What is this?

**pawjob** is a cheat for **archived 2018 CS:GO** — the build that shipped ~8 years ago. It's two DLLs:

| DLL | Bitness | Loaded into | Role |
|-----|---------|-------------|------|
| `steam.dll` | **x64** | `steam.exe` | Hooks `CreateProcessW`, injects the cheat into the game child process |
| `pawjob.dll` | **x86** | `csgo.exe` | The cheat module itself |

Steam dropped 32-bit Windows on January 1, 2026, so `steam.exe` is now a 64-bit process. CS:GO is still 32-bit (WOW64). That's why there are two DLLs at different bitness.

## Why 2018 CS:GO?

- **CS2 is the current game.** Nobody is playing 2018 CS:GO for fair matches anymore.
- **VAC is gone.** A CS2 update split CS:GO and CS2 into separate AppIDs — inventory, ranks, and VAC bans no longer sync. There is no anti-cheat surface left on the 2018 build.
- **It's a dead game.** Releasing this costs no real player a competitive match.

## Building

Requires **Visual Studio 2022** with the C++ desktop workload.

```
build.bat
```

Or manually (note the two different platforms):

```bat
MSBuild steam\steam.vcxproj  -p:Configuration=Release -p:Platform=x64   -m
MSBuild pawjob\pawjob.vcxproj -p:Configuration=Release -p:Platform=Win32 -m
```

> **Don't build the whole solution at one platform.** `Release|x64` would build `pawjob` as 64-bit (wrong — it uses hard-coded 32-bit addresses), and `Release|x86` would build `steam` as 32-bit (wrong — it must be 64-bit to load into `steam.exe`). Build each project at its own platform.

**Output:**
- `x64\Release\steam.dll` → inject into `steam.exe`
- `Release\pawjob.dll` → loaded into `csgo.exe` by `steam.dll`

**Dependencies:** [MinHook](https://github.com/TsudaKageyu/minHook) is included in `thirdparty/minhook/`.

## How it works

1. **`steam.dll`** gets injected into `steam.exe` (64-bit). It hooks `CreateProcessW` via MinHook on `kernelbase.dll`.
2. When Steam launches `csgo.exe`, the hook walks `C:\pawjob\*_<basehex>_<sizehex>.<ext>`, parses the base address and size from each filename, and `VirtualAllocEx` + `WriteProcessMemory`s the bytes into the csgo child at the named base.
3. On the same launch, `steam.dll` starts an in-process localhost cloud emulator on `127.0.0.1:5444`. It dies with `steam.exe` on exit — no child process, no external dependency.
4. **`pawjob.dll`** is the cheat module loaded into `csgo.exe`. It sets up a local config tree next to the game executable.

## Network

Every socket the DLLs touch is `127.0.0.1`. The only network redirection is the historical cloud endpoint `51.222.158.143:5444` → `127.0.0.1:5444`. Unrelated Steam/game networking is left alone. The full source is right here — verify it yourself.

## Credits

- **PinkKing** — cracked moneybot
- **MOxXiE1337** — performance fixes
- Built with [MinHook](https://github.com/TsudaKageyu/minHook)

---

<p align="center">
  <sub>Don't use this on CS2. Don't be weird.</sub>
</p>
