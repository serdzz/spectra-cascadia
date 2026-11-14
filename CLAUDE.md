# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is
Spectra-Cascadia: a from-scratch MeshCore **repeater** firmware for the DX-LR30 (STM32F103C8 + SX1262, 20 KB RAM), forked from SPECTER. Forwarding, wire formats, CLI names and reply text follow upstream MeshCore (`src/Mesh.cpp`, `examples/simple_repeater`) as closely as possible. Upstream changes are **ported by hand, never merged**. `UPSTREAM_SYNC.md` is the policy (in/out of scope, budgets, versioning) and `.upstream-sync.json` holds the sync state.

## Commands
- Build all six envs: `pio run` (repeaters `specter`, `specter_eu`, `specter_xl`, `specter_xl_eu`; companions `specter_companion`, `specter_companion_eu`)
- Flash XL: `pio run -e specter_xl -t upload` (OpenOCD + ST-Link, flash size forced to 128 KB, writes the `.hex`)
- Host tests (no hardware):
  `CRYPTO_DIR=.pio/libdeps/specter/Crypto MESHCORE_DIR=/path/to/MeshCore test/host/run.sh`
  Without `MESHCORE_DIR` only `test_forwarding.cpp` runs; `test_xl.cpp` and `test_companion.cpp` are skipped. They use upstream's `lib/ed25519` as the reference.
  There is no single-test selector: each file is one binary and prints `PASS`/`FAIL` lines from `CHECK(cond, msg)`, so grep its output.
- Full release check (what CI runs): `tools/ci.sh`. It runs the tests, all six builds, and image checks, and writes to `dist/`. By default it uses `tools/offline/setup.sh` → `platformio-offline.ini` (envs `us xl eu xl_eu companion companion_eu`, deps in `~/.spectra-deps`). That setup script assumes Linux/apt (`/usr/bin/arm-none-eabi-*`). On a Mac, run `CI_ONLINE=1 CRYPTO_DIR=… MESHCORE_DIR=… tools/ci.sh` instead.
- Serial console: USART1 via CH340 @ 115200. The ROM bootloader only works at **57600** (`stm32flash -b 57600`) and needs the physical BOOT0+RESET buttons; DTR/RTS entry does not work.

## Architecture
- **`src/main.cpp` is almost the whole firmware** (one translation unit, about 3.6k lines): radio driver glue, packet parse/forward rules, region HMAC scoping, TX queue/LBT/airtime, flash settings + clock journal, mesh clock sync, battery/power, and the USB serial CLI.
- **`src/xl_admin.inc`** is `#include`d into main.cpp only under `SPECTER_XL`. It is the server side of `simple_repeater`: ANON_REQ login, status/telemetry/neighbours/ACL, CLI over TXT_MSG. It also holds the crypto (`ecdh`, `encrypt_then_mac`, `mac_then_decrypt`) and the `xl_send_flood`/`xl_send_direct` senders.
- **`src/companion.inc`** (`SPECTER_COMPANION`, always together with `SPECTER_XL`) is the client side of upstream `examples/companion_radio`: the app's serial frame protocol plus contacts, DMs/ACKs, channels and repeater requests. In this build `on_receive()` hands every packet to `comp_on_receive()`. As a result `handle_flood`/`handle_direct` and the remote-admin server are never called and get optimised out, and the node never forwards. App frames (`<`) and console lines share `Serial1`, via `comp_serial_byte()` in `cli_poll()`. Several table sizes shrink under `SPECTER_COMPANION` (`DEDUP_SIZE`, `RT_SLOTS`, `TELE_N`, `XL_MAX_*`, `LH_N`) to make RAM room for the contact store.
- **Build variants** are selected only by `-D` flags (`platformio.ini`): `SPECTER_XL`, plus region defaults (`LORA_FREQ_KHZ` etc.). Every `#ifndef` default near the top of main.cpp is a first-boot default only. Runtime settings saved in flash win.
- **Memory layout:** standard image ≤ 62 KB (`board_upload.maximum_size = 63488`). 0x0800F800 holds settings and 0x0800FC00 the clock journal (1 KB pages, survive upgrades). XL (`specter_xl.ld`) puts RadioLib + Crypto and `XL_HI`-tagged functions in 0x08010000+. That half may be missing on a given chip, so code there must only run from `loop()` after setup()'s check. `tools/xl_hex.py` fails the build if a global constructor lands up there, and emits the `.hex`. XL must be flashed as `.hex`, never `.bin` (a `.bin` zeros the settings pages). The companion uses `specter_companion.ld`: the upper half ends at 0x0801CC00, and 0x0801CC00–0x0801FBFF holds the contact store (two alternating 6 KB copies). `tools/ci.sh` fails if an image has data there.
- **Host tests** (`test/host/`) `#include "../../src/main.cpp"` directly, with stubs in `test/host/stub/` (Arduino, SPI, RadioLib, IWatchdog). Fake flash/UID come from `CONFIG_ADDR`, `JOURNAL_ADDR`, and `UID_BASE` defined before the include. New hardware-touching code must keep compiling against these stubs (guard real-hardware bits with `ARDUINO_ARCH_STM32`).
- Hardware quirks: SX1262 DIO1 is not wired, so RadioLib runs in polling mode (non-blocking receive plus `getIrqFlags()`; blocking `receive()` hangs). Adverts must be validly Ed25519-signed. See `docs/development-notes.md`.

## Constraints when changing code
- Flash is the binding constraint. The standard build has only a few hundred bytes left, so prefer XL-only (`#ifdef SPECTER_XL`) for new features. XL budget is about 52/62 KB low flash, 29/63 KB high flash, and 13/20 KB static RAM; keep ≥3 KB for the stack and decline anything pushing static RAM past 15 KB. Check `RAM:`/`Flash:` lines after building.
- Use upstream's exact CLI command names, reply text (`  -> ` prefix), and defaults. Don't invent formats; the apps parse them.
- Add a host test for each ported or changed behaviour.

## Releasing
Every push to `main` runs `.github/workflows/release.yml` (`tools/ci.sh`). If `FW_VERSION` in `src/main.cpp` has no tag yet, CI tags the commit and publishes a release using that version's section in `CHANGELOG.md`. So, to release: bump `FW_VERSION` **and** the `* Version:` header comment in main.cpp, add a `## [X.Y.Z.N] - date` CHANGELOG section, then push. **Never push tags.** Versions are upstream MeshCore `X.Y.Z` plus our fourth number, which resets to `.1` on a new upstream release.
