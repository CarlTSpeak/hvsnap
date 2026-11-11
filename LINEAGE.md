# Lineage

hvsnap (formerly `hvtrace`) is a fork of
[tandasat/SimpleSvm](https://github.com/tandasat/SimpleSvm) with NPT
execute-trap machinery adapted from
[tandasat/SimpleSvmHook](https://github.com/tandasat/SimpleSvmHook). Both are
MIT-licensed; verbatim notices are kept in `THIRD_PARTY/`.

## Upstream pins (the trees this fork started from)

| Upstream | Commit | License file |
|---|---|---|
| SimpleSvm | `c4a479e0244b5771c0c865f751f97d1b4f27c091` ("Make translation up to 1TB") | `THIRD_PARTY/SimpleSvm-LICENSE.txt` |
| SimpleSvmHook | `853589934fec0e8fa726f39137bdde9889a3b1a4` ("Resolve warnings with code analysis") | `THIRD_PARTY/SimpleSvmHook-LICENSE.txt` |

## What derives from what

| hvsnap file | Derivation |
|---|---|
| `hvsnap/hvsnap.hpp` | Derived from SimpleSvm's `SimpleSvm.hpp` (SVM/VMCB structures, segmentation helpers); modified for this tool's state layout |
| `hvsnap/hvsnap.cpp` | Derived from SimpleSvm's `SimpleSvm.cpp` (SVM setup, virtualize/devirtualize, NPT management) with the NPT execute-trap + `#NPF`/`#DB` step-over approach adapted from SimpleSvmHook's hooking example; extensively rewritten — IOCTL device, thread park/stub protocol, measured same-hit state capture (FS/GS/CR/EFER/DR6-7/SYSCALL MSRs/TSC/TSC_AUX/CR8), TSC cloak, trace ring are hvsnap's own |
| `hvsnap/x64.asm` | Derived from SimpleSvm's assembly linkage (`SvLaunchVm` / `SvHandleVmExit`) |
| `hvctl/*`, `tools/*`, `DOCUMENTATION.md`, `README.md` | Written for hvsnap (no upstream derivation beyond ordinary Win32 API usage) |
