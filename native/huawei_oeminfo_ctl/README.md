# Huawei OEMINFO recovery helper

This is a minimal AArch64 recovery executable for enumerating and reading
Huawei OEMINFO records through the model-matched `liboeminfo.so` and
`oeminfo_nvm_server` already present in an engineering recovery image.

It does not parse or overwrite the raw OEMINFO partition. The normal `scan`
and `read` commands are read-only. Writing requires the literal
`write-confirmed` command and is only appropriate after a complete raw
partition backup and record-by-record verification.

The helper is linked against the exact recovery library being used on the
device. A typical Clang/LLD build is:

```powershell
clang --target=aarch64-linux-android28 -fPIC -fno-builtin `
  -fno-stack-protector -c start.S -o start.o
clang --target=aarch64-linux-android28 -fPIC -fno-builtin `
  -fno-stack-protector -c main.c -o main.o
clang --target=aarch64-linux-android28 -fuse-ld=lld -nostdlib `
  -Wl,-e,_start -Wl,--dynamic-linker,/system/bin/linker64 `
  -Wl,-rpath,/vendor/lib64 -L PATH_TO_RECOVERY_VENDOR_LIB64 `
  start.o main.o -loeminfo -o huawei-oeminfo-ctl
```

Do not reuse a linked helper with another model's recovery library without
rebuilding and rechecking its exported API.
