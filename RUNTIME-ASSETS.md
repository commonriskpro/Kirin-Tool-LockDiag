# Runtime assets

This repository intentionally excludes `bin/`, `obj/`, and the Huawei runtime blobs
(`loaders/` and `fastboot/`). They are build output or vendor binaries, not source.

To run the built application, copy these folders from your existing Kirin-Tool
release into the build output:

- `loaders/` -> `bin/Release/net8.0-windows/loaders/`
- `fastboot/` -> `bin/Release/net8.0-windows/fastboot/`

The app resolves `fastboot/fastboot.exe` relative to the current working directory,
so run `Kirin-Tool.exe` from the output directory with those folders next to it.

The **Lock Diagnostic** feature needs the factory fastboot loaded through VCOM.
It also accepts a base `UPDATE.APP` and a signed factory `fastboot.img` for the
image comparison; both are optional.
