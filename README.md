# ScumCheckerV2

C++ rewrite of ScumChecker with a WebView2 frontend.

## Layout

- `app/` - Win32 + WebView2 shell and bridge between JavaScript and the scanner.
- `scanner/` - native C++ scanner code migrated from the original project.
- `web/` - HTML/CSS/JS frontend.
- `profiles/` - game-specific check profiles.

## Profiles

- `SCUM` is the primary checker target.
- `Dota` contains defensive indicators for local Dota investigations, including Melonity and Ambrela/Ambrella naming.
- `CS` is present in the UI as `soon...` until real checker material is available.

The project is for defensive checking. Do not add rules or code that helps bypass anti-cheat, hide loaders, or improve cheat operation.

## Build

Run from PowerShell:

```powershell
.\scripts\build.ps1
```

The script downloads the official Microsoft WebView2 SDK NuGet package, configures CMake for x64, and builds `build-vs2022\Release\ScumCheckerV2.exe`.

The project intentionally generates Visual Studio 2022 projects with platform toolset `v143`. If CMake previously generated `build/` with Visual Studio 18 / `v145`, ignore that folder or close Visual Studio and delete it later. Use `build-vs2022/ScumCheckerV2.sln` instead.

## Regression tests

CTest is enabled by default. After configuring CMake, run:

```powershell
cmake --build build-vs2022 --config Release --target scanner_regression_tests
ctest --test-dir build-vs2022 -C Release --output-on-failure
```

The tests use temporary fixture files and the test process itself; they do not
scan the user's folders or load a driver. They cover repeated file scans,
changed rules, overlapping roots, risk scoring independent of display text,
deduplication, and growing or incomplete process module snapshots.

The desktop UI retains all findings from a single scan and receives them in
chunks of 256. The legacy caller-buffer API reports `findings_total` and
`findings_truncated` and returns `NS_STATUS_PARTIAL` when the buffer is too small.
Native consumers must rebuild against the current `NsReport` definition.
The scan summary also lists module failures, access limitations, and file roots
or directories skipped by entry limits, depth limits, or directory exclusions.
When Node.js is available, CTest also checks report status and chunk delivery.

## Signature exemptions and vulnerable drivers

Valid embedded Authenticode and installed catalog signatures exempt files from
generic filename, path, process-command-line and autorun heuristics. A certificate
merely being present is not sufficient: Windows trust verification must succeed.
Memory checks remain active for recognized game processes, including signed games.

Known vulnerable driver versions are an exception to the signature exemption.
The checker compares full SHA-256 hashes against the embedded verified vulnerable
samples from LOLDrivers. A name-only family match, when the image is unavailable,
is a low-priority request to verify the version, not proof of vulnerability or cheating.
The same database is used for files, loaded drivers and driver services.
Refresh detection metadata with `python scripts/update_driver_indicators.py`;
no driver binaries are downloaded. Source attribution is in `notices/LOLDrivers.md`.
