# Verification

## Local verification before publication — 2026-10-28

Windows x64, LLVM/MinGW Clang 23.1.4, C17 Release build, Python 3.12.14:

- CMake build completed with `-Wall -Wextra -Wpedantic -Werror` for application/core sources.
- CTest: 2 suites passed.
- Core: 36 assertions, 50,000 deterministic random-byte parser calls, and truncations of a valid record.
- CLI: 35 test methods, 34 passed and 1 skipped. `/dev/full` output failure is POSIX-specific and runs in Linux CI.
- Differential test compares all per-path counts, bytes, server errors, and status counts for 3,000 generated records against an independent Python dictionary implementation.
- The checked-in sample JSON was produced by the executable and its totals verified.

These checks cover boundaries and contracts; they are not a proof that no defect exists. Random-byte tests are not equivalent to coverage-guided fuzzing.

## Continuous integration

[CI runs](https://github.com/ThanhVu90/LogScan/actions/workflows/ci.yml) are the source of truth for each commit. The workflow builds/tests with Linux GCC and Windows MSVC, runs Linux Clang AddressSanitizer/UndefinedBehaviorSanitizer tests, and performs 20,000 libFuzzer parser executions with a valid input seed. This is a bounded smoke run, not a sustained security fuzzing campaign.

To reproduce sanitizer checks on Linux:

```sh
cmake -S . -B build-asan -DCMAKE_C_COMPILER=clang -DLOGSCAN_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-asan
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 ctest --test-dir build-asan --output-on-failure
```

## Reproducible throughput smoke test

```sh
python tests/benchmark.py build/logscan --lines 1000000
```

Use `build/logscan.exe` or `build/Release/logscan.exe` on Windows. Generation happens before the timer. The script validates aggregate totals and measures child-process start, scan, and report time, excluding generation. It does not measure peak memory.

One local Windows run: 1,000,000 synthetic lines, 80,900,000 input bytes, 100 distinct paths, **1.739 seconds** (~575,093 lines/s). This single-machine observation is not a general performance guarantee or a comparison with other tools. Disk caching, compiler, hardware, line length, and cardinality change the result. Memory bounds are explained in the architecture document, not inferred from this timing.
