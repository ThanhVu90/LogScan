# LogScan

[![CI](https://github.com/ThanhVu90/LogScan/actions/workflows/ci.yml/badge.svg)](https://github.com/ThanhVu90/LogScan/actions/workflows/ci.yml)

A C17 command-line tool for investigating Apache/Nginx **Common or Combined access logs**. Find frequent request paths, count server errors, and isolate a UTC time window without loading the entire file into memory. This is a portfolio project with synthetic examples, not a claim of production deployment.

## An incident investigation in three commands

```sh
logscan examples/access.txt
logscan --json --since 2026-10-28T00:00:00Z --until 2026-10-29T00:00:00Z examples/access.txt
logscan --fail-on-5xx examples/access.txt
```

The sample contains 5 lines: 4 requests, 1 malformed record, 1 HTTP 5xx, 440 known response bytes, and 1 unknown response size. `/api/tickets` is the most frequent path with 2 requests. The last command prints a report and exits **1**, making an error threshold usable in a script. Malformed lines are counted and reported on stderr; `--strict` rejects them instead.

## Build and test

Requirements: a C17 compiler, CMake 3.20+, and Python 3 for tests only. The executable uses the C standard library plus small platform-specific stdin/signal handling; it has no third-party runtime dependency.

Linux with GCC or Clang:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
./build/logscan --json examples/access.txt
```

Windows with Visual Studio 2022 C++ build tools (includes the C compiler):

```powershell
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
.\build\Release\logscan.exe --json examples/access.txt
```

For a single-config Windows Ninja/MinGW build, the executable is `build/logscan.exe`. Python is not needed when configuring with `-DBUILD_TESTING=OFF`.

## CLI contract

| Option | Meaning |
|---|---|
| `--json` | Machine-readable JSON, schema version 1 |
| `--since UTC` / `--until UTC` | Inclusive lower / exclusive upper bound, `YYYY-MM-DDTHH:MM:SSZ` |
| `--top N` | 1–100 paths, default 10; count descending, then path ascending |
| `--max-paths N` | Exact distinct-path capacity, 1–100000, default 4096 |
| `--strict` | Stop at the first malformed line without producing a report |
| `--fail-on-5xx` | Exit 1 if selected requests contain HTTP 500–599 |
| `--` | End options, allowing filenames beginning with `-` |
| `-` | Read stdin, at most once |

At most 64 input files are accepted. Duplicate options are rejected. Exit codes: **0** success, **1** selected 5xx with the flag enabled, **2** usage/strict-input failure, **3** I/O, allocation, capacity, or arithmetic overflow. A scan failure emits no report; an output-device failure may leave partial output, so always check the exit code.

## What makes the result reviewable

- Streaming reader drains oversized lines before reading the next record; embedded NUL cannot hide a suffix.
- Checked 64-bit counters, Gregorian dates, timezone conversion, and explicit unknown response sizes.
- Exact bounded aggregation: exceeding capacity fails visibly instead of silently dropping paths.
- Deterministic JSON and independent Python aggregation checks against generated data.
- C core tests, CLI boundary tests, Linux sanitizer tests, and a bounded libFuzzer smoke run in CI.

See [architecture and tradeoffs](docs/ARCHITECTURE.md), [input and JSON contract](docs/FORMAT.md), and [verification](docs/VERIFICATION.md).

## Privacy and scope

Reports omit client addresses, identities, referrers, user agents, and query/fragment suffixes. **Paths can still contain sensitive identifiers.** Review reports before sharing. LogScan does not upload logs or make network requests.

It is not a general log-format detector: JSON logs, syslog, custom formats, gzip input, latency percentiles, live tailing, and route-template inference are out of scope. `/users/1` and `/users/2` remain separate paths. Large cardinality requires a tighter time range or a larger explicit cap.
