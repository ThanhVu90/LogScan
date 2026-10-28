# Input and output contract

Input: `host ident user [DD/Mon/YYYY:HH:MM:SS +/-HHMM] "METHOD TARGET HTTP/1.1" STATUS BYTES`, optionally followed by quoted referrer and user-agent fields. Spaces or tabs separate fields. Host/identity tokens are limited to 255 bytes. Escaped quotes/backslashes are scanned without decoding. Extra fields are rejected.

Supported request protocol tokens: HTTP/1.0, HTTP/1.1, HTTP/2.0, HTTP/3.0. A request of `"-"` maps to path `-`. Request methods are nonempty tokens of at most 32 bytes. Targets are retained literally up to the first `?` or `#`; they are not URL-decoded, normalized, or restricted to origin-form paths.

Dates use English month abbreviations, years 1970–9999, real Gregorian month lengths, hours 0–23, minutes/seconds 0–59. Leap seconds are rejected. Numeric offsets accept hours 0–23 and minutes 0–59. UTC results can precede 1970 when local time is near the lower boundary. Filters require UTC `Z`, not numeric offsets.

Status is exactly three digits, 100–599. Bytes are an unsigned 64-bit integer or `-` for unknown; unknown sizes contribute zero to known-byte totals. Arithmetic overflow fails the scan. Line limit is 8192 bytes excluding LF and an optional preceding CR; LF, CRLF, and final lines without newline are supported. NUL, DEL, and ASCII controls except tab make a line invalid. Overlong lines are drained; no truncated prefix is parsed.

## JSON schema 1

- `lines = valid + invalid`; `valid = requests + filtered` for a completed scan.
- `overlong` and `binary` are subsets of `invalid` and may overlap.
- `bytes`, `unknown_size_requests`, `server_errors`, `distinct_paths`, and `statuses` describe only selected requests.
- `first_unix` and `last_unix` are min/max UTC epoch seconds, null when no requests are selected. Input need not be sorted.
- `top_paths` contains at most `--top` entries: `path`, `requests`, `server_errors`, `bytes`.
- Counters are JSON integers up to UINT64_MAX. JavaScript consumers need a lossless JSON parser for values above 2^53−1.
- Raw bytes >=127 are escaped individually as `\u00xx`. This is byte-preserving representation, **not UTF-8 decoding**. Text reports show such bytes as `\xXX`. JSON quotes and backslashes are escaped.
