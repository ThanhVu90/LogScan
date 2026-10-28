#include "logscan.h"
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
static void usage(FILE *out) {
    fputs("Usage: logscan [OPTIONS] FILE...\n\n  --json             Emit deterministic JSON "
          "instead of a text summary\n  --strict           Stop on malformed input without a "
          "report\n  --since UTC        Inclusive YYYY-MM-DDTHH:MM:SSZ lower bound\n  --until UTC  "
          "      Exclusive YYYY-MM-DDTHH:MM:SSZ upper bound\n  --top N            Show 1..100 "
          "paths (default 10)\n  --max-paths N      Limit exact aggregation to 1..100000 distinct "
          "paths (4096)\n  --fail-on-5xx      Exit 1 when selected requests contain HTTP 5xx\n  -- "
          "                End options; use - as a filename for standard input\n  --version        "
          "  Print version\n  --help             Print this help\n\nExit: 0 success, 1 selected "
          "5xx, 2 usage/strict input, 3 I/O/resource failure.\n",
          out);
}
static bool positive(const char *s, size_t maximum, size_t *value) {
    if (!*s)
        return false;
    *value = 0;
    while (*s) {
        if (*s < '0' || *s > '9')
            return false;
        unsigned digit = (unsigned)(*s++ - '0');
        if (*value > (maximum - digit) / 10)
            return false;
        *value = *value * 10 + digit;
        if (*value > maximum)
            return false;
    }
    return *value > 0;
}
static int scan(FILE *input, ls_stats *stats, const ls_filter *filter, bool strict) {
    char line[LS_LINE_LIMIT + 2];
    size_t length;
    bool overlong, binary;
    int result;
    while ((result = ls_read_line(input, line, &length, &overlong, &binary)) == 1) {
        if (stats->lines == UINT64_MAX) {
            fputs("logscan: line counter overflow\n", stderr);
            return 3;
        }
        stats->lines++;
        ls_record record;
        if (overlong || binary || !ls_parse(line, length, &record)) {
            stats->invalid++;
            stats->overlong += (uint64_t)overlong;
            stats->binary += (uint64_t)binary;
            if (strict) {
                fprintf(stderr,
                        "logscan: malformed input at cumulative line %" PRIu64
                        "; no report produced\n",
                        stats->lines);
                return 2;
            }
            continue;
        }
        stats->valid++;
        const char *error = ls_accept(stats, &record, filter);
        if (error) {
            fprintf(stderr, "logscan: %s; no report produced\n", error);
            return 3;
        }
    }
    if (result < 0) {
        fputs("logscan: input read failed; no report produced\n", stderr);
        return 3;
    }
    return 0;
}
int main(int argc, char **argv) {
    const char *files[64];
    size_t file_count = 0, top = 10, capacity = 4096;
    bool json = false, strict = false, fail = false, end_options = false, stdin_used = false;
    unsigned seen = 0;
    ls_filter filter = {0};
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (!end_options && strcmp(arg, "--") == 0) {
            end_options = true;
            continue;
        }
        if (!end_options && arg[0] == '-' && arg[1]) {
            if (strcmp(arg, "--help") == 0) {
                usage(stdout);
                return 0;
            }
            if (strcmp(arg, "--version") == 0) {
                puts("LogScan " LS_VERSION);
                return 0;
            }
            unsigned bit = 0;
            if (strcmp(arg, "--json") == 0) {
                bit = 1;
                json = true;
            } else if (strcmp(arg, "--strict") == 0) {
                bit = 2;
                strict = true;
            } else if (strcmp(arg, "--fail-on-5xx") == 0) {
                bit = 4;
                fail = true;
            } else if (strcmp(arg, "--top") == 0) {
                bit = 8;
                if (++i == argc || !positive(argv[i], 100, &top))
                    goto bad_usage;
            } else if (strcmp(arg, "--max-paths") == 0) {
                bit = 16;
                if (++i == argc || !positive(argv[i], 100000, &capacity))
                    goto bad_usage;
            } else if (strcmp(arg, "--since") == 0) {
                bit = 32;
                filter.has_since = true;
                if (++i == argc || !ls_iso_time(argv[i], &filter.since))
                    goto bad_usage;
            } else if (strcmp(arg, "--until") == 0) {
                bit = 64;
                filter.has_until = true;
                if (++i == argc || !ls_iso_time(argv[i], &filter.until))
                    goto bad_usage;
            } else
                goto bad_usage;
            if (seen & bit)
                goto bad_usage;
            seen |= bit;
        } else {
            if (file_count == 64)
                goto bad_usage;
            if (strcmp(arg, "-") == 0) {
                if (stdin_used)
                    goto bad_usage;
                stdin_used = true;
            }
            files[file_count++] = arg;
        }
    }
    if (!file_count || (filter.has_since && filter.has_until && filter.since >= filter.until))
        goto bad_usage;
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif
#ifdef _WIN32
    if (stdin_used && _setmode(_fileno(stdin), _O_BINARY) == -1) {
        fputs("logscan: cannot set binary stdin\n", stderr);
        return 3;
    }
#endif
    ls_stats stats;
    if (!ls_init(&stats, capacity)) {
        fputs("logscan: memory allocation failed\n", stderr);
        return 3;
    }
    int result = 0;
    for (size_t i = 0; i < file_count; i++) {
        FILE *input = strcmp(files[i], "-") == 0 ? stdin : fopen(files[i], "rb");
        if (!input) {
            fprintf(stderr, "logscan: cannot open input %zu; no report produced\n", i + 1);
            result = 3;
            break;
        }
        result = scan(input, &stats, &filter, strict);
        if (input != stdin && fclose(input) != 0 && !result) {
            fputs("logscan: input close failed\n", stderr);
            result = 3;
        }
        if (result)
            break;
    }
    if (!result) {
        if (stats.invalid)
            fprintf(stderr,
                    "logscan: skipped %" PRIu64 " malformed lines (%" PRIu64 " overlong, %" PRIu64
                    " containing NUL)\n",
                    stats.invalid, stats.overlong, stats.binary);
        if (!ls_report(stdout, &stats, top, json)) {
            fputs("logscan: report allocation or output write failed\n", stderr);
            result = 3;
        } else if (fail && stats.server_errors)
            result = 1;
    }
    ls_free(&stats);
    return result;
bad_usage:
    fputs("logscan: invalid arguments; use --help\n", stderr);
    return 2;
}
