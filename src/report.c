#include "logscan.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

static int compare(const void *left, const void *right) {
    const ls_route *a = *(const ls_route *const *)left, *b = *(const ls_route *const *)right;
    if (a->count != b->count)
        return a->count > b->count ? -1 : 1;
    return strcmp(a->path, b->path);
}
static void quoted(FILE *out, const char *s) {
    fputc('"', out);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            fputc('\\', out);
            fputc(c, out);
        } else if (c < 32 || c >= 127)
            fprintf(out, "\\u%04x", (unsigned)c);
        else
            fputc(c, out);
    }
    fputc('"', out);
}
static void safe_text(FILE *out, const char *s) {
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c < 32 || c >= 127)
            fprintf(out, "\\x%02x", (unsigned)c);
        else
            fputc(c, out);
    }
}
bool ls_report(FILE *out, ls_stats *stats, size_t top, bool json) {
    ls_route **rank = NULL;
    if (stats->count) {
        rank = malloc(stats->count * sizeof(*rank));
        if (!rank)
            return false;
        for (size_t i = 0; i < stats->count; i++)
            rank[i] = &stats->routes[i];
        qsort(rank, stats->count, sizeof(*rank), compare);
    }
    size_t shown = top < stats->count ? top : stats->count;
    if (json) {
        fprintf(out,
                "{\n  \"schema_version\": 1,\n  \"lines\": %" PRIu64 ",\n  \"valid\": %" PRIu64
                ",\n  \"invalid\": %" PRIu64 ",\n  \"overlong\": %" PRIu64
                ",\n  \"binary\": %" PRIu64 ",\n  \"filtered\": %" PRIu64
                ",\n  \"requests\": %" PRIu64 ",\n  \"bytes\": %" PRIu64
                ",\n  \"unknown_size_requests\": %" PRIu64 ",\n  \"server_errors\": %" PRIu64
                ",\n  \"distinct_paths\": %zu,\n",
                stats->lines, stats->valid, stats->invalid, stats->overlong, stats->binary,
                stats->filtered, stats->selected, stats->bytes, stats->unknown_bytes,
                stats->server_errors, stats->count);
        if (stats->selected)
            fprintf(out, "  \"first_unix\": %" PRId64 ",\n  \"last_unix\": %" PRId64 ",\n",
                    stats->first, stats->last);
        else
            fputs("  \"first_unix\": null,\n  \"last_unix\": null,\n", out);
        fputs("  \"statuses\": {", out);
        bool comma = false;
        for (unsigned i = 100; i < 600; i++)
            if (stats->status[i]) {
                fprintf(out, "%s\"%u\": %" PRIu64, comma ? ", " : "", i, stats->status[i]);
                comma = true;
            }
        fputs("},\n  \"top_paths\": [", out);
        for (size_t i = 0; i < shown; i++) {
            const ls_route *p = rank[i];
            fputs(i ? ",\n    {\"path\": " : "\n    {\"path\": ", out);
            quoted(out, p->path);
            fprintf(out,
                    ", \"requests\": %" PRIu64 ", \"server_errors\": %" PRIu64
                    ", \"bytes\": %" PRIu64 "}",
                    p->count, p->server_errors, p->bytes);
        }
        fputs(shown ? "\n  ]\n}\n" : "]\n}\n", out);
    } else {
        fprintf(out,
                "LogScan %s | access-log summary\n\nScanned lines    %" PRIu64
                "\nValid / invalid  %" PRIu64 " / %" PRIu64 "\nFiltered out     %" PRIu64
                "\nRequests         %" PRIu64 "\nKnown bytes      %" PRIu64
                "\nUnknown sizes    %" PRIu64 "\nHTTP 5xx         %" PRIu64
                "\nDistinct paths   %zu\n\n%-10s %-10s %-12s %s\n",
                LS_VERSION, stats->lines, stats->valid, stats->invalid, stats->filtered,
                stats->selected, stats->bytes, stats->unknown_bytes, stats->server_errors,
                stats->count, "REQUESTS", "5XX", "BYTES", "PATH (query removed)");
        for (size_t i = 0; i < shown; i++) {
            fprintf(out, "%-10" PRIu64 " %-10" PRIu64 " %-12" PRIu64 " ", rank[i]->count,
                    rank[i]->server_errors, rank[i]->bytes);
            safe_text(out, rank[i]->path);
            fputc('\n', out);
        }
    }
    free(rank);
    return fflush(out) == 0 && !ferror(out);
}
