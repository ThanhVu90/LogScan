#ifndef LOGSCAN_H
#define LOGSCAN_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#define LS_LINE_LIMIT 8192
#define LS_PATH_LIMIT 2048
#define LS_VERSION "1.0.0"
typedef struct {
    int64_t timestamp;
    unsigned status;
    uint64_t bytes;
    bool unknown_bytes;
    char path[LS_PATH_LIMIT + 1];
} ls_record;
typedef struct {
    char *path;
    uint64_t count, server_errors, bytes;
} ls_route;
typedef struct {
    uint64_t lines, valid, invalid, overlong, binary, filtered, selected;
    uint64_t bytes, unknown_bytes, server_errors, status[600];
    int64_t first, last;
    size_t count, capacity, slot_count;
    ls_route *routes;
    size_t *slots;
} ls_stats;
typedef struct {
    bool has_since, has_until;
    int64_t since, until;
} ls_filter;
/* Reader result: 1 line, 0 EOF, -1 I/O. Overlong input is fully drained. */
int ls_read_line(FILE *input, char line[LS_LINE_LIMIT + 2], size_t *length, bool *overlong,
                 bool *binary);
bool ls_parse(const char *line, size_t length, ls_record *record);
bool ls_iso_time(const char *text, int64_t *result);
bool ls_init(ls_stats *stats, size_t capacity);
void ls_free(ls_stats *stats);
/* Returns NULL on success, otherwise a fixed diagnostic. */
const char *ls_accept(ls_stats *stats, const ls_record *record, const ls_filter *filter);
bool ls_report(FILE *output, ls_stats *stats, size_t top, bool json);
#endif
