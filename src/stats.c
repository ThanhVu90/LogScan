#include "logscan.h"
#include <stdlib.h>
#include <string.h>

bool ls_init(ls_stats *stats, size_t capacity) {
    memset(stats, 0, sizeof(*stats));
    if (capacity < 1 || capacity > 100000)
        return false;
    stats->capacity = capacity;
    stats->slot_count = 1;
    while (stats->slot_count < capacity * 2)
        stats->slot_count *= 2;
    stats->routes = calloc(capacity, sizeof(*stats->routes));
    stats->slots = calloc(stats->slot_count, sizeof(*stats->slots));
    if (!stats->routes || !stats->slots) {
        ls_free(stats);
        return false;
    }
    return true;
}
void ls_free(ls_stats *stats) {
    if (stats->routes)
        for (size_t i = 0; i < stats->count; i++)
            free(stats->routes[i].path);
    free(stats->routes);
    free(stats->slots);
    memset(stats, 0, sizeof(*stats));
}
static uint64_t hash_path(const char *s) {
    uint64_t hash = UINT64_C(14695981039346656037);
    while (*s) {
        hash ^= (unsigned char)*s++;
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}
const char *ls_accept(ls_stats *stats, const ls_record *record, const ls_filter *filter) {
    if ((filter->has_since && record->timestamp < filter->since) ||
        (filter->has_until && record->timestamp >= filter->until)) {
        if (stats->filtered == UINT64_MAX)
            return "counter overflow";
        stats->filtered++;
        return NULL;
    }
    size_t slot = (size_t)(hash_path(record->path) & (stats->slot_count - 1));
    while (stats->slots[slot] &&
           strcmp(stats->routes[stats->slots[slot] - 1].path, record->path) != 0)
        slot = (slot + 1) & (stats->slot_count - 1);
    bool fresh = stats->slots[slot] == 0;
    if (fresh && stats->count == stats->capacity)
        return "distinct path limit reached; raise --max-paths or narrow the time range";
    if (stats->selected == UINT64_MAX || stats->bytes > UINT64_MAX - record->bytes)
        return "counter overflow";
    ls_route *route = fresh ? &stats->routes[stats->count] : &stats->routes[stats->slots[slot] - 1];
    if (fresh) {
        size_t length = strlen(record->path) + 1;
        route->path = malloc(length);
        if (!route->path)
            return "memory allocation failed";
        memcpy(route->path, record->path, length);
        stats->slots[slot] = ++stats->count;
    }
    /* Per-route/status counts cannot exceed the already checked total. */
    if (!stats->selected)
        stats->first = stats->last = record->timestamp;
    if (record->timestamp < stats->first)
        stats->first = record->timestamp;
    if (record->timestamp > stats->last)
        stats->last = record->timestamp;
    stats->selected++;
    stats->bytes += record->bytes;
    stats->status[record->status]++;
    stats->unknown_bytes += (uint64_t)record->unknown_bytes;
    stats->server_errors += (uint64_t)(record->status >= 500);
    route->count++;
    route->bytes += record->bytes;
    route->server_errors += (uint64_t)(record->status >= 500);
    return NULL;
}
