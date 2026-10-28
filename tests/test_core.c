#include "logscan.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks = 0;
#define CHECK(x)                                                                                   \
    do {                                                                                           \
        checks++;                                                                                  \
        if (!(x)) {                                                                                \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x);                           \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)
static bool parse(const char *s, ls_record *r) { return ls_parse(s, strlen(s), r); }
int main(void) {
    int64_t time;
    ls_record record;
    ls_filter filter = {0};
    ls_stats stats;
    CHECK(ls_iso_time("1970-01-01T00:00:00Z", &time) && time == 0);
    CHECK(ls_iso_time("2000-02-29T12:00:00Z", &time) && time == INT64_C(951825600));
    CHECK(!ls_iso_time("2100-02-29T00:00:00Z", &time));
    CHECK(!ls_iso_time("2026-04-31T00:00:00Z", &time));
    CHECK(!ls_iso_time("2026-01-01T24:00:00Z", &time));
    CHECK(!ls_iso_time("2026-01-01T00:00:60Z", &time));
    CHECK(!ls_iso_time("1969-12-31T00:00:00Z", &time));
    CHECK(
        parse("127.0.0.1 - - [01/Jan/1970:07:00:00 +0700] \"GET /index?q=secret HTTP/1.1\" 200 123",
              &record));
    CHECK(record.timestamp == 0 && strcmp(record.path, "/index") == 0 && record.bytes == 123);
    CHECK(parse(
        "::1 - user [01/Jan/1970:00:00:00 -0100] \"POST /api HTTP/2.0\" 503 - \"-\" \"browser\"",
        &record));
    CHECK(record.timestamp == 3600 && record.unknown_bytes && record.status == 503);
    CHECK(!parse("x - - [31/Feb/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 200 0", &record));
    CHECK(!parse("x - - [01/Jan/2026:00:00:00 +2460] \"GET / HTTP/1.1\" 200 0", &record));
    CHECK(!parse("x - - [01/Jan/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 600 0", &record));
    CHECK(!parse("x - - [01/Jan/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 200 18446744073709551616",
                 &record));
    CHECK(!parse("x - - [01/Jan/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 200 0 trailing", &record));
    CHECK(!ls_init(&stats, 0));
    CHECK(!ls_init(&stats, 100001));
    CHECK(ls_init(&stats, 2));
    record = (ls_record){.timestamp = 1, .status = 200, .bytes = 2};
    strcpy(record.path, "/a");
    CHECK(ls_accept(&stats, &record, &filter) == NULL);
    record.status = 500;
    CHECK(ls_accept(&stats, &record, &filter) == NULL);
    CHECK(stats.count == 1 && stats.selected == 2 && stats.server_errors == 1 && stats.bytes == 4);
    strcpy(record.path, "/b");
    CHECK(ls_accept(&stats, &record, &filter) == NULL);
    strcpy(record.path, "/c");
    CHECK(ls_accept(&stats, &record, &filter) != NULL && stats.selected == 3);
    FILE *temp = tmpfile();
    CHECK(temp != NULL);
    CHECK(ls_report(temp, &stats, 10, true));
    fclose(temp);
    strcpy(record.path, "/a");
    CHECK(ls_accept(&stats, &record, &filter) == NULL);
    CHECK(stats.selected == 4);
    stats.bytes = UINT64_MAX;
    record.bytes = 1;
    CHECK(ls_accept(&stats, &record, &filter) != NULL);
    CHECK(stats.selected == 4);
    ls_free(&stats);
    CHECK(stats.routes == NULL && stats.slots == NULL);
    CHECK(ls_init(&stats, 1));
    filter = (ls_filter){.has_since = true, .since = 10, .has_until = true, .until = 20};
    record.timestamp = 9;
    CHECK(ls_accept(&stats, &record, &filter) == NULL && stats.filtered == 1 && stats.count == 0);
    record.timestamp = 20;
    CHECK(ls_accept(&stats, &record, &filter) == NULL && stats.filtered == 2);
    record.timestamp = 10;
    CHECK(ls_accept(&stats, &record, &filter) == NULL && stats.selected == 1);
    stats.selected = UINT64_MAX;
    CHECK(ls_accept(&stats, &record, &filter) != NULL);
    ls_free(&stats);
    /* Deterministic random bytes + every truncation exercise parser boundaries. */
    uint32_t seed = UINT32_C(0x739abc12);
    char bytes[LS_LINE_LIMIT + 2];
    for (unsigned run = 0; run < 50000; run++) {
        seed = seed * UINT32_C(1664525) + UINT32_C(1013904223);
        size_t n = seed % 257;
        for (size_t i = 0; i < n; i++) {
            seed = seed * UINT32_C(1664525) + UINT32_C(1013904223);
            bytes[i] = (char)(seed >> 24);
        }
        bytes[n] = '\0';
        (void)ls_parse(bytes, n, &record);
    }
    const char *good =
        "x - - [10/Oct/2000:13:55:36 -0700] \"GET / HTTP/1.1\" 200 123 \"ref\" \"agent\"";
    for (size_t i = 0; i < strlen(good); i++) {
        memcpy(bytes, good, i);
        bytes[i] = '\0';
        (void)ls_parse(bytes, i, &record);
    }
    printf("%u core assertions passed; 50000 deterministic parser byte cases completed\n", checks);
    return 0;
}
