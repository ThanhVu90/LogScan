#include "logscan.h"
#include <limits.h>
#include <string.h>

int ls_read_line(FILE *input, char line[LS_LINE_LIMIT + 2], size_t *length, bool *overlong,
                 bool *binary) {
    size_t used = 0;
    int c;
    bool any = false;
    *overlong = false;
    *binary = false;
    while ((c = fgetc(input)) != EOF) {
        any = true;
        if (c == '\n')
            break;
        if (c == 0)
            *binary = true;
        if (used < LS_LINE_LIMIT + 1)
            line[used++] = (char)c;
        else
            *overlong = true;
    }
    if (ferror(input))
        return -1;
    if (!any)
        return 0;
    if (used && line[used - 1] == '\r')
        used--;
    if (used > LS_LINE_LIMIT)
        *overlong = true;
    line[used] = '\0';
    *length = used;
    return 1;
}
static bool digits(const char *s, size_t n, unsigned *out) {
    unsigned value = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return false;
        value = value * 10u + (unsigned)(s[i] - '0');
    }
    *out = value;
    return true;
}
static bool leap(unsigned y) { return y % 4u == 0 && (y % 100u != 0 || y % 400u == 0); }
static bool epoch(unsigned y, unsigned m, unsigned d, unsigned h, unsigned min, unsigned sec,
                  int offset, int64_t *out) {
    static const unsigned month_days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (y < 1970 || y > 9999 || m < 1 || m > 12 || d < 1 || h > 23 || min > 59 || sec > 59)
        return false;
    if (d > month_days[m - 1] + (unsigned)(m == 2 && leap(y)))
        return false;
    int64_t prior = (int64_t)y - 1;
    int64_t days = 365 * ((int64_t)y - 1970) + (prior / 4 - 1969 / 4) - (prior / 100 - 1969 / 100) +
                   (prior / 400 - 1969 / 400);
    for (unsigned i = 1; i < m; i++)
        days += month_days[i - 1] + (unsigned)(i == 2 && leap(y));
    days += (int64_t)d - 1;
    *out = days * 86400 + (int64_t)h * 3600 + (int64_t)min * 60 + sec - (int64_t)offset * 60;
    return true;
}
bool ls_iso_time(const char *s, int64_t *out) {
    unsigned y, m, d, h, min, sec;
    if (strlen(s) != 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
        s[16] != ':' || s[19] != 'Z')
        return false;
    return digits(s, 4, &y) && digits(s + 5, 2, &m) && digits(s + 8, 2, &d) &&
           digits(s + 11, 2, &h) && digits(s + 14, 2, &min) && digits(s + 17, 2, &sec) &&
           epoch(y, m, d, h, min, sec, 0, out);
}
static bool log_time(const char *s, size_t n, int64_t *out) {
    static const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    unsigned y, m = 0, d, h, min, sec, oh, om;
    if (n != 26 || s[2] != '/' || s[6] != '/' || s[11] != ':' || s[14] != ':' || s[17] != ':' ||
        s[20] != ' ' || (s[21] != '+' && s[21] != '-'))
        return false;
    for (unsigned i = 0; i < 12; i++)
        if (memcmp(s + 3, months[i], 3) == 0)
            m = i + 1;
    if (!digits(s, 2, &d) || !digits(s + 7, 4, &y) || !digits(s + 12, 2, &h) ||
        !digits(s + 15, 2, &min) || !digits(s + 18, 2, &sec) || !digits(s + 22, 2, &oh) ||
        !digits(s + 24, 2, &om) || oh > 23 || om > 59)
        return false;
    int offset = (int)(oh * 60 + om);
    if (s[21] == '-')
        offset = -offset;
    return epoch(y, m, d, h, min, sec, offset, out);
}
static bool space(char c) { return c == ' ' || c == '\t'; }
static void skip(const char **p) {
    while (space(**p))
        (*p)++;
}
static bool token(const char **p, const char **start, size_t *length) {
    skip(p);
    *start = *p;
    while (**p && !space(**p))
        (*p)++;
    *length = (size_t)(*p - *start);
    return *length > 0;
}
static bool quoted(const char **p, const char **start, size_t *length) {
    skip(p);
    if (**p != '"')
        return false;
    (*p)++;
    *start = *p;
    while (**p && **p != '"') {
        if (**p == '\\') {
            (*p)++;
            if (!**p)
                return false;
        }
        (*p)++;
    }
    if (**p != '"')
        return false;
    *length = (size_t)(*p - *start);
    (*p)++;
    return true;
}
static bool number(const char *s, size_t n, uint64_t *value) {
    if (!n)
        return false;
    *value = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return false;
        unsigned digit = (unsigned)(s[i] - '0');
        if (*value > (UINT64_MAX - digit) / 10)
            return false;
        *value = *value * 10 + digit;
    }
    return true;
}
bool ls_parse(const char *line, size_t length, ls_record *record) {
    /* Contract: caller supplies a terminated buffer of exactly length bytes. */
    if (length > LS_LINE_LIMIT || strlen(line) != length)
        return false;
    for (size_t i = 0; i < length; i++)
        if (((unsigned char)line[i] < 32 && line[i] != '\t') || (unsigned char)line[i] == 127)
            return false;
    const char *p = line, *s;
    size_t n;
    for (int i = 0; i < 3; i++)
        if (!token(&p, &s, &n) || n > 255)
            return false;
    skip(&p);
    if (*p != '[')
        return false;
    s = ++p;
    while (*p && *p != ']')
        p++;
    if (*p != ']' || !log_time(s, (size_t)(p - s), &record->timestamp))
        return false;
    p++;
    if (!space(*p))
        return false;
    if (!quoted(&p, &s, &n))
        return false;
    if (n == 1 && s[0] == '-')
        strcpy(record->path, "-");
    else {
        const char *end = s + n, *method = s;
        while (s < end && !space(*s))
            s++;
        if (s == method || s - method > 32)
            return false;
        while (s < end && space(*s))
            s++;
        const char *target = s;
        while (s < end && !space(*s))
            s++;
        size_t target_len = (size_t)(s - target);
        if (!target_len || target_len > LS_PATH_LIMIT)
            return false;
        while (s < end && space(*s))
            s++;
        size_t protocol = (size_t)(end - s);
        if (!((protocol == 8 && (memcmp(s, "HTTP/1.0", 8) == 0 || memcmp(s, "HTTP/1.1", 8) == 0)) ||
              (protocol == 8 && memcmp(s, "HTTP/2.0", 8) == 0) ||
              (protocol == 8 && memcmp(s, "HTTP/3.0", 8) == 0)))
            return false;
        size_t kept = 0;
        while (kept < target_len && target[kept] != '?' && target[kept] != '#')
            kept++;
        if (!kept)
            return false;
        memcpy(record->path, target, kept);
        record->path[kept] = '\0';
    }
    if (!space(*p) || !token(&p, &s, &n) || n != 3)
        return false;
    uint64_t status;
    if (!number(s, n, &status) || status < 100 || status > 599)
        return false;
    record->status = (unsigned)status;
    if (!token(&p, &s, &n))
        return false;
    record->unknown_bytes = n == 1 && s[0] == '-';
    record->bytes = 0;
    if (!record->unknown_bytes && !number(s, n, &record->bytes))
        return false;
    skip(&p);
    if (*p) {
        if (!quoted(&p, &s, &n) || !space(*p) || !quoted(&p, &s, &n))
            return false;
        skip(&p);
        if (*p)
            return false;
    }
    return true;
}
