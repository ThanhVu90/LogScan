/* Optional libFuzzer entry point; build with Clang -fsanitize=fuzzer,address,undefined. */
#include "logscan.h"
#include <string.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > LS_LINE_LIMIT)
        return 0;
    char line[LS_LINE_LIMIT + 1];
    memcpy(line, data, size);
    line[size] = '\0';
    ls_record record;
    (void)ls_parse(line, size, &record);
    return 0;
}
