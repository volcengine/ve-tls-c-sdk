#include "producer/ve_tls_checkpoint.h"
#include "ve_tls_alloc.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return -1; \
    } \
} while (0)

typedef struct {
    uint32_t magic;
    uint32_t version;
    int64_t acked_log_id;
    int64_t replay_begin_log_id;
    uint32_t replay_begin_segment_id;
    uint32_t reserved;
    uint64_t replay_begin_offset;
    uint32_t last_segment_id;
    uint32_t checksum;
} legacy_file;

static ve_tls_platform real_platform;
static ve_tls_platform fault_platform;
static char test_dir[PATH_MAX];
static char checkpoint_path[PATH_MAX];
static ve_tls_file * writable_file;
static ve_tls_file * directory_file;
static int fault;
static int fault_step;
static int read_calls;

enum {
    FAULT_NONE,
    FAULT_WRITE,
    FAULT_SHORT_WRITE,
    FAULT_SHORT_SUCCESS,
    FAULT_FILE_FSYNC,
    FAULT_RENAME,
    FAULT_DIR_OPEN,
    FAULT_DIR_FSYNC,
    FAULT_READ_FIRST,
    FAULT_READ_EXTENSION,
    FAULT_SEEK
};

static ve_tls_file * hooked_open(const char * path, int flags, int mode) {
    if (fault == FAULT_DIR_OPEN && strcmp(path, test_dir) == 0 && flags == VE_TLS_FILE_OPEN_RDONLY) {
        return NULL;
    }
    ve_tls_file * file = real_platform.file_open(path, flags, mode);
    if (file && (flags & (VE_TLS_FILE_OPEN_WRONLY | VE_TLS_FILE_OPEN_RDWR))) writable_file = file;
    if (file && strcmp(path, test_dir) == 0 && flags == VE_TLS_FILE_OPEN_RDONLY) directory_file = file;
    return file;
}

static void hooked_close(ve_tls_file * file) {
    if (file == writable_file) writable_file = NULL;
    if (file == directory_file) directory_file = NULL;
    real_platform.file_close(file);
}

static int64_t hooked_write(ve_tls_file * file, const void * buf, size_t size) {
    if (file == writable_file && fault == FAULT_WRITE) return -1;
    if (file == writable_file && fault == FAULT_SHORT_WRITE) {
        if (fault_step++ == 0) return real_platform.file_write(file, buf, size > 1 ? size / 2 : size);
        return -1;
    }
    if (file == writable_file && fault == FAULT_SHORT_SUCCESS && size > 1) {
        return real_platform.file_write(file, buf, size / 2);
    }
    return real_platform.file_write(file, buf, size);
}

static int64_t hooked_read(ve_tls_file * file, void * buf, size_t size) {
    read_calls++;
    if ((fault == FAULT_READ_FIRST && read_calls == 1) ||
        (fault == FAULT_READ_EXTENSION && read_calls == 2)) return -1;
    return real_platform.file_read(file, buf, size);
}

static int64_t hooked_seek(ve_tls_file * file, int64_t offset, int whence) {
    if (fault == FAULT_SEEK) return -1;
    return real_platform.file_seek(file, offset, whence);
}

static int hooked_fsync(ve_tls_file * file) {
    if ((fault == FAULT_FILE_FSYNC && file == writable_file) ||
        (fault == FAULT_DIR_FSYNC && file == directory_file)) return -1;
    return real_platform.file_fsync(file);
}

static int hooked_rename(const char * from, const char * to) {
    if (fault == FAULT_RENAME) return -1;
    return real_platform.path_rename(from, to);
}

static void use_fault(int value) {
    fault = value;
    fault_step = 0;
    read_calls = 0;
    writable_file = NULL;
    directory_file = NULL;
}

static uint32_t fnv1a(const unsigned char * data, size_t size) {
    uint32_t value = 2166136261u;
    for (size_t i = 0; i < size; i++) value = (value ^ data[i]) * 16777619u;
    return value;
}

static int same_state(const ve_tls_checkpoint_state * a, const ve_tls_checkpoint_state * b) {
    return a->acked_log_id == b->acked_log_id &&
        a->replay_begin_log_id == b->replay_begin_log_id &&
        a->replay_begin_segment_id == b->replay_begin_segment_id &&
        a->replay_begin_offset == b->replay_begin_offset &&
        a->last_segment_id == b->last_segment_id;
}

static ve_tls_checkpoint_state sample_state(int64_t ack) {
    ve_tls_checkpoint_state state;
    memset(&state, 0, sizeof(state));
    state.acked_log_id = ack;
    state.replay_begin_log_id = 35;
    state.replay_begin_segment_id = 4;
    state.replay_begin_offset = 218;
    state.last_segment_id = 8;
    return state;
}

static int write_bytes(const unsigned char * data, size_t size) {
    FILE * f = fopen(checkpoint_path, "wb");
    CHECK(f != NULL);
    int ok = fwrite(data, 1, size, f) == size;
    CHECK(fclose(f) == 0 && ok);
    return 0;
}

static int read_bytes(unsigned char * data, size_t capacity, size_t * size) {
    FILE * f = fopen(checkpoint_path, "rb");
    CHECK(f != NULL);
    *size = fread(data, 1, capacity, f);
    CHECK(!ferror(f) && feof(f));
    CHECK(fclose(f) == 0);
    return 0;
}

static int write_legacy(const ve_tls_checkpoint_state * state, unsigned char * bytes) {
    legacy_file file;
    CHECK(sizeof(file) == 48 && offsetof(legacy_file, checksum) == 44);
    memset(&file, 0, sizeof(file));
    file.magic = 0x54435031u;
    file.version = 1;
    file.acked_log_id = state->acked_log_id;
    file.replay_begin_log_id = state->replay_begin_log_id;
    file.replay_begin_segment_id = state->replay_begin_segment_id;
    file.replay_begin_offset = state->replay_begin_offset;
    file.last_segment_id = state->last_segment_id;
    file.checksum = fnv1a((const unsigned char *)&file, offsetof(legacy_file, checksum));
    memcpy(bytes, &file, sizeof(file));
    return write_bytes(bytes, sizeof(file));
}

/* This runs unchanged against the baseline implementation: the assertion must
 * fail there because opening checkpoint with TRUNC destroys the old state. */
static int test_failed_write_preserves_old_checkpoint(void) {
    ve_tls_checkpoint_state before = sample_state(3), after, update = sample_state(4);
    unsigned char fixture[sizeof(legacy_file)];
    CHECK(write_legacy(&before, fixture) == 0);
    use_fault(FAULT_WRITE);
    int rc = ve_tls_checkpoint_save(&fault_platform, checkpoint_path, &update);
    use_fault(FAULT_NONE);
    CHECK(rc != 0);
    CHECK(ve_tls_checkpoint_load(&real_platform, checkpoint_path, &after) == 0);
    CHECK(same_state(&before, &after));
    return 0;
}

#ifndef VE_TLS_CHECKPOINT_BASELINE

#define EXT_HEADER_SIZE 20u
#define EXT_COUNT_OFFSET (sizeof(legacy_file) + 8u)
#define EXT_CRC_OFFSET (sizeof(legacy_file) + 16u)
#define EXT_RECORD_OFFSET (sizeof(legacy_file) + EXT_HEADER_SIZE)
#define EXT_RECORD_SIZE 16u

static void put_u32_le(unsigned char * data, uint32_t value) {
    for (unsigned i = 0; i < 4; i++) data[i] = (unsigned char)(value >> (8u * i));
}

static void put_u64_le(unsigned char * data, uint64_t value) {
    for (unsigned i = 0; i < 8; i++) data[i] = (unsigned char)(value >> (8u * i));
}

static uint32_t crc_update(uint32_t crc, const unsigned char * data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)-(int32_t)(crc & 1u));
    }
    return crc;
}

/* CRC covers the V1 prefix and extension fields/records, excluding the CRC. */
static void update_extension_crc(unsigned char * data, size_t size) {
    uint32_t crc = crc_update(0xFFFFFFFFu, data, EXT_CRC_OFFSET);
    crc = crc_update(crc, data + EXT_CRC_OFFSET + 4, size - EXT_CRC_OFFSET - 4);
    put_u32_le(data + EXT_CRC_OFFSET, crc ^ 0xFFFFFFFFu);
}

static int same_ranges(const ve_tls_checkpoint_range * a, const ve_tls_checkpoint_range * b, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (a[i].start_id != b[i].start_id || a[i].end_id != b[i].end_id) return 0;
    }
    return 1;
}

static int assert_loaded(const ve_tls_checkpoint_state * expected,
    const ve_tls_checkpoint_range * expected_ranges, size_t expected_count) {
    ve_tls_checkpoint_state actual;
    ve_tls_checkpoint_range * ranges = NULL;
    size_t count = 0;
    int rc = ve_tls_checkpoint_load_ranges(&real_platform, checkpoint_path, &actual, &ranges, &count);
    int good = rc == VE_TLS_CHECKPOINT_LOAD_OK && same_state(&actual, expected) &&
        count == expected_count && (!count || (ranges && same_ranges(ranges, expected_ranges, count)));
    ve_tls_free(ranges);
    CHECK(good);
    return 0;
}

static int test_legacy_and_ranges_roundtrip(void) {
    ve_tls_checkpoint_state state = sample_state(10), loaded;
    ve_tls_checkpoint_range wanted[] = {{12, 13}, {16, 18}, {21, INT64_MAX}};
    static const unsigned char expected_extension[] = {
        0x41, 0x43, 0x4b, 0x32, 0x01, 0, 0, 0, 0x03, 0, 0, 0, 0, 0, 0, 0,
        0x10, 0x69, 0x5f, 0x56,
        0x0c, 0, 0, 0, 0, 0, 0, 0, 0x0d, 0, 0, 0, 0, 0, 0, 0,
        0x10, 0, 0, 0, 0, 0, 0, 0, 0x12, 0, 0, 0, 0, 0, 0, 0,
        0x15, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
    };
    unsigned char legacy[sizeof(legacy_file)], saved[512];
    size_t size = 0;
    CHECK(write_legacy(&state, legacy) == 0);
    CHECK(ve_tls_checkpoint_load(&real_platform, checkpoint_path, &loaded) == 0 && same_state(&state, &loaded));
    CHECK(assert_loaded(&state, NULL, 0) == 0);
    CHECK(ve_tls_checkpoint_save_ranges(&real_platform, checkpoint_path, &state, wanted, 3) == 0);
    CHECK(read_bytes(saved, sizeof(saved), &size) == 0);
    CHECK(size == sizeof(legacy_file) + EXT_HEADER_SIZE + 3 * EXT_RECORD_SIZE);
    CHECK(memcmp(saved, legacy, sizeof(legacy)) == 0);
    CHECK(memcmp(saved + sizeof(legacy), expected_extension, sizeof(expected_extension)) == 0);
    CHECK(ve_tls_checkpoint_load(&real_platform, checkpoint_path, &loaded) == 0 && same_state(&state, &loaded));
    CHECK(assert_loaded(&state, wanted, 3) == 0);
    CHECK(ve_tls_checkpoint_save(&real_platform, checkpoint_path, &state) == 0);
    CHECK(read_bytes(saved, sizeof(saved), &size) == 0 && size == sizeof(legacy));
    CHECK(memcmp(saved, legacy, sizeof(legacy)) == 0);
    CHECK(assert_loaded(&state, NULL, 0) == 0);
    return 0;
}

static int test_save_rejects_invalid_ranges(void) {
    ve_tls_checkpoint_state state = sample_state(10), loaded;
    const ve_tls_checkpoint_range valid[] = {{12, 13}, {16, 18}};
    const ve_tls_checkpoint_range invalid[][2] = {
        {{11, 11}, {16, 18}}, /* Adjacent to prefix; would cross a hole. */
        {{10, 11}, {16, 18}},
        {{13, 12}, {16, 18}},
        {{12, 14}, {14, 18}}, /* Overlap. */
        {{12, 14}, {15, 18}}, /* Adjacent; canonical ranges must be merged. */
        {{16, 18}, {12, 13}}, /* Unsorted. */
        {{12, INT64_MAX}, {16, 18}},
    };
    CHECK(ve_tls_checkpoint_save_ranges(&real_platform, checkpoint_path, &state, valid, 2) == 0);
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        CHECK(ve_tls_checkpoint_save_ranges(&real_platform, checkpoint_path, &state, invalid[i], 2) != 0);
        CHECK(assert_loaded(&state, valid, 2) == 0);
    }
    CHECK(ve_tls_checkpoint_save_ranges(&real_platform, checkpoint_path, &state, NULL, 1) != 0);
    CHECK(ve_tls_checkpoint_save_ranges(&real_platform, checkpoint_path, &state, valid,
        SIZE_MAX / sizeof(ve_tls_checkpoint_range) + 1) != 0);
    state.acked_log_id = INT64_MAX;
    CHECK(ve_tls_checkpoint_save_ranges(&real_platform, checkpoint_path, &state, valid, 1) != 0);
    CHECK(ve_tls_checkpoint_load(&real_platform, checkpoint_path, &loaded) == 0 && loaded.acked_log_id == 10);
    return 0;
}

static int expect_extension_invalid(const unsigned char * data, size_t size,
    const ve_tls_checkpoint_state * expected_prefix) {
    ve_tls_checkpoint_state state;
    ve_tls_checkpoint_range * ranges = (ve_tls_checkpoint_range *)(uintptr_t)1;
    size_t count = 99;
    CHECK(write_bytes(data, size) == 0);
    CHECK(ve_tls_checkpoint_load_ranges(&real_platform, checkpoint_path, &state, &ranges, &count) ==
        VE_TLS_CHECKPOINT_LOAD_EXT_INVALID);
    CHECK(same_state(&state, expected_prefix) && ranges == NULL && count == 0);
    return 0;
}

static int test_bad_extensions_preserve_prefix(void) {
    ve_tls_checkpoint_state state = sample_state(10), changed;
    const ve_tls_checkpoint_range valid[] = {{12, 13}, {16, 18}};
    unsigned char good[512], bad[512]; size_t size = 0;
    CHECK(ve_tls_checkpoint_save_ranges(&real_platform, checkpoint_path, &state, valid, 2) == 0);
    CHECK(read_bytes(good, sizeof(good), &size) == 0);
    CHECK(size == sizeof(legacy_file) + EXT_HEADER_SIZE + 2 * EXT_RECORD_SIZE);
    CHECK(expect_extension_invalid(good, sizeof(legacy_file) + 1, &state) == 0);
    CHECK(expect_extension_invalid(good, size - 1, &state) == 0);
    memcpy(bad, good, size); bad[sizeof(legacy_file)] ^= 0x40;
    CHECK(expect_extension_invalid(bad, size, &state) == 0);
    memcpy(bad, good, size); put_u32_le(bad + sizeof(legacy_file) + 4, UINT32_MAX);
    CHECK(expect_extension_invalid(bad, size, &state) == 0);
    memcpy(bad, good, size); bad[EXT_CRC_OFFSET] ^= 0x01;
    CHECK(expect_extension_invalid(bad, size, &state) == 0);
    memcpy(bad, good, size); put_u64_le(bad + EXT_COUNT_OFFSET, UINT64_MAX);
    CHECK(expect_extension_invalid(bad, size, &state) == 0);
    memcpy(bad, good, size); bad[size] = 0x11;
    CHECK(expect_extension_invalid(bad, size + 1, &state) == 0);
    for (int kind = 0; kind < 6; kind++) {
        memcpy(bad, good, size);
        switch (kind) {
            case 0: put_u64_le(bad + EXT_RECORD_OFFSET, 11); break; /* starts at ack+1 */
            case 1: put_u64_le(bad + EXT_RECORD_OFFSET, 14); break; /* end < start */
            case 2: put_u64_le(bad + EXT_RECORD_OFFSET + EXT_RECORD_SIZE, 13); break; /* overlap */
            case 3: put_u64_le(bad + EXT_RECORD_OFFSET + EXT_RECORD_SIZE, 14); break; /* adjacent */
            case 4: put_u64_le(bad + EXT_RECORD_OFFSET + EXT_RECORD_SIZE, 10); break; /* unsorted */
            case 5: put_u64_le(bad + EXT_RECORD_OFFSET, UINT64_MAX); break; /* not int64 */
        }
        update_extension_crc(bad, size);
        CHECK(expect_extension_invalid(bad, size, &state) == 0);
    }
    memcpy(bad, good, size);
    legacy_file prefix;
    memcpy(&prefix, bad, sizeof(prefix));
    prefix.last_segment_id++;
    prefix.checksum = fnv1a((const unsigned char *)&prefix, offsetof(legacy_file, checksum));
    memcpy(bad, &prefix, sizeof(prefix));
    changed = state; changed.last_segment_id++;
    CHECK(expect_extension_invalid(bad, size, &changed) == 0); /* CRC binds V1. */
    return 0;
}

static void * failing_malloc(size_t size, void * user) { (void)size; (void)user; return NULL; }

static int test_load_errors_and_oom(void) {
    ve_tls_checkpoint_state state = sample_state(10), actual;
    const ve_tls_checkpoint_range valid[] = {{12, 13}, {16, 18}};
    unsigned char before[512], after[512]; size_t before_size = 0, after_size = 0;
    ve_tls_checkpoint_range * ranges = NULL; size_t count = 0;
    CHECK(ve_tls_checkpoint_save_ranges(&real_platform, checkpoint_path, &state, valid, 2) == 0);
    CHECK(read_bytes(before, sizeof(before), &before_size) == 0);
    ve_tls_alloc_hooks saved, failing;
    ve_tls_alloc_get_hooks(&saved); failing = saved; failing.malloc_fn = failing_malloc;
    ve_tls_alloc_set_hooks(&failing);
    int rc = ve_tls_checkpoint_load_ranges(&real_platform, checkpoint_path, &actual, &ranges, &count);
    ve_tls_alloc_set_hooks(&saved);
    CHECK(rc == VE_TLS_CHECKPOINT_LOAD_OOM && ranges == NULL && count == 0);
    CHECK(read_bytes(after, sizeof(after), &after_size) == 0 && before_size == after_size && memcmp(before, after, before_size) == 0);
    CHECK(assert_loaded(&state, valid, 2) == 0);
    ve_tls_alloc_set_hooks(&failing);
    rc = ve_tls_checkpoint_save_ranges(&real_platform, checkpoint_path, &state, NULL, 0);
    if (rc == 0) rc = ve_tls_checkpoint_load_ranges(&real_platform, checkpoint_path, &actual, &ranges, &count);
    ve_tls_alloc_set_hooks(&saved);
    CHECK(rc == VE_TLS_CHECKPOINT_LOAD_OK && ranges == NULL && count == 0 && same_state(&state, &actual));
    CHECK(write_bytes(before, before_size) == 0);
    use_fault(FAULT_READ_FIRST);
    rc = ve_tls_checkpoint_load_ranges(&fault_platform, checkpoint_path, &actual, &ranges, &count);
    use_fault(FAULT_NONE);
    CHECK(rc == VE_TLS_CHECKPOINT_LOAD_ERROR);
    use_fault(FAULT_READ_EXTENSION);
    rc = ve_tls_checkpoint_load_ranges(&fault_platform, checkpoint_path, &actual, &ranges, &count);
    use_fault(FAULT_NONE);
    CHECK(rc == VE_TLS_CHECKPOINT_LOAD_ERROR);
    use_fault(FAULT_SEEK);
    rc = ve_tls_checkpoint_load_ranges(&fault_platform, checkpoint_path, &actual, &ranges, &count);
    use_fault(FAULT_NONE);
    CHECK(rc == VE_TLS_CHECKPOINT_LOAD_ERROR);
    before[0] ^= 0x01;
    CHECK(write_bytes(before, before_size) == 0);
    CHECK(ve_tls_checkpoint_load_ranges(&real_platform, checkpoint_path, &actual, &ranges, &count) == VE_TLS_CHECKPOINT_LOAD_ERROR);
    CHECK(write_bytes(before, sizeof(legacy_file) - 1) == 0);
    CHECK(ve_tls_checkpoint_load_ranges(&real_platform, checkpoint_path, &actual, &ranges, &count) == VE_TLS_CHECKPOINT_LOAD_ERROR);
    return 0;
}

static int test_atomic_write_failures(void) {
    ve_tls_checkpoint_state old = sample_state(3), newer = sample_state(4), actual;
    const ve_tls_checkpoint_range old_ranges[] = {{5, 6}, {9, 10}};
    const ve_tls_checkpoint_range new_ranges[] = {{6, 6}, {9, 10}};
    int cases[] = {FAULT_WRITE, FAULT_SHORT_WRITE, FAULT_FILE_FSYNC, FAULT_RENAME, FAULT_DIR_OPEN, FAULT_DIR_FSYNC};
    use_fault(FAULT_SHORT_SUCCESS);
    int short_rc = ve_tls_checkpoint_save_ranges(&fault_platform, checkpoint_path, &old, old_ranges, 2);
    use_fault(FAULT_NONE);
    CHECK(short_rc == 0 && assert_loaded(&old, old_ranges, 2) == 0);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        CHECK(ve_tls_checkpoint_save_ranges(&real_platform, checkpoint_path, &old, old_ranges, 2) == 0);
        use_fault(cases[i]);
        int rc = ve_tls_checkpoint_save_ranges(&fault_platform, checkpoint_path, &newer, new_ranges, 2);
        use_fault(FAULT_NONE);
        CHECK(rc != 0);
        if (cases[i] == FAULT_DIR_FSYNC) {
            /* Rename has happened: either complete version is safe to read. */
            CHECK(ve_tls_checkpoint_load(&real_platform, checkpoint_path, &actual) == 0);
            if (same_state(&actual, &newer)) CHECK(assert_loaded(&newer, new_ranges, 2) == 0);
            else CHECK(assert_loaded(&old, old_ranges, 2) == 0);
        } else {
            CHECK(assert_loaded(&old, old_ranges, 2) == 0);
        }
    }
    return 0;
}
#endif

int main(void) {
    char temp[] = "/tmp/ve-tls-checkpoint-ranges-XXXXXX";
    if (!mkdtemp(temp)) return 2;
    snprintf(test_dir, sizeof(test_dir), "%s", temp);
    snprintf(checkpoint_path, sizeof(checkpoint_path), "%s/checkpoint", test_dir);
    ve_tls_platform_init_default(&real_platform);
    fault_platform = real_platform;
    fault_platform.file_open = hooked_open;
    fault_platform.file_close = hooked_close;
    fault_platform.file_write = hooked_write;
    fault_platform.file_read = hooked_read;
    fault_platform.file_seek = hooked_seek;
    fault_platform.file_fsync = hooked_fsync;
    fault_platform.path_rename = hooked_rename;
    use_fault(FAULT_NONE);
    struct { const char *name; int (*run)(void); } tests[] = {
        {"failed_write_preserves_old_checkpoint", test_failed_write_preserves_old_checkpoint},
#ifndef VE_TLS_CHECKPOINT_BASELINE
        {"legacy_and_ranges_roundtrip", test_legacy_and_ranges_roundtrip},
        {"save_rejects_invalid_ranges", test_save_rejects_invalid_ranges},
        {"bad_extensions_preserve_prefix", test_bad_extensions_preserve_prefix},
        {"load_errors_and_oom", test_load_errors_and_oom},
        {"atomic_write_failures", test_atomic_write_failures},
#endif
    };
    int failed = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        int rc = tests[i].run();
        printf("%s %s\n", rc == 0 ? "PASS" : "FAIL", tests[i].name);
        if (rc != 0) { failed = 1; break; }
    }
    char temp_path[PATH_MAX];
    snprintf(temp_path, sizeof(temp_path), "%s/checkpoint.tmp", test_dir);
    (void)unlink(temp_path);
    (void)unlink(checkpoint_path);
    (void)rmdir(test_dir);
    return failed;
}
