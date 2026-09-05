/* Persistent reader bounds and lease callback regressions. */

typedef struct {
    int calls;
    int result;
    char path[256];
} persistent_reader_remove_state;

static persistent_reader_remove_state * g_persistent_reader_remove_state;

static int persistent_reader_path_remove(const char * path) {
    persistent_reader_remove_state * state = g_persistent_reader_remove_state;
    if (state) {
        state->calls++;
        if (path) {
            snprintf(state->path, sizeof(state->path), "%s", path);
        }
        return state->result;
    }
    return -1;
}

static int test_persistent_reader_lease_release_contract(void) {
    ve_tls_config config;
    ve_tls_platform platform;
    persistent_reader_remove_state state;

    memset(&state, 0, sizeof(state));
    ve_tls_config_init(&config);
    if (ve_tls_lease_release(NULL, "lease") == 0 ||
        ve_tls_lease_release(&config.platform, NULL) == 0) {
        return -1;
    }

    platform = config.platform;
    platform.path_remove = NULL;
    if (ve_tls_lease_release(&platform, "lease") == 0) {
        return -1;
    }

    platform = config.platform;
    platform.path_remove = persistent_reader_path_remove;
    state.result = -37;
    g_persistent_reader_remove_state = &state;
    if (ve_tls_lease_release(&platform, "/tmp/persistent-reader-lease") != -37 ||
        state.calls != 1 ||
        strcmp(state.path, "/tmp/persistent-reader-lease") != 0) {
        g_persistent_reader_remove_state = NULL;
        return -1;
    }
    state.result = 0;
    if (ve_tls_lease_release(&platform, "lease") != 0 || state.calls != 2) {
        g_persistent_reader_remove_state = NULL;
        return -1;
    }
    g_persistent_reader_remove_state = NULL;
    return 0;
}

static void persistent_reader_write_u32_le(unsigned char * p, uint32_t value) {
    p[0] = (unsigned char)(value & 0xffu);
    p[1] = (unsigned char)((value >> 8) & 0xffu);
    p[2] = (unsigned char)((value >> 16) & 0xffu);
    p[3] = (unsigned char)((value >> 24) & 0xffu);
}

static int persistent_reader_write_file(const char * path, const unsigned char * data, size_t size) {
    FILE * file;
    int rc = 0;
    if (!path || (!data && size != 0)) {
        return -1;
    }
    file = fopen(path, "wb");
    if (!file) {
        return -1;
    }
    if (size != 0 && fwrite(data, 1, size, file) != size) {
        rc = -1;
    }
    if (fclose(file) != 0) {
        rc = -1;
    }
    return rc;
}

static int persistent_reader_init_store(
    ve_tls_segment_store * store,
    ve_tls_config * config,
    const char * dir
) {
    size_t dir_len;
    if (!store || !config || !dir) {
        return -1;
    }
    dir_len = strlen(dir);
    if (dir_len == 0 || dir_len >= sizeof(store->dir_path)) {
        return -1;
    }
    memset(store, 0, sizeof(*store));
    ve_tls_config_init(config);
    store->platform = &config->platform;
    memcpy(store->dir_path, dir, dir_len + 1);
    return 0;
}

static int persistent_reader_expect_rejected(
    const unsigned char * record,
    size_t record_size
) {
    char dir[PATH_MAX];
    char segment_path[PATH_MAX];
    ve_tls_config config;
    ve_tls_segment_store store;
    ve_tls_segment_reader reader;
    ve_tls_path_info info;
    alloc_select_fail_state allocation;
    unsigned char * out_record = NULL;
    size_t out_size = 0;
    uint64_t next_offset = 0;
    int read_rc;
    int stream_rc;

    if (!record || record_size < VE_TLS_PERSISTENT_RECORD_HEADER_SIZE ||
        make_temp_dir(dir, sizeof(dir)) != 0) {
        return -1;
    }
    join_path(segment_path, sizeof(segment_path), dir, "seg-000001.log");
    if (persistent_reader_write_file(segment_path, record, record_size) != 0 ||
        persistent_reader_init_store(&store, &config, dir) != 0 ||
        config.platform.path_stat(segment_path, &info) != 0 ||
        !info.exists || info.size != record_size) {
        cleanup_persistent_dir(dir);
        return -1;
    }

    memset(&allocation, 0, sizeof(allocation));
    set_alloc_select_fail(&allocation, 0, 0, 0, 0);
    read_rc = ve_tls_segment_store_read(
        &store, 1, 0, &out_record, &out_size, &next_offset);
    ve_tls_alloc_set_hooks(NULL);
    if (read_rc == 0 || out_record != NULL || out_size != 0 || allocation.malloc_calls != 0) {
        ve_tls_segment_store_read_free(out_record);
        cleanup_persistent_dir(dir);
        return -1;
    }

    memset(&reader, 0, sizeof(reader));
    if (ve_tls_segment_store_reader_open(&store, 1, info.size, &reader) != 0) {
        cleanup_persistent_dir(dir);
        return -1;
    }
    out_record = NULL;
    out_size = 0;
    memset(&allocation, 0, sizeof(allocation));
    set_alloc_select_fail(&allocation, 0, 0, 0, 0);
    stream_rc = ve_tls_segment_store_reader_next(&store, &reader, &out_record, &out_size);
    ve_tls_alloc_set_hooks(NULL);
    ve_tls_segment_store_reader_close(&store, &reader);
    if (stream_rc >= 0 || out_record != NULL || out_size != 0 || allocation.malloc_calls != 0) {
        ve_tls_segment_store_read_free(out_record);
        cleanup_persistent_dir(dir);
        return -1;
    }
    cleanup_persistent_dir(dir);
    return 0;
}

static int persistent_reader_encode(
    unsigned char * record,
    size_t record_capacity,
    size_t * record_size,
    int64_t log_id,
    uint32_t version,
    const char * hash_key,
    const unsigned char * payload,
    size_t payload_size
) {
    ve_tls_persistent_record_view view;
    if (!record || !record_size || !payload || payload_size == 0) {
        return -1;
    }
    memset(&view, 0, sizeof(view));
    view.log_id = log_id;
    view.record_version = version;
    view.enqueue_time_ms = 1710000000123LL;
    view.flags = hash_key ? VE_TLS_PERSISTENT_RECORD_FLAG_HAS_EXT : 0;
    view.hash_key = hash_key;
    view.payload = payload;
    view.payload_size = payload_size;
    *record_size = ve_tls_persistent_record_encoded_size(&view);
    if (*record_size == 0 || *record_size > record_capacity) {
        return -1;
    }
    return ve_tls_persistent_record_encode(record, record_capacity, &view, record_size);
}

static int persistent_reader_check_decoded(
    const unsigned char * record,
    size_t record_size,
    uint32_t expected_version,
    const char * expected_hash_key,
    const unsigned char * expected_payload,
    size_t expected_payload_size
) {
    ve_tls_persistent_record decoded;
    int ok;
    memset(&decoded, 0, sizeof(decoded));
    if (ve_tls_persistent_record_decode(record, record_size, &decoded) != 0) {
        return -1;
    }
    ok = decoded.record_version == expected_version &&
         decoded.payload != NULL &&
         decoded.payload_size == expected_payload_size &&
         memcmp(decoded.payload, expected_payload, expected_payload_size) == 0;
    if (expected_hash_key) {
        ok = ok && decoded.hash_key && strcmp(decoded.hash_key, expected_hash_key) == 0;
    } else {
        ok = ok && decoded.hash_key == NULL;
    }
    ve_tls_persistent_record_free(&decoded);
    return ok ? 0 : -1;
}

static int test_persistent_reader_malformed_lengths(void) {
    unsigned char bad_magic[VE_TLS_PERSISTENT_RECORD_HEADER_SIZE + 1];
    unsigned char bad_ext[VE_TLS_PERSISTENT_RECORD_HEADER_SIZE + VE_TLS_PERSISTENT_RECORD_EXT_MAX + 1];
    unsigned char no_payload[VE_TLS_PERSISTENT_RECORD_HEADER_SIZE];
    unsigned char ext_without_payload[VE_TLS_PERSISTENT_RECORD_HEADER_SIZE + 4];
    unsigned char file_bounded_length[VE_TLS_PERSISTENT_RECORD_HEADER_SIZE];

    memset(bad_magic, 0, sizeof(bad_magic));
    persistent_reader_write_u32_le(bad_magic, VE_TLS_PERSISTENT_RECORD_MAGIC ^ 1u);
    persistent_reader_write_u32_le(bad_magic + 4, (uint32_t)sizeof(bad_magic));
    if (persistent_reader_expect_rejected(bad_magic, sizeof(bad_magic)) != 0) {
        return -1;
    }

    memset(bad_ext, 0xA5, sizeof(bad_ext));
    persistent_reader_write_u32_le(bad_ext, VE_TLS_PERSISTENT_RECORD_MAGIC);
    persistent_reader_write_u32_le(bad_ext + 4, (uint32_t)sizeof(bad_ext));
    persistent_reader_write_u32_le(bad_ext + 24, VE_TLS_PERSISTENT_RECORD_EXT_MAX + 1u);
    if (persistent_reader_expect_rejected(bad_ext, sizeof(bad_ext)) != 0) {
        return -1;
    }

    memset(no_payload, 0, sizeof(no_payload));
    persistent_reader_write_u32_le(no_payload, VE_TLS_PERSISTENT_RECORD_MAGIC);
    persistent_reader_write_u32_le(no_payload + 4, (uint32_t)sizeof(no_payload));
    if (persistent_reader_expect_rejected(no_payload, sizeof(no_payload)) != 0) {
        return -1;
    }

    memset(ext_without_payload, 0, sizeof(ext_without_payload));
    persistent_reader_write_u32_le(ext_without_payload, VE_TLS_PERSISTENT_RECORD_MAGIC);
    persistent_reader_write_u32_le(ext_without_payload + 4, (uint32_t)sizeof(ext_without_payload));
    persistent_reader_write_u32_le(ext_without_payload + 24, 4u);
    if (persistent_reader_expect_rejected(ext_without_payload, sizeof(ext_without_payload)) != 0) {
        return -1;
    }

    memset(file_bounded_length, 0, sizeof(file_bounded_length));
    persistent_reader_write_u32_le(file_bounded_length, VE_TLS_PERSISTENT_RECORD_MAGIC);
    persistent_reader_write_u32_le(file_bounded_length + 4, UINT32_MAX);
    if (persistent_reader_expect_rejected(file_bounded_length, sizeof(file_bounded_length)) != 0) {
        return -1;
    }
    return 0;
}

static int test_persistent_reader_valid_records(void) {
    static const unsigned char v1_payload[] = {'v', '1', '-', 'o', 'k'};
    static const unsigned char v2_payload[] = {'v', '2', '-', 'o', 'k'};
    unsigned char v1_record[256];
    unsigned char v2_record[256];
    size_t v1_size = 0;
    size_t v2_size = 0;
    char dir[PATH_MAX];
    char segment_path[PATH_MAX];
    ve_tls_config config;
    ve_tls_segment_store store;
    ve_tls_segment_reader reader;
    ve_tls_path_info info;
    unsigned char * out_record = NULL;
    size_t out_size = 0;
    uint64_t next_offset = 0;
    FILE * file = NULL;
    int stream_rc;
    int rc = -1;

    if (persistent_reader_encode(
            v1_record, sizeof(v1_record), &v1_size, 11,
            VE_TLS_PERSISTENT_RECORD_VERSION_LEGACY, NULL,
            v1_payload, sizeof(v1_payload)) != 0 ||
        persistent_reader_encode(
            v2_record, sizeof(v2_record), &v2_size, 12,
            VE_TLS_PERSISTENT_RECORD_VERSION_CURRENT, "reader-hash",
            v2_payload, sizeof(v2_payload)) != 0 ||
        make_temp_dir(dir, sizeof(dir)) != 0) {
        return -1;
    }
    join_path(segment_path, sizeof(segment_path), dir, "seg-000001.log");
    file = fopen(segment_path, "wb");
    if (!file) {
        cleanup_persistent_dir(dir);
        return -1;
    }
    if (fwrite(v1_record, 1, v1_size, file) != v1_size ||
        fwrite(v2_record, 1, v2_size, file) != v2_size) {
        fclose(file);
        cleanup_persistent_dir(dir);
        return -1;
    }
    if (fclose(file) != 0) {
        cleanup_persistent_dir(dir);
        return -1;
    }
    file = NULL;
    if (persistent_reader_init_store(&store, &config, dir) != 0 ||
        config.platform.path_stat(segment_path, &info) != 0 ||
        !info.exists || info.size != v1_size + v2_size) {
        cleanup_persistent_dir(dir);
        return -1;
    }
    if (ve_tls_segment_store_read(&store, 1, 0, &out_record, &out_size, &next_offset) != 0 ||
        out_size != v1_size || memcmp(out_record, v1_record, v1_size) != 0 ||
        next_offset != v1_size ||
        persistent_reader_check_decoded(
            out_record, out_size, VE_TLS_PERSISTENT_RECORD_VERSION_LEGACY,
            NULL, v1_payload, sizeof(v1_payload)) != 0) {
        ve_tls_segment_store_read_free(out_record);
        cleanup_persistent_dir(dir);
        return -1;
    }
    ve_tls_segment_store_read_free(out_record);
    out_record = NULL;
    if (ve_tls_segment_store_read(&store, 1, v1_size, &out_record, &out_size, &next_offset) != 0 ||
        out_size != v2_size || memcmp(out_record, v2_record, v2_size) != 0 ||
        next_offset != v1_size + v2_size ||
        persistent_reader_check_decoded(
            out_record, out_size, VE_TLS_PERSISTENT_RECORD_VERSION_CURRENT,
            "reader-hash", v2_payload, sizeof(v2_payload)) != 0) {
        ve_tls_segment_store_read_free(out_record);
        cleanup_persistent_dir(dir);
        return -1;
    }
    ve_tls_segment_store_read_free(out_record);
    out_record = NULL;

    memset(&reader, 0, sizeof(reader));
    if (ve_tls_segment_store_reader_open(&store, 1, info.size, &reader) != 0) {
        cleanup_persistent_dir(dir);
        return -1;
    }
    if (ve_tls_segment_store_reader_next(&store, &reader, &out_record, &out_size) != 1 ||
        out_size != v1_size || memcmp(out_record, v1_record, v1_size) != 0) {
        ve_tls_segment_store_read_free(out_record);
        ve_tls_segment_store_reader_close(&store, &reader);
        cleanup_persistent_dir(dir);
        return -1;
    }
    ve_tls_segment_store_read_free(out_record);
    out_record = NULL;
    if (ve_tls_segment_store_reader_next(&store, &reader, &out_record, &out_size) != 1 ||
        out_size != v2_size || memcmp(out_record, v2_record, v2_size) != 0) {
        ve_tls_segment_store_read_free(out_record);
        ve_tls_segment_store_reader_close(&store, &reader);
        cleanup_persistent_dir(dir);
        return -1;
    }
    ve_tls_segment_store_read_free(out_record);
    out_record = NULL;
    stream_rc = ve_tls_segment_store_reader_next(&store, &reader, &out_record, &out_size);
    ve_tls_segment_store_reader_close(&store, &reader);
    if (stream_rc != 0 || out_record != NULL || out_size != 0) {
        ve_tls_segment_store_read_free(out_record);
        cleanup_persistent_dir(dir);
        return -1;
    }
    cleanup_persistent_dir(dir);
    rc = 0;
    return rc;
}

static int test_persistent_reader_record_over_rotation_threshold(void) {
    unsigned char payload[160];
    unsigned char record[256];
    size_t record_size = 0;
    char dir[PATH_MAX];
    ve_tls_config config;
    ve_tls_segment_store_options options;
    ve_tls_segment_store store;
    ve_tls_segment_record_ref ref;
    unsigned char * out_record = NULL;
    size_t out_size = 0;
    int rc = -1;

    for (size_t i = 0; i < sizeof(payload); i++) {
        payload[i] = (unsigned char)(i ^ 0x5Au);
    }
    if (persistent_reader_encode(
            record, sizeof(record), &record_size, 23,
            VE_TLS_PERSISTENT_RECORD_VERSION_LEGACY, NULL,
            payload, sizeof(payload)) != 0 ||
        record_size <= 64 || make_temp_dir(dir, sizeof(dir)) != 0) {
        return -1;
    }
    memset(&options, 0, sizeof(options));
    memset(&store, 0, sizeof(store));
    memset(&ref, 0, sizeof(ref));
    ve_tls_config_init(&config);
    options.platform = &config.platform;
    options.dir_path = dir;
    options.segment_max_bytes = 64;
    options.segment_max_records = 32;
    if (ve_tls_segment_store_open(&store, &options) != 0 ||
        ve_tls_segment_store_append(&store, record, record_size, &ref) != 0 ||
        ref.segment_id != 1 || ref.offset != 0 ||
        store.active_size != record_size) {
        ve_tls_segment_store_close(&store);
        cleanup_persistent_dir(dir);
        return -1;
    }
    ve_tls_segment_store_close(&store);
    memset(&store, 0, sizeof(store));
    if (persistent_reader_init_store(&store, &config, dir) != 0 ||
        ve_tls_segment_store_read(&store, 1, 0, &out_record, &out_size, NULL) != 0 ||
        out_size != record_size || memcmp(out_record, record, record_size) != 0 ||
        persistent_reader_check_decoded(
            out_record, out_size, VE_TLS_PERSISTENT_RECORD_VERSION_LEGACY,
            NULL, payload, sizeof(payload)) != 0) {
        ve_tls_segment_store_read_free(out_record);
        cleanup_persistent_dir(dir);
        return -1;
    }
    ve_tls_segment_store_read_free(out_record);
    rc = 0;
    cleanup_persistent_dir(dir);
    return rc;
}

static int test_persistent_reader_regressions(void) {
    if (test_persistent_reader_lease_release_contract() != 0) {
        fprintf(stderr, "persistent reader regression: lease release contract\n");
        return -1;
    }
    if (test_persistent_reader_malformed_lengths() != 0) {
        fprintf(stderr, "persistent reader regression: malformed bounds\n");
        return -1;
    }
    if (test_persistent_reader_valid_records() != 0) {
        fprintf(stderr, "persistent reader regression: valid records\n");
        return -1;
    }
    if (test_persistent_reader_record_over_rotation_threshold() != 0) {
        fprintf(stderr, "persistent reader regression: rotation threshold\n");
        return -1;
    }
    return 0;
}
