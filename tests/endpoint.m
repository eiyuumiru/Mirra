// Compile the endpoint's actual cleanup helper. Endpoint main is never run,
// so no device, keybag, certificate or real AKS reset is accessed by this test.
#define main unused_endpoint_main
#include "../src/phone/endpoint.m"
#undef main

static int reset_calls;
static int reset_status;
static int last_handle;
static int symbol_calls, fallback_calls;
static int record_reset(int handle) {
    reset_calls++;
    last_handle = handle;
    return reset_status;
}

static void *fake_symbol(void *library, const char *name) {
    (void)library;
    symbol_calls++;
    return strcmp(name, "aks_remote_session") == 0 ? NULL : (void *)record_reset;
}

static void *fake_fallback(const char *name) {
    fallback_calls++;
    return strcmp(name, "aks_remote_session") == 0 ? (void *)fake_fallback : NULL;
}

static int key_failure, key_invalid, key_calls[8], key_unloads;
static int key_stage(int stage) {
    key_calls[stage]++;
    return key_failure == stage ? -700 - stage : 0;
}

static int fake_bag(const void *password, int length, int flags, int *bag) {
    if (!password || length != 32 || flags != 0) abort();
    int status = key_stage(1);
    *bag = status || key_invalid == 1 ? -1 : 17;
    return status;
}

static int fake_unload(int bag) {
    if (bag != 17) abort();
    key_unloads++;
    return 0;
}

static void *fake_params(const void *data, size_t length) {
    if (data || length) abort();
    return key_stage(2) ? NULL : (void *)1;
}

static int fake_data(void *params, int tag, const void *data, size_t length) {
    if (params != (void *)1 || tag != 21 || length != 4 || memcmp(data, "DCRT", 4)) abort();
    return key_stage(3);
}

static int fake_number(void *params, int tag, const int64_t *value) {
    if (params != (void *)1 || tag != 20 || *value != 4) abort();
    return key_stage(4);
}

static const unsigned char fixture_der[] = {0x30, 0x00};
static int fake_der(void *params, const void **der, size_t *length) {
    if (params != (void *)1) abort();
    *der = key_invalid == 5 ? NULL : fixture_der;
    *length = key_invalid == 5 ? 0 : sizeof(fixture_der);
    return key_stage(5);
}

static int fake_key(int bag, int key_class, void **blob, size_t *size) {
    if (bag != 17 || key_class != 9) abort();
    int status = key_stage(7);
    if (!status && key_invalid != 6) {
        *size = 8;
        *blob = malloc(*size);
        memcpy(*blob, "TESTKEY!", *size);
    }
    return status;
}

static int fake_attested_key(int bag, int key_class, const void *der, size_t length,
                             void **blob, size_t *size) {
    if (der != fixture_der || length != sizeof(fixture_der)) abort();
    int status = key_stage(6);
    return status ? status : fake_key(bag, key_class, blob, size);
}

static BOOL check_generation(void) {
    KeyStore keys = {.create_bag = fake_bag, .unload_bag = fake_unload,
        .params_create = fake_params, .params_data = fake_data, .params_number = fake_number,
        .params_der = fake_der, .create_key_params = fake_attested_key, .create_key = fake_key};
    NSData *certificate = [NSData dataWithBytes:"DCRT" length:4];
    NSArray *stages = @[@"", @"aks_create_bag", @"aks_params_create", @"aks_params_set_data",
                       @"aks_params_set_number", @"aks_params_get_der", @"aks_create_signing_key_with_params"];
    for (int stage = 1; stage <= 6; stage++) {
        key_failure = stage; key_invalid = 0; key_unloads = 0;
        memset(key_calls, 0, sizeof(key_calls));
        NSMutableDictionary *owned = [NSMutableDictionary dictionary];
        NSDictionary *response = generate_identity(&keys, certificate, YES, 9, owned);
        if (owned.count || response[@"identity"] || key_unloads != (stage == 1 ? 0 : 1) ||
            ![response[@"operation_stage"] isEqual:stages[stage]]) return NO;
        if (stage == 2) {
            if (![response[@"error"] isEqual:@"keystore_parameters_unavailable"] || key_calls[3]) return NO;
        } else if ([response[@"status"] intValue] != -700 - stage) return NO;
        for (int skipped = stage + 1; skipped <= 7; skipped++) if (key_calls[skipped]) return NO;
    }
    key_failure = 0;
    for (NSNumber *invalid in @[@1, @5, @6]) {
        key_invalid = invalid.intValue; key_unloads = 0;
        memset(key_calls, 0, sizeof(key_calls));
        NSMutableDictionary *owned = [NSMutableDictionary dictionary];
        NSDictionary *response = generate_identity(&keys, certificate, YES, 9, owned);
        if (owned.count || !response[@"error"] || [response[@"status"] intValue] ||
            key_unloads != (key_invalid == 1 ? 0 : 1) ||
            (key_invalid == 5 && key_calls[6])) return NO;
    }
    key_invalid = 0;
    for (NSNumber *attested in @[@YES, @NO]) {
        key_unloads = 0;
        memset(key_calls, 0, sizeof(key_calls));
        NSMutableDictionary *owned = [NSMutableDictionary dictionary];
        NSDictionary *response = generate_identity(&keys, certificate, attested.boolValue, 9, owned);
        NSDictionary *identity = owned[response[@"identity"]];
        if ([response[@"status"] intValue] || response[@"error"] || owned.count != 1 || !identity ||
            [identity[@"bag"] intValue] != 17 || ![identity[@"attested"] isEqual:attested] ||
            [identity[@"ltk"] length] != 8 || [response[@"bytes"] intValue] != 8 || key_unloads ||
            key_calls[2] != (attested.boolValue ? 1 : 0)) return NO;
    }
    return YES;
}

static BOOL check_saved_pairing_cleanup(void) {
    KeyStore keys = {.reset_session = record_reset};
    NSArray *same = @[@"local", @"remote", @0x81];
    NSArray *other = @[@"local", @"other", @0x81];
    NSMutableSet *sessions = [NSMutableSet setWithArray:@[@1, @2, @3, @4, @5]];
    NSMutableDictionary *kinds = [@{
        @1: @{@"peer": same, @"confirmed": @YES, @"order": @1},
        @2: @{@"peer": same, @"confirmed": @YES, @"order": @2},
        @3: @{@"peer": other, @"confirmed": @YES, @"order": @3},
        @4: @{@"peer": same, @"order": @4},
        @5: @{@"flags": @0xff, @"order": @5}
    } mutableCopy];
    reset_status = -123;
    prune_saved_pairing_sessions(sessions, kinds, &keys, NO);
    if (sessions.count != 5 || kinds.count != 5) return NO;
    reset_status = 0;
    prune_saved_pairing_sessions(sessions, kinds, &keys, NO);
    if ([sessions containsObject:@1] || kinds[@1] || ![sessions containsObject:@4]) return NO;
    prune_saved_pairing_sessions(sessions, kinds, &keys, YES);
    return [sessions isEqual:[NSSet setWithArray:@[@2, @3, @5]]] &&
        !kinds[@4] && kinds.count == sessions.count;
}

int main(void) {
    @autoreleasepool {
        NSMutableSet *owned = [NSMutableSet setWithArray:@[@17, @91]];
        NSDictionary *reply = reset_owned_session(owned, @8, record_reset);
        if (![reply[@"error"] isEqual:@"session_not_owned"] || reset_calls || owned.count != 2) return 1;
        reset_status = -123;
        reply = reset_owned_session(owned, @17, record_reset);
        if ([reply[@"status"] intValue] != -123 || reset_calls != 1 || last_handle != 17 ||
            ![owned containsObject:@17] || ![owned containsObject:@91]) return 2;
        reset_status = 0;
        reply = reset_owned_session(owned, @17, record_reset);
        if ([reply[@"status"] intValue] || reset_calls != 2 || [owned containsObject:@17] ||
            ![owned containsObject:@91]) return 3;
        reply = reset_owned_session(owned, @17, record_reset);
        if (![reply[@"error"] isEqual:@"session_not_owned"] || reset_calls != 2) return 4;
        NSMutableArray *missing = [NSMutableArray array];
        if (required_symbol((void *)1, "aks_remote_session", missing, fake_symbol, NULL) != NULL ||
            ![missing isEqual:@[@"aks_remote_session"]]) return 5;
        if (required_symbol((void *)1, "aks_remote_session_reset", missing, fake_symbol, NULL) == NULL || missing.count != 1) return 6;
        if (required_symbol(NULL, "aks_create_bag", missing, fake_symbol, NULL) != NULL || missing.count != 2) return 7;
        KeyStore keys = {0};
        symbol_calls = fallback_calls = 0;
        missing = load_keystore(&keys, (void *)1, fake_symbol, fake_fallback);
        if (missing.count || symbol_calls != 21 || fallback_calls != 1 ||
            (void *)keys.reset_session != (void *)record_reset ||
            (void *)keys.remote_session != (void *)fake_fallback) return 8;
        // Unsupported maps retain the original error list and available APIs.
        missing = load_keystore(&keys, (void *)1, fake_symbol, mapped_keystore_symbol);
        if (![missing isEqual:@[@"aks_remote_session"]] || keys.remote_session ||
            (void *)keys.reset_session != (void *)record_reset) return 9;
        symbol_calls = 0;
        missing = load_keystore(&keys, NULL, fake_symbol, NULL);
        if (missing.count != 18 || symbol_calls || keys.reset_session || keys.remote_session) return 10;
        fallback_calls = 0;
        missing = load_keystore(&keys, NULL, fake_symbol, fake_fallback);
        if (missing.count != 17 || symbol_calls || fallback_calls != 21 ||
            (void *)keys.remote_session != (void *)fake_fallback || keys.reset_session) return 11;
        if (!check_generation()) return 12;
        if (!check_saved_pairing_cleanup()) return 13;
        puts("{\"cases\":23,\"passed\":true,\"real_aks_accessed\":false}");
    }
    return 0;
}
