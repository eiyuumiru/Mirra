// Compile against the actual endpoint. Every private API below is a fixture.
// The iOS certificate branch runs with host Foundation, not an iPhone ABI.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <TargetConditionals.h>
#include <dlfcn.h>
#include <sys/sysctl.h>
#include <stdlib.h>
#include <string.h>

static NSMutableDictionary *calls;
static NSMutableArray *resets, *unloads;
static NSData *keyFixture;
static int nextSession = 0;
static void (^pendingCallback)(NSError *);

static const char *setting(const char *name, const char *fallback) {
    const char *value = getenv(name);
    return value ? value : fallback;
}

static int simulate(const char *name) {
    NSString *key = @(name);
    calls[key] = @([calls[key] intValue] + 1);
    return !strcmp(setting("MIRRA_SIM_FAIL", ""), name) ? -701 : 0;
}

static int fake_bag(const void *password, int length, int flags, int *bag) {
    if (!password || length != 32 || flags != 0) abort();
    int status = simulate("aks_create_bag");
    *bag = status ? -1 : 100 + [calls[@"aks_create_bag"] intValue];
    if (!strcmp(setting("MIRRA_SIM_BAG", ""), "negative")) *bag = -1;
    return status;
}

static int fake_unload(int bag) {
    [unloads addObject:@(bag)];
    return simulate("aks_unload_bag");
}

static void supply_blob(const char *api, NSData *data, void **blob, size_t *size) {
    const char *mode = !strcmp(setting("MIRRA_SIM_MODE_API", ""), api) ? setting("MIRRA_SIM_MODE", "normal") : "normal";
    if (!strcmp(mode, "empty")) { *blob = NULL; *size = 0; return; }
    if (!strcmp(mode, "null_with_size")) { *blob = NULL; *size = 8; return; }
    if (!strcmp(mode, "zero_with_buffer")) { *blob = calloc(1, 8); *size = 0; return; }
    *size = !strcmp(mode, "oversize") ? 65537 : data.length;
    *blob = calloc(1, *size);
    if (!*blob) abort();
    memcpy(*blob, data.bytes, MIN(*size, data.length));
}

static int fake_key(int bag, int keyClass, void **blob, size_t *size) {
    if (bag < 100 || (keyClass != 9 && keyClass != 10 && keyClass != 11)) abort();
    int status = simulate("aks_create_signing_key");
    if (!status) supply_blob("aks_create_signing_key", keyFixture, blob, size);
    return status;
}

static void *fake_params(const void *data, size_t length) {
    if (data || length) abort();
    return simulate("aks_params_create") ? NULL : (void *)1;
}

static int fake_param_data(void *params, int tag, const void *data, size_t length) {
    if (params != (void *)1 || tag != 21 || !data || !length) abort();
    return simulate("aks_params_set_data");
}

static int fake_param_number(void *params, int tag, const int64_t *value) {
    if (params != (void *)1 || tag != 20 || *value != 4) abort();
    return simulate("aks_params_set_number");
}

static int fake_der(void *params, const void **der, size_t *size) {
    if (params != (void *)1) abort();
    static const unsigned char bytes[] = {0x30, 0x00};
    *der = bytes; *size = sizeof(bytes);
    if (!strcmp(setting("MIRRA_SIM_DER", ""), "null")) *der = NULL;
    if (!strcmp(setting("MIRRA_SIM_DER", ""), "empty")) *size = 0;
    return simulate("aks_params_get_der");
}

static int fake_attested(int bag, int keyClass, const void *der, size_t length, void **blob, size_t *size) {
    if (bag < 100 || !der || !length || (keyClass != 9 && keyClass != 10 && keyClass != 11)) abort();
    int status = simulate("aks_create_signing_key_with_params");
    if (!status) supply_blob("aks_create_signing_key_with_params", keyFixture, blob, size);
    return status;
}

static int fake_sign(int bag, int keyClass, const void *local, size_t localSize,
                     int remoteClass, const void *remote, size_t remoteSize, void **blob, size_t *size) {
    if (bag < 100 || !local || !localSize || !remote || !remoteSize ||
        (keyClass != 9 && keyClass != 10 && keyClass != 11) ||
        (remoteClass != 9 && remoteClass != 10 && remoteClass != 11)) abort();
    int status = simulate("aks_sign_signing_key");
    if (!status) {
        NSMutableData *value = [[NSData dataWithBytes:remote length:remoteSize] mutableCopy];
        ((unsigned char *)value.mutableBytes)[0] ^= 0x55;
        supply_blob("aks_sign_signing_key", value, blob, size);
    }
    return status;
}

static int fake_session(int bag, unsigned flags, const void *local, size_t localSize,
                        const void *remote, size_t remoteSize, const void *params, size_t paramSize, int *session) {
    (void)flags; (void)params; (void)paramSize;
    if (bag < 100 || !local || !localSize || !remote || !remoteSize) abort();
    int status = simulate("aks_remote_session");
    const char *mode = setting("MIRRA_SIM_HANDLE", "normal");
    *session = !strcmp(mode, "negative") ? -1 : !strcmp(mode, "duplicate") ? 7 : nextSession++;
    return status;
}

static int fake_reset(int session) {
    [resets addObject:@(session)];
    return simulate("aks_remote_session_reset");
}

static int fake_output(const char *name, int session, void **blob, size_t *size) {
    if (session < 0) abort();
    int status = simulate(name);
    if (!status || !strcmp(setting("MIRRA_SIM_MODE", ""), "failure_with_data"))
        supply_blob(name, [@"SYNTHETIC" dataUsingEncoding:NSUTF8StringEncoding], blob, size);
    return status;
}

static int fake_step(int session, const void *input, size_t length, void **blob, size_t *size) {
    (void)input; (void)length;
    return fake_output("aks_remote_session_step", session, blob, size);
}
static int fake_setup(int session, const void *input, size_t length, void **blob, size_t *size) {
    (void)input; (void)length;
    return fake_output("aks_remote_peer_setup", session, blob, size);
}
static int fake_token(int session, void **blob, size_t *size) {
    return fake_output("aks_remote_session_token", session, blob, size);
}
static int fake_confirm(int session, void **blob, size_t *size) {
    return fake_output("aks_remote_peer_confirm", session, blob, size);
}
static int fake_validate(int bag, int keyClass, const void *key, size_t size) {
    (void)bag; (void)keyClass; (void)key; (void)size;
    return simulate("aks_validate_local_key");
}
static int fake_state(int bag, const void *key, size_t size, void *output) {
    (void)bag; (void)key; (void)size;
    memset(output, 0x42, 104);
    return simulate("aks_remote_peer_get_state");
}
static int fake_drop(int bag, const void *key, size_t size) {
    (void)bag; (void)key; (void)size;
    return simulate("aks_remote_peer_drop");
}

static NSData *fake_copy(NSError *__autoreleasing *error) {
    if (simulate("MAECopyDCRTWithError")) {
        *error = [NSError errorWithDomain:@"simulation.activation" code:701 userInfo:nil];
        return nil;
    }
    if (!strcmp(setting("MIRRA_SIM_CERT_TYPE", ""), "invalid")) return (id)NSNull.null;
    return [NSMutableData dataWithLength:(NSUInteger)strtoul(setting("MIRRA_SIM_CERT_SIZE", "1024"), NULL, 10)];
}
static void fake_issue(NSDictionary *options, void *context, void (^callback)(NSError *)) {
    (void)options; (void)context;
    int status = simulate("MAEIssueDCRTWithCallback");
    const char *mode = setting("MIRRA_SIM_ISSUE", "immediate");
    if (!strcmp(mode, "timeout")) return;
    if (!strcmp(mode, "delayed")) { pendingCallback = [callback copy]; return; }
    callback(status ? [NSError errorWithDomain:@"simulation.activation" code:701 userInfo:nil] : nil);
}

// Advance virtual time in the actual issuance loop, including a delayed callback.
@interface SimulatedClock : NSObject
@property NSTimeInterval remaining;
+ (instancetype)dateWithTimeIntervalSinceNow:(NSTimeInterval)value;
- (NSTimeInterval)timeIntervalSinceNow;
@end
@implementation SimulatedClock
+ (instancetype)dateWithTimeIntervalSinceNow:(NSTimeInterval)value {
    SimulatedClock *clock = [self new]; clock.remaining = value + 20; return clock;
}
- (NSTimeInterval)timeIntervalSinceNow { self.remaining -= 20; return self.remaining; }
@end
@interface SimulatedRunLoop : NSObject
+ (instancetype)currentRunLoop;
- (BOOL)runMode:(NSString *)mode beforeDate:(id)date;
@end
@implementation SimulatedRunLoop
+ (instancetype)currentRunLoop { return [self new]; }
- (BOOL)runMode:(NSString *)mode beforeDate:(id)date {
    (void)mode; (void)date;
    if (pendingCallback) { void (^callback)(NSError *) = pendingCallback; pendingCallback = nil; callback(nil); }
    return YES;
}
@end

static OSStatus fake_random(SecRandomRef random, size_t count, uint8_t *bytes) {
    (void)random; memset(bytes, 0x41, count);
    return simulate("SecRandomCopyBytes");
}
static int fake_sysctl(const char *name, void *output, size_t *size, void *newValue, size_t newSize) {
    (void)newValue; (void)newSize;
    const char *value = !strcmp(name, "hw.machine") ? setting("MIRRA_SIM_MODEL", "iPhone11,2") :
        !strcmp(name, "kern.osproductversion") ? setting("MIRRA_SIM_IOS", "17.2") :
        !strcmp(name, "kern.osversion") ? setting("MIRRA_SIM_BUILD", "21C62") : "unavailable";
    if (*size < strlen(value) + 1) return -1;
    *size = strlen(value) + 1; memcpy(output, value, *size); return 0;
}
static void *fake_open(const char *path, int flags) {
    (void)path; (void)flags;
    return !strcmp(setting("MIRRA_SIM_MISSING", ""), "library") ? NULL : (void *)1;
}
static void *fake_symbol(void *library, const char *name) {
    if (!library || !strcmp(setting("MIRRA_SIM_MISSING", ""), name)) return NULL;
#define SYMBOL(NAME, FUNCTION) if (!strcmp(name, NAME)) return (void *)FUNCTION
    SYMBOL("aks_create_bag", fake_bag); SYMBOL("aks_unload_bag", fake_unload);
    SYMBOL("aks_create_signing_key", fake_key); SYMBOL("aks_create_signing_key_with_params", fake_attested);
    SYMBOL("aks_sign_signing_key", fake_sign); SYMBOL("aks_params_create", fake_params);
    SYMBOL("aks_params_set_data", fake_param_data); SYMBOL("aks_params_set_number", fake_param_number);
    SYMBOL("aks_params_get_der", fake_der); SYMBOL("aks_remote_session", fake_session);
    SYMBOL("aks_remote_session_step", fake_step); SYMBOL("aks_remote_session_reset", fake_reset);
    SYMBOL("aks_remote_session_token", fake_token); SYMBOL("aks_remote_peer_confirm", fake_confirm);
    SYMBOL("aks_remote_peer_setup", fake_setup); SYMBOL("aks_validate_local_key", fake_validate);
    SYMBOL("aks_remote_peer_get_state", fake_state); SYMBOL("aks_remote_peer_drop", fake_drop);
    SYMBOL("MAECopyDCRTWithError", fake_copy); SYMBOL("MAEIssueDCRTWithCallback", fake_issue);
#undef SYMBOL
    return NULL;
}

#undef TARGET_OS_IPHONE
#define TARGET_OS_IPHONE 1
#define dlopen fake_open
#define dlsym fake_symbol
#define SecRandomCopyBytes fake_random
#define sysctlbyname fake_sysctl
#define NSDate SimulatedClock
#define NSRunLoop SimulatedRunLoop
#define main mirra_endpoint_main
#include "../src/phone/endpoint.m"
#undef main
#undef NSRunLoop
#undef NSDate
#undef sysctlbyname
#undef SecRandomCopyBytes
#undef dlsym
#undef dlopen

int main(int argc, const char **argv) {
    @autoreleasepool {
        calls = [NSMutableDictionary dictionary]; resets = [NSMutableArray array]; unloads = [NSMutableArray array];
        const char *keyPath = getenv("MIRRA_SIM_KEY_FILE");
        keyFixture = keyPath ? [NSData dataWithContentsOfFile:@(keyPath)] : [@"TESTKEY!" dataUsingEncoding:NSUTF8StringEncoding];
        int code;
        NSString *exception = @"";
        @try { code = mirra_endpoint_main(argc, argv); }
        @catch (NSException *error) { code = 86; exception = error.name; }
        NSDictionary *summary = @{@"calls": calls, @"resets": resets, @"unloads": unloads, @"exception": exception,
            @"real_aks_accessed": @NO, @"real_issuer_contacted": @NO, @"virtual_issuance_clock": @YES};
        const char *output = getenv("MIRRA_SIM_STATS_FILE");
        if (output) [[NSJSONSerialization dataWithJSONObject:summary options:0 error:NULL] writeToFile:@(output) atomically:NO];
        return code;
    }
}
