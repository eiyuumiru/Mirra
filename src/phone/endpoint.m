#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <TargetConditionals.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/mman.h>
#include <limits.h>
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Network/Network.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#if TARGET_OS_IPHONE && defined(__arm64__)
#define KEYSTORE_SYMBOL_TARGET 1
#else
#define KEYSTORE_SYMBOL_TARGET 0
#endif
#if KEYSTORE_SYMBOL_TARGET || defined(MIRRA_SYMBOL_FIXTURES)
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/vm_prot.h>
#include <stdbool.h>
#include "keystore-symbols.h"
#include "cache-symbols.h"
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif
#endif

// Experimental AKS bridge service. SSH is used only to install it; the Mac
// then talks to it over TLS-PSK (HTTP for status/certificate, WebSocket for a
// keystore session). All identities live in newly allocated unsaved keybags.
// Only session IDs created by a connection can be stepped/reset by it.
// System keybags are not used.
typedef int (*CreateBag)(const void *, int, int, int *);
typedef int (*UnloadBag)(int);
typedef int (*CreateKey)(int, int, void **, size_t *);
typedef int (*CreateKeyParams)(int, int, const void *, size_t, void **, size_t *);
typedef int (*SignKey)(int, int, const void *, size_t, int, const void *, size_t, void **, size_t *);
typedef void *(*ParamsCreate)(const void *, size_t);
typedef int (*ParamsData)(void *, int, const void *, size_t);
typedef int (*ParamsNumber)(void *, int, const int64_t *);
typedef int (*ParamsDER)(void *, const void **, size_t *);
typedef int (*RemoteSession)(int, unsigned int, const void *, size_t, const void *, size_t, const void *, size_t, int *);
typedef int (*RemoteStep)(int, const void *, size_t, void **, size_t *);
typedef int (*ResetSession)(int);
typedef int (*RemoteOutput)(int, void **, size_t *);
typedef int (*ValidateKey)(int, int, const void *, size_t);
typedef int (*PeerState)(int, const void *, size_t, void *);
typedef int (*PeerDrop)(int, const void *, size_t);
typedef int (*SaveBag)(int, void **, int *);
typedef int (*LoadBag)(const void *, int, int *);
typedef int (*UnlockBag)(int, const void *, int);

// Shared by the protocol endpoint and its device check.
typedef struct {
    CreateBag create_bag;
    UnloadBag unload_bag;
    CreateKey create_key;
    CreateKeyParams create_key_params;
    SignKey sign_key;
    ParamsCreate params_create;
    ParamsData params_data;
    ParamsNumber params_number;
    ParamsDER params_der;
    RemoteSession remote_session;
    RemoteStep remote_step;
    ResetSession reset_session;
    RemoteOutput session_token;
    RemoteOutput peer_confirm;
    RemoteStep peer_setup;
    ValidateKey validate_key;
    PeerState peer_state;
    PeerDrop peer_drop;
    // Optional: keep a Mac's keybag across connections and service restarts.
    SaveBag save_bag;
    LoadBag load_bag;
    UnlockBag unlock_bag;
} KeyStore;

typedef void *(*SymbolResolver)(void *, const char *);
typedef void *(*SymbolFallback)(const char *);

static void reply(NSDictionary *value) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:value options:0 error:NULL];
    fwrite(data.bytes, 1, data.length, stdout);
    putchar('\n');
    fflush(stdout);
}

static void diagnostic(NSDictionary *value) {
    // stderr is diagnostic-only; the JSON request/reply stream stays intact.
    NSData *data = [NSJSONSerialization dataWithJSONObject:value options:0 error:NULL];
    NSMutableData *line = [[@"MIRRA_ENDPOINT " dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    [line appendData:data]; [line appendBytes:"\n" length:1];
    // Use the already-reviewed write import in the fallback iOS linker.
    (void)write(STDERR_FILENO, line.bytes, line.length);
}

static NSMutableDictionary *result(int status) {
    return [@{@"status": @(status), @"status_hex": [NSString stringWithFormat:@"0x%08x", status]} mutableCopy];
}

static NSMutableDictionary *invalid_native_result(NSString *error, NSString *stage) {
    // Keep the API's zero status as evidence, but never forward unusable
    // native output to a caller that interprets status alone as success.
    NSMutableDictionary *response = result((int)0xe00002bc);
    response[@"native_status"] = @0;
    response[@"error"] = error;
    response[@"operation_stage"] = stage;
    return response;
}

static BOOL valid_request_fields(NSDictionary *request) {
    if (![request[@"operation"] isKindOfClass:NSString.class]) return NO;
    NSString *string_fields[] = {@"identity", @"remote_ltk", @"parameters", @"data"};
    for (size_t i = 0; i < sizeof(string_fields) / sizeof(*string_fields); i++) {
        NSString *field = string_fields[i];
        if (request[field] && ![request[field] isKindOfClass:NSString.class]) return NO;
    }
    NSString *number_fields[] = {@"attested", @"key_class", @"remote_key_class", @"flags", @"session"};
    for (size_t i = 0; i < sizeof(number_fields) / sizeof(*number_fields); i++) {
        NSString *field = number_fields[i];
        if (request[field] && ![request[field] isKindOfClass:NSNumber.class]) return NO;
    }
    return YES;
}

static NSDictionary *reset_owned_session(NSMutableSet<NSNumber *> *sessions,
                                         NSNumber *session, ResetSession reset) {
    if (!session || ![sessions containsObject:session])
        return @{@"error": @"session_not_owned"};
    int status = reset(session.intValue);
    // A failed AKS reset may leave the native session alive. Retain its handle
    // for retry and final process cleanup instead of silently orphaning it.
    if (status == 0) [sessions removeObject:session];
    return result(status);
}

static void clear_blob(void *blob, size_t size) {
    if (!blob) return;
    volatile unsigned char *bytes = blob;
    for (size_t i = 0; i < size; i++) bytes[i] = 0;
    free(blob);
}

static NSString *digest(NSData *data) {
    if (!data.length || data.length > 1048576) return @"";
    unsigned char value[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, value);
    char text[CC_SHA256_DIGEST_LENGTH * 2 + 1];
    for (size_t i = 0; i < sizeof(value); i++) snprintf(text + i * 2, 3, "%02x", value[i]);
    return [NSString stringWithUTF8String:text];
}

static NSString *system_value(const char *name) {
    char value[256] = {0};
    size_t size = sizeof(value);
    return sysctlbyname(name, value, &size, NULL, 0) == 0 ? [NSString stringWithUTF8String:value] : @"unavailable";
}

static NSString *process_architecture(void) {
#if defined(__arm64e__)
    return @"arm64e";
#elif defined(__arm64__)
    return @"arm64";
#elif defined(__x86_64__)
    return @"x86_64";
#else
    return @"unknown";
#endif
}

static const char *keystore_path(void) {
#if TARGET_OS_IPHONE
    return "/System/Library/PrivateFrameworks/AppleKeyStore.framework/AppleKeyStore";
#else
    return "/System/Library/PrivateFrameworks/AppleKeyStore.framework/Versions/A/AppleKeyStore";
#endif
}

// Private symbol fallback contributed by @OiviaDesu in PR #4 (a193c167).
#if KEYSTORE_SYMBOL_TARGET || defined(MIRRA_SYMBOL_FIXTURES)

static bool symbol_map_supported(const char *build, const char *architecture) {
    return build && architecture && !strcmp(build, keystore_build) && !strcmp(architecture, "arm64");
}

static const MappedSymbol *find_symbol(const char *name) {
    if (!name) return NULL;
    for (size_t i = 0; i < sizeof(keystore_symbols) / sizeof(*keystore_symbols); i++)
        if (!strcmp(name, keystore_symbols[i].name)) return &keystore_symbols[i];
    return NULL;
}

static bool slid_address(uint64_t value, intptr_t slide, uintptr_t *result) {
    if (slide >= 0) {
        if (value > UINTPTR_MAX - (uintptr_t)slide) return false;
        *result = (uintptr_t)value + (uintptr_t)slide;
    } else {
        uintptr_t amount = (uintptr_t)(-(slide + 1)) + 1;
        if (value < amount) return false;
        *result = (uintptr_t)value - amount;
    }
    return true;
}

// Validate metadata separately from dyld lookup so malformed and mismatched
// images can be checked on the host without calling any private function.
static void *image_address(const void *bytes, size_t length, uintptr_t address,
                           intptr_t slide, const unsigned char *expected_uuid,
                           bool allow_arm64e, unsigned section_index) {
    if (!bytes || length < sizeof(struct mach_header_64) || (address & 3)) return NULL;
    struct mach_header_64 header;
    memcpy(&header, bytes, sizeof(header));
    cpu_subtype_t subtype = header.cpusubtype & ~CPU_SUBTYPE_MASK;
    if (header.magic != MH_MAGIC_64 || header.cputype != CPU_TYPE_ARM64 ||
        (subtype != CPU_SUBTYPE_ARM64_ALL && !(allow_arm64e && subtype == CPU_SUBTYPE_ARM64E)) ||
        header.sizeofcmds > length - sizeof(header)) return NULL;
    const unsigned char *cursor = (const unsigned char *)bytes + sizeof(header);
    size_t remaining = header.sizeofcmds;
    bool uuid_ok = false, text_ok = false;
    unsigned uuid_count = 0;
    uint64_t sections = 0;
    for (uint32_t i = 0; i < header.ncmds; i++) {
        struct load_command command;
        if (remaining < sizeof(command)) return NULL;
        memcpy(&command, cursor, sizeof(command));
        if (command.cmdsize < sizeof(command) || command.cmdsize > remaining ||
            command.cmdsize % 8) return NULL;
        if (command.cmd == LC_UUID) {
            struct uuid_command uuid;
            if (command.cmdsize != sizeof(uuid) || ++uuid_count != 1) return NULL;
            memcpy(&uuid, cursor, sizeof(uuid));
            uuid_ok = expected_uuid ? !memcmp(uuid.uuid, expected_uuid, sizeof(uuid.uuid))
                                    : cache_uuid_present(uuid.uuid);
        } else if (command.cmd == LC_SEGMENT_64) {
            struct segment_command_64 segment;
            if (command.cmdsize < sizeof(segment)) return NULL;
            memcpy(&segment, cursor, sizeof(segment));
            if (segment.nsects > (command.cmdsize - sizeof(segment)) / sizeof(struct section_64)) return NULL;
            if (!strncmp(segment.segname, "__TEXT", sizeof(segment.segname)) &&
                (segment.initprot & VM_PROT_EXECUTE)) {
                uintptr_t start;
                if (!slid_address(segment.vmaddr, slide, &start) || address < start ||
                    segment.vmsize < 4 || address - start > segment.vmsize - 4) return NULL;
                for (uint32_t s = 0; s < segment.nsects; s++) {
                    struct section_64 section;
                    memcpy(&section, cursor + sizeof(segment) + s * sizeof(section), sizeof(section));
                    if (!strncmp(section.segname, "__TEXT", sizeof(section.segname)) &&
                        !strncmp(section.sectname, "__text", sizeof(section.sectname)) &&
                        (section.flags & S_ATTR_PURE_INSTRUCTIONS) &&
                        slid_address(section.addr, slide, &start) && address >= start &&
                        section.size >= 4 && address - start <= section.size - 4 &&
                        (!section_index || sections + s + 1 == section_index)) text_ok = true;
                }
            }
            sections += segment.nsects;
        }
        cursor += command.cmdsize;
        remaining -= command.cmdsize;
    }
    return remaining == 0 && uuid_ok && text_ok ? (void *)address : NULL;
}

static void *image_symbol(const void *bytes, size_t length, uintptr_t base,
                          intptr_t slide, const MappedSymbol *symbol) {
    if (!symbol || symbol->image >= sizeof(keystore_images) / sizeof(*keystore_images) ||
        symbol->offset > UINTPTR_MAX - base) return NULL;
    return image_address(bytes, length, base + symbol->offset, slide,
                         keystore_images[symbol->image].uuid, false, 0);
}

typedef struct {
    void *mapping;
    size_t mapping_size;
    CacheSymbols symbols;
} CacheSymbolsFile;

static inline void close_cache_symbols(CacheSymbolsFile *file) {
    if (file->mapping) munmap(file->mapping, file->mapping_size);
    *file = (CacheSymbolsFile){0};
}

static inline bool open_cache_symbols(const char *path, const unsigned char uuid[16],
                                      const unsigned char magic[16], CacheSymbolsFile *output,
                                      const char **error) {
    *error = "cache_symbols_file_unavailable";
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return false;
    struct stat info;
    unsigned char bytes[CACHE_HEADER_BYTES];
    CacheHeader header;
    CacheSymbolsFile file = {0};
    bool available = false;
    do {
        if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_size < CACHE_UUID_OFFSET + 16 ||
            (info.st_uid != 0 && info.st_uid != getuid()) || (info.st_mode & 022)) break;
        ssize_t size = pread(fd, bytes, sizeof(bytes), 0);
        *error = "cache_symbols_header_invalid";
        if (size < 0 || !cache_header(bytes, (size_t)size, &header) ||
            !cache_range((size_t)info.st_size, 0, header.mapping_offset)) break;
        *error = "cache_symbols_uuid_mismatch";
        if (memcmp(header.uuid, uuid, 16) || memcmp(header.magic, magic, 16)) break;
        *error = "cache_local_symbols_unavailable";
        if (!header.symbols_offset || !header.symbols_size) break;
        *error = "cache_local_symbols_invalid";
        if (!cache_range((size_t)info.st_size, header.symbols_offset, header.symbols_size)) break;
        int page = getpagesize();
        if (page <= 0) break;
        uint64_t offset = header.symbols_offset - header.symbols_offset % (unsigned)page;
        size_t prefix = (size_t)(header.symbols_offset - offset);
        if (header.symbols_size > SIZE_MAX - prefix) break;
        file.mapping_size = (size_t)header.symbols_size + prefix;
        file.mapping = mmap(NULL, file.mapping_size, PROT_READ, MAP_PRIVATE, fd, (off_t)offset);
        if (file.mapping == MAP_FAILED) { file.mapping = NULL; break; }
        if (!cache_symbols((const unsigned char *)file.mapping + prefix,
                           (size_t)header.symbols_size, header.wide_entries, &file.symbols)) break;
        *output = file;
        available = true;
        *error = NULL;
    } while (false);
    close(fd);
    if (!available) close_cache_symbols(&file);
    return available;
}

static inline bool open_active_cache_symbols(const char *path, const CacheHeader *active,
                                             CacheSymbolsFile *output, const char **error) {
    if (open_cache_symbols(path, active->uuid, active->magic, output, error)) return true;
    if (!cache_uuid_present(active->symbols_uuid)) return false;
    char companion[PATH_MAX];
    int size = snprintf(companion, sizeof(companion), "%s.symbols", path);
    if (size < 0 || (size_t)size >= sizeof(companion)) return false;
    return open_cache_symbols(companion, active->symbols_uuid, active->magic, output, error);
}

static inline bool find_cache_symbols(const char *path, const CacheHeader *active,
                                      CacheSymbolsFile *output, const char **error) {
    const char *first_error = NULL;
    if (path) {
        if (open_active_cache_symbols(path, active, output, error)) return true;
        if (strcmp(*error, "cache_symbols_file_unavailable")) first_error = *error;
    }
    // Older dyld reports the standard filename, which can differ from the
    // active development cache. Every candidate still requires the active UUID.
    const char *directories[] = {"/System/Library/Caches/com.apple.dyld", "/System/Library/dyld"};
    const char *suffixes[] = {"", ".development"};
    const char *architecture = active->magic[14] == 'e' ? "arm64e" : "arm64";
    char candidate[PATH_MAX];
    for (unsigned d = 0; d < sizeof(directories) / sizeof(*directories); d++) {
        for (unsigned s = 0; s < sizeof(suffixes) / sizeof(*suffixes); s++) {
            int size = snprintf(candidate, sizeof(candidate), "%s/dyld_shared_cache_%s%s",
                                directories[d], architecture, suffixes[s]);
            if (size < 0 || (size_t)size >= sizeof(candidate) || (path && !strcmp(path, candidate))) continue;
            if (open_active_cache_symbols(candidate, active, output, error)) return true;
            if (!first_error && strcmp(*error, "cache_symbols_file_unavailable")) first_error = *error;
        }
    }
    *error = first_error ? first_error : "cache_symbols_file_unavailable";
    return false;
}

static inline void *cache_symbol_function(const CacheSymbol *symbol, const void *image,
                                          size_t length, intptr_t slide) {
    const struct mach_header_64 *header = image;
    if (!image || length < sizeof(*header) || header->filetype != MH_DYLIB ||
        !(header->flags & MH_DYLIB_IN_CACHE)) return NULL;
    uintptr_t address;
    if (!slid_address(symbol->value, slide, &address)) return NULL;
    void *function = image_address(image, length, address, slide, NULL, true, symbol->section);
#if __has_feature(ptrauth_calls)
    if (function) function = ptrauth_sign_unauthenticated(function, ptrauth_key_asia, 0);
#endif
    return function;
}

static inline void *cache_image_symbol(const CacheSymbols *symbols, uint64_t image_offset,
                                       const void *image, size_t length, intptr_t slide,
                                       const char *name, CacheSymbolResult *result) {
    CacheSymbol symbol;
    *result = cache_find_symbol(symbols, image_offset, name, &symbol);
    if (*result != CACHE_SYMBOL_FOUND) return NULL;
    void *function = cache_symbol_function(&symbol, image, length, slide);
    if (!function) *result = CACHE_SYMBOL_INVALID;
    return function;
}

static inline void *live_cache_symbol(const void *image, size_t length, intptr_t slide,
                                      const void *cache, size_t cache_size, const char *name,
                                      CacheSymbolResult *result) {
    *result = CACHE_SYMBOL_INVALID;
    if (!image || length < sizeof(struct mach_header_64) || !cache ||
        cache_size > UINTPTR_MAX - (uintptr_t)cache) return NULL;
    if ((uintptr_t)image < (uintptr_t)cache ||
        !cache_range(cache_size, (uintptr_t)image - (uintptr_t)cache, length)) return NULL;
    struct mach_header_64 header;
    memcpy(&header, image, sizeof(header));
    if (header.magic != MH_MAGIC_64 || header.cputype != CPU_TYPE_ARM64 ||
        !(header.flags & MH_DYLIB_IN_CACHE) || header.filetype != MH_DYLIB ||
        header.sizeofcmds > length - sizeof(header)) return NULL;
    const unsigned char *cursor = (const unsigned char *)image + sizeof(header);
    size_t remaining = header.sizeofcmds;
    struct symtab_command table = {0};
    struct segment_command_64 linkedit = {0};
    bool table_found = false, linkedit_found = false;
    for (uint32_t i = 0; i < header.ncmds; i++) {
        struct load_command command;
        if (remaining < sizeof(command)) return NULL;
        memcpy(&command, cursor, sizeof(command));
        if (command.cmdsize < sizeof(command) || command.cmdsize > remaining || command.cmdsize % 8) return NULL;
        if (command.cmd == LC_SYMTAB) {
            if (table_found || command.cmdsize != sizeof(table)) return NULL;
            memcpy(&table, cursor, sizeof(table)); table_found = true;
        } else if (command.cmd == LC_SEGMENT_64) {
            struct segment_command_64 segment;
            if (command.cmdsize < sizeof(segment)) return NULL;
            memcpy(&segment, cursor, sizeof(segment));
            if (segment.nsects > (command.cmdsize - sizeof(segment)) / sizeof(struct section_64)) return NULL;
            if (!strncmp(segment.segname, "__LINKEDIT", sizeof(segment.segname))) {
                if (linkedit_found) return NULL;
                linkedit = segment; linkedit_found = true;
            }
        }
        cursor += command.cmdsize; remaining -= command.cmdsize;
    }
    if (remaining) return NULL;
    *result = CACHE_SYMBOL_MISSING;
    if (!table_found || !linkedit_found || !table.nsyms) return NULL;
    *result = CACHE_SYMBOL_INVALID;
    uintptr_t base;
    uint64_t nlist_size = (uint64_t)table.nsyms * sizeof(struct nlist_64);
    if (!(linkedit.initprot & VM_PROT_READ) || table.symoff < linkedit.fileoff ||
        table.stroff < linkedit.fileoff || !slid_address(linkedit.vmaddr, slide, &base) ||
        base < (uintptr_t)cache || !cache_range(cache_size, base - (uintptr_t)cache, linkedit.vmsize)) return NULL;
    uint64_t nlists = table.symoff - linkedit.fileoff, strings = table.stroff - linkedit.fileoff;
    if (!cache_range(linkedit.filesize, nlists, nlist_size) ||
        !cache_range(linkedit.vmsize, nlists, nlist_size) ||
        !cache_range(linkedit.filesize, strings, table.strsize) ||
        !cache_range(linkedit.vmsize, strings, table.strsize) ||
        !cache_disjoint(nlists, nlist_size, strings, table.strsize)) return NULL;
    CacheSymbol symbol;
    *result = cache_nlist_symbol((const void *)(base + nlists), (size_t)nlist_size,
                                 (const void *)(base + strings), table.strsize, name, &symbol);
    if (*result != CACHE_SYMBOL_FOUND) return NULL;
    void *function = cache_symbol_function(&symbol, image, length, slide);
    if (!function) *result = CACHE_SYMBOL_INVALID;
    return function;
}

typedef const void *(*CacheRange)(size_t *);
typedef bool (*CacheUUID)(unsigned char *);
typedef const char *(*CachePath)(void);
typedef struct { CacheRange range; CacheUUID uuid; CachePath path; } CacheRuntime;

static inline CacheRuntime cache_runtime(void) {
    return (CacheRuntime){
        .range = (CacheRange)dlsym(RTLD_DEFAULT, "_dyld_get_shared_cache_range"),
        .uuid = (CacheUUID)dlsym(RTLD_DEFAULT, "_dyld_get_shared_cache_uuid"),
        .path = (CachePath)dlsym(RTLD_DEFAULT, "dyld_shared_cache_file_path")};
}

#if KEYSTORE_SYMBOL_TARGET
typedef struct {
    bool checked, available, file_checked;
    const void *base;
    size_t size;
    CacheHeader header;
    const char *path;
    CacheSymbolsFile file;
    unsigned live_resolved, file_resolved;
    const char *error;
} CacheLookup;
static CacheLookup cache_lookup;

static void *shared_cache_symbol(const void *header, size_t length, intptr_t slide, const char *name) {
    if (!cache_lookup.checked) {
        cache_lookup.checked = true;
        CacheRuntime runtime = cache_runtime();
        unsigned char current_uuid[16];
        cache_lookup.error = "shared_cache_api_unavailable";
        if (!runtime.range || !runtime.uuid) return NULL;
        cache_lookup.base = runtime.range(&cache_lookup.size);
        cache_lookup.path = runtime.path ? runtime.path() : NULL;
        cache_lookup.error = "shared_cache_identity_unavailable";
        if (!cache_lookup.base || !runtime.uuid(current_uuid) ||
            !cache_header(cache_lookup.base, cache_lookup.size, &cache_lookup.header) ||
            memcmp(cache_lookup.header.uuid, current_uuid, 16)) return NULL;
        cache_lookup.available = true;
        cache_lookup.error = NULL;
    }
    if (!cache_lookup.available || (uintptr_t)header < (uintptr_t)cache_lookup.base) return NULL;
    uint64_t offset = (uintptr_t)header - (uintptr_t)cache_lookup.base;
    if (!cache_range(cache_lookup.size, offset, length)) return NULL;
    CacheSymbolResult result;
    void *function = live_cache_symbol(header, length, slide, cache_lookup.base, cache_lookup.size, name, &result);
    if (function) { cache_lookup.live_resolved++; return function; }
    if (!cache_lookup.file_checked) {
        cache_lookup.file_checked = true;
        find_cache_symbols(cache_lookup.path, &cache_lookup.header,
                            &cache_lookup.file, &cache_lookup.error);
    }
    if (!cache_lookup.file.mapping) return NULL;
    function = cache_image_symbol(&cache_lookup.file.symbols, offset, header, length, slide, name, &result);
    if (function) cache_lookup.file_resolved++;
    if (result == CACHE_SYMBOL_INVALID) cache_lookup.error = "cache_local_symbols_invalid";
    return function;
}
#endif
#endif

static void *mapped_keystore_symbol(const char *name) {
#if KEYSTORE_SYMBOL_TARGET
    // Reuse the endpoint's platform helpers and inspect the build once, only
    // after a normal lookup fails. Other hosts keep the ordinary lookup path.
    static bool checked, supported, discovery;
    if (!checked) {
        supported = symbol_map_supported(system_value("kern.osversion").UTF8String,
                                         process_architecture().UTF8String);
        discovery = cache_discovery_supported(system_value("kern.osproductversion").UTF8String,
                                              system_value("kern.osversion").UTF8String,
                                              process_architecture().UTF8String);
        checked = true;
    }
    if (!supported && !discovery) return NULL;
    const MappedSymbol *symbol = find_symbol(name);
    if (!symbol) return NULL;
    // Called from the endpoint's serial request loop; retain handles for the
    // process lifetime so a returned function address cannot become unmapped.
    enum { image_count = sizeof(keystore_images) / sizeof(*keystore_images) };
    static void *handles[image_count + 1];
    // Prefer exports in every candidate before using any private symbol.
    for (unsigned pass = 0; pass <= image_count; pass++) {
        unsigned index = pass < image_count ? (symbol->image + pass) % image_count : image_count;
        const char *path = index < image_count ? keystore_images[index].path : keystore_path();
        if (!handles[index]) handles[index] = dlopen(path, RTLD_LAZY | RTLD_LOCAL);
        void *exported = handles[index] ? dlsym(handles[index], name) : NULL;
        if (exported) return exported;
    }
    for (unsigned pass = 0; pass <= image_count; pass++) {
        unsigned index = pass < image_count ? (symbol->image + pass) % image_count : image_count;
        if (!handles[index]) continue;
        const char *path = index < image_count ? keystore_images[index].path : keystore_path();
        for (uint32_t i = 0; i < _dyld_image_count(); i++) {
            const char *loaded = _dyld_get_image_name(i);
            if (!loaded || strcmp(loaded, path)) continue;
            const struct mach_header_64 *header = (const void *)_dyld_get_image_header(i);
            // dyld owns these headers; bound metadata before either resolver.
            if (!header || header->sizeofcmds > 1024 * 1024) return NULL;
            size_t length = sizeof(*header) + header->sizeofcmds;
            intptr_t slide = _dyld_get_image_vmaddr_slide(i);
            void *function = supported && index == symbol->image
                ? image_symbol(header, length, (uintptr_t)header, slide, symbol) : NULL;
            if (!function && discovery) function = shared_cache_symbol(header, length, slide, name);
            if (function) return function;
            break;
        }
    }
#else
    (void)name;
#endif
    return NULL;
}

static void *required_symbol(void *library, const char *name,
                             NSMutableArray<NSString *> *missing,
                             SymbolResolver resolve, SymbolFallback fallback) {
    void *symbol = library ? resolve(library, name) : NULL;
    if (!symbol && fallback) symbol = fallback(name);
    if (!symbol) [missing addObject:@(name)];
    return symbol;
}

static void *keystore_library(void) {
    return dlopen(keystore_path(), RTLD_LAZY | RTLD_LOCAL);
}

static NSMutableArray<NSString *> *load_keystore(KeyStore *keys, void *library,
                                                SymbolResolver resolve, SymbolFallback fallback) {
    NSMutableArray<NSString *> *missing = [NSMutableArray array];
#define LOAD(TYPE, NAME, SYMBOL) keys->NAME = (TYPE)required_symbol(library, SYMBOL, missing, resolve, fallback)
    LOAD(CreateBag, create_bag, "aks_create_bag");
    LOAD(UnloadBag, unload_bag, "aks_unload_bag");
    LOAD(CreateKey, create_key, "aks_create_signing_key");
    LOAD(CreateKeyParams, create_key_params, "aks_create_signing_key_with_params");
    LOAD(SignKey, sign_key, "aks_sign_signing_key");
    LOAD(ParamsCreate, params_create, "aks_params_create");
    LOAD(ParamsData, params_data, "aks_params_set_data");
    LOAD(ParamsNumber, params_number, "aks_params_set_number");
    LOAD(ParamsDER, params_der, "aks_params_get_der");
    LOAD(RemoteSession, remote_session, "aks_remote_session");
    LOAD(RemoteStep, remote_step, "aks_remote_session_step");
    LOAD(ResetSession, reset_session, "aks_remote_session_reset");
    LOAD(RemoteOutput, session_token, "aks_remote_session_token");
    LOAD(RemoteOutput, peer_confirm, "aks_remote_peer_confirm");
    LOAD(RemoteStep, peer_setup, "aks_remote_peer_setup");
    LOAD(ValidateKey, validate_key, "aks_validate_local_key");
    LOAD(PeerState, peer_state, "aks_remote_peer_get_state");
    LOAD(PeerDrop, peer_drop, "aks_remote_peer_drop");
#undef LOAD
#define OPTIONAL(TYPE, NAME, SYMBOL) do { \
        void *found = library ? resolve(library, SYMBOL) : NULL; \
        if (!found && fallback) found = fallback(SYMBOL); \
        keys->NAME = (TYPE)found; \
    } while (0)
    OPTIONAL(SaveBag, save_bag, "aks_save_bag");
    OPTIONAL(LoadBag, load_bag, "aks_load_bag");
    OPTIONAL(UnlockBag, unlock_bag, "aks_unlock_bag");
#undef OPTIONAL
    return missing;
}

static BOOL persistence_available(const KeyStore *keys) {
    return keys->save_bag && keys->load_bag && keys->unlock_bag;
}

// Copies (and optionally first requests) the bridge's device certificate.
// On success *certificate is set and the result describes it; otherwise the
// result carries the failure code and *certificate stays nil.
static NSDictionary *copy_certificate(BOOL issue, NSString *replace_digest, NSData **certificate) {
    *certificate = nil;
    diagnostic(@{@"operation": issue ? @"issue_certificate" : @"export_certificate", @"stage": @"begin"});
#if TARGET_OS_IPHONE
    void *ma = dlopen("/System/Library/PrivateFrameworks/MobileActivation.framework/MobileActivation", RTLD_LAZY | RTLD_LOCAL);
    typedef NSData *(*CopyDCRT)(NSError *__autoreleasing *);
    CopyDCRT copy = ma ? (CopyDCRT)dlsym(ma, "MAECopyDCRTWithError") : NULL;
    diagnostic(@{@"stage": @"resolve_certificate_api", @"framework_loaded": @(ma != NULL), @"copy_available": @(copy != NULL)});
    if (!copy) return @{@"error": @"certificate_api_unavailable"};
    if (issue) {
        typedef void (*IssueDCRT)(NSDictionary *, void *, void (^)(NSError *));
        IssueDCRT request = (IssueDCRT)dlsym(ma, "MAEIssueDCRTWithCallback");
        diagnostic(@{@"stage": @"resolve_issuance_api", @"issue_available": @(request != NULL)});
        if (!request) return @{@"error": @"certificate_issuance_api_unavailable"};
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        __block NSError *issue_error = nil;
        diagnostic(@{@"stage": @"MAEIssueDCRTWithCallback_call"});
        request(nil, NULL, ^(NSError *error) {
            issue_error = error;
            diagnostic(@{@"stage": @"MAEIssueDCRTWithCallback_result", @"error_code": @(error.code), @"error_domain": error.domain ?: @""});
            dispatch_semaphore_signal(done);
        });
        NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:40];
        BOOL completed = NO;
        while (deadline.timeIntervalSinceNow > 0) {
            // Service this thread's run loop for callbacks delivered there, and
            // block briefly instead of spinning when it has no input sources.
            if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 50 * NSEC_PER_MSEC)) == 0) { completed = YES; break; }
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
        }
        if (!completed || issue_error) {
            diagnostic(@{@"stage": @"issuance_failed", @"completed": @(completed), @"error_code": @(issue_error.code)});
            return @{@"error": @"certificate_issuance_failed", @"completed": @(completed),
                     @"error_code": @(issue_error.code), @"error_domain": issue_error.domain ?: @""};
        }
    }
    NSDate *refresh_deadline = replace_digest ? [NSDate dateWithTimeIntervalSinceNow:12] : nil;
    NSError *error = nil;
    BOOL unchanged = NO;
    for (;;) {
        error = nil;
        diagnostic(@{@"stage": @"MAECopyDCRTWithError_call"});
        NSData *data = copy(&error);
        NSUInteger size = [data isKindOfClass:NSData.class] ? data.length : 0;
        diagnostic(@{@"stage": @"MAECopyDCRTWithError_result", @"bytes": @(size),
                     @"error_code": @(error.code), @"error_domain": error.domain ?: @""});
        if (size && size <= 1048576) {
            NSString *sha256 = digest(data);
            if (![sha256 isEqualToString:replace_digest]) {
                *certificate = data;
                return @{@"certificate_exported": @YES, @"bytes": @(size), @"sha256": sha256,
                         @"issuance_requested": @(issue)};
            }
            unchanged = YES;
        }
        // A successful issuance callback can precede the cache update. Read
        // again within the same request, without requesting another issuance.
        if (!refresh_deadline || refresh_deadline.timeIntervalSinceNow <= 0) break;
        [NSThread sleepForTimeInterval:1];
    }
    if (unchanged) return @{@"error": @"certificate_unchanged", @"completed": @YES};
    return @{@"error": @"cached_certificate_unavailable", @"error_code": @(error.code),
             @"error_domain": error.domain ?: @""};
#else
    (void)issue;
    (void)replace_digest;
    return @{@"error": @"certificate_export_requires_ios_backend"};
#endif
}

static int export_certificate(const char *output, BOOL issue) {
    struct stat info;
    if (lstat(output, &info) == 0) { reply(@{@"error": @"output_already_exists"}); return 1; }
    NSData *data = nil;
    NSDictionary *result = copy_certificate(issue, nil, &data);
    if (!data) { reply(result); return 1; }
    int fd = open(output, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) { reply(@{@"error": @"certificate_output_unavailable"}); return 1; }
    const uint8_t *bytes = data.bytes;
    size_t written = 0;
    while (written < data.length) {
        ssize_t count = write(fd, bytes + written, data.length - written);
        if (count <= 0) { close(fd); unlink(output); reply(@{@"error": @"certificate_write_failed"}); return 1; }
        written += (size_t)count;
    }
    close(fd);
    diagnostic(@{@"stage": @"certificate_file_written", @"bytes": @(written), @"issuance_requested": @(issue)});
    reply(result);
    return 0;
}

static NSDictionary *generate_identity(const KeyStore *keys, NSData *dcrt, BOOL attested,
                                      int key_class, NSMutableDictionary *identities) {
    uint8_t passcode[32];
    int status = SecRandomCopyBytes(kSecRandomDefault, sizeof(passcode), passcode);
    if (status != 0) {
        NSMutableDictionary *response = result(status);
        response[@"operation_stage"] = @"SecRandomCopyBytes";
        return response;
    }
    int bag = -1;
    NSString *stage = @"aks_create_bag";
    NSString *error = nil;
    status = keys->create_bag(passcode, sizeof(passcode), 0, &bag);
    // A saved keybag is unlocked with its passcode when a Mac reconnects.
    NSData *bag_passcode = [NSData dataWithBytes:passcode length:sizeof(passcode)];
    volatile uint8_t *secret = passcode;
    for (size_t i = 0; i < sizeof(passcode); i++) secret[i] = 0;
    void *blob = NULL;
    size_t size = 0;
    if (status == 0 && bag < 0) error = @"invalid_keybag_result";
    if (status == 0 && !error) {
        if (!attested) {
            stage = @"aks_create_signing_key";
            status = keys->create_key(bag, key_class, &blob, &size);
        } else {
            stage = @"aks_params_create";
            void *params = keys->params_create(NULL, 0);
            int64_t flag = 4;
            const void *der = NULL;
            size_t der_size = 0;
            if (!params) error = @"keystore_parameters_unavailable";
            if (!error) {
                stage = @"aks_params_set_data";
                status = keys->params_data(params, 21, dcrt.bytes, dcrt.length);
            }
            if (status == 0 && !error) {
                stage = @"aks_params_set_number";
                status = keys->params_number(params, 20, &flag);
            }
            if (status == 0 && !error) {
                stage = @"aks_params_get_der";
                status = keys->params_der(params, &der, &der_size);
                if (status == 0 && (!der || !der_size)) error = @"keystore_parameters_invalid";
            }
            if (status == 0 && !error) {
                stage = @"aks_create_signing_key_with_params";
                status = keys->create_key_params(bag, key_class, der, der_size, &blob, &size);
            }
        }
    }
    NSMutableDictionary *response = result(status);
    response[@"operation_stage"] = stage;
    if (status == 0 && !error && blob && size && size <= 65536) {
        NSString *identifier = NSUUID.UUID.UUIDString;
        NSData *ltk = [NSData dataWithBytes:blob length:size];
        identities[identifier] = @{@"bag": @(bag), @"ltk": ltk, @"attested": @(attested), @"key_class": @(key_class),
                                   @"identifier": identifier, @"passcode": bag_passcode,
                                   @"created": @((long long)time(NULL))};
        response[@"identity"] = identifier;
        response[@"ltk"] = [ltk base64EncodedStringWithOptions:0];
        response[@"bytes"] = @(size);
        response[@"key_class"] = @(key_class);
    } else {
        if (status == 0) response[@"error"] = error ?: @"invalid_signing_key_result";
        if (bag >= 0) keys->unload_bag(bag);
    }
    clear_blob(blob, size);
    return response;
}

// A WebSocket owns its keybags and AKS sessions. Saved clients can retain
// established pairing state when the connection closes.
static NSMutableDictionary *new_bridge_session(NSData *dcrt) {
    return [@{@"dcrt": dcrt ?: [NSData data], @"identities": [NSMutableDictionary dictionary],
              @"sessions": [NSMutableSet set], @"remote_owners": [NSMutableDictionary dictionary],
              @"session_kinds": [NSMutableDictionary dictionary]} mutableCopy];
}

// A saved Mac's loaded keybags and AKS sessions, kept while the service runs.
// The iPhone pairing secret lives in the pairing session, not in the saved
// keybag: resetting that session (or unloading its keybag) makes the iPhone
// ignore unlock requests until it pairs again and asks for its passcode.
static NSMutableDictionary<NSString *, NSMutableDictionary *> *client_states;

// Unlock sessions (low flag bits 2, 8 or 12) are disposable once finished;
// pairing sessions (0x8a, 0x81, ...) hold the paired peer and are kept.
static BOOL unlock_session_flags(unsigned int flags) {
    unsigned int kind = flags & 0x3f;
    return kind == 2 || kind == 8 || kind == 12;
}

static BOOL pairing_session_flags(unsigned int flags) {
    unsigned int kind = flags & 0x3f;
    return kind == 1 || kind == 10;
}

// Free AKS session slots by resetting the oldest unlock sessions.
static void prune_unlock_sessions(NSMutableSet<NSNumber *> *sessions, NSMutableDictionary *kinds,
                                  const KeyStore *keys, NSUInteger keep) {
    NSMutableArray<NSNumber *> *unlock = [NSMutableArray array];
    for (NSNumber *session in sessions) {
        NSDictionary *kind = kinds[session];
        if (kind && unlock_session_flags([kind[@"flags"] unsignedIntValue])) [unlock addObject:session];
    }
    [unlock sortUsingComparator:^NSComparisonResult(NSNumber *a, NSNumber *b) {
        return [kinds[a][@"order"] compare:kinds[b][@"order"]];
    }];
    while (unlock.count > keep) {
        NSNumber *oldest = unlock.firstObject;
        [unlock removeObjectAtIndex:0];
        if (keys->reset_session(oldest.intValue) == 0) {
            [sessions removeObject:oldest];
            [kinds removeObjectForKey:oldest];
        }
    }
}

static void prune_saved_pairing_sessions(NSMutableSet<NSNumber *> *sessions, NSMutableDictionary *kinds,
                                        const KeyStore *keys, BOOL disconnected) {
    NSMutableDictionary<NSArray *, NSDictionary *> *latest = [NSMutableDictionary dictionary];
    for (NSNumber *session in sessions) {
        NSDictionary *kind = kinds[session];
        NSArray *peer = kind[@"peer"];
        if (peer && [kind[@"confirmed"] boolValue] &&
            [kind[@"order"] unsignedLongLongValue] > [latest[peer][@"order"] unsignedLongLongValue]) {
            latest[peer] = kind;
        }
    }
    for (NSNumber *session in [sessions copy]) {
        NSDictionary *kind = kinds[session];
        NSArray *peer = kind[@"peer"];
        if (!peer) continue;
        BOOL confirmed = [kind[@"confirmed"] boolValue];
        BOOL superseded = confirmed && [kind[@"order"] unsignedLongLongValue] <
            [latest[peer][@"order"] unsignedLongLongValue];
        // A different peer, identity, or pairing kind is independent. A
        // pending attempt on a live connection can still complete.
        if ((superseded || (disconnected && !confirmed)) && keys->reset_session(session.intValue) == 0) {
            [sessions removeObject:session];
            [kinds removeObjectForKey:session];
        }
    }
}

static void release_client_state(NSMutableDictionary *state, const KeyStore *store) {
    for (NSNumber *session in state[@"sessions"]) store->reset_session(session.intValue);
    for (NSDictionary *identity in [state[@"identities"] allValues]) store->unload_bag([identity[@"bag"] intValue]);
    [state[@"sessions"] removeAllObjects];
    [state[@"identities"] removeAllObjects];
    [state[@"remote_owners"] removeAllObjects];
    [state[@"session_kinds"] removeAllObjects];
}

// Defined with the network service: saves a known Mac's keybags and pairing.
static void persist_client(NSMutableDictionary *bridge, const KeyStore *store);

static void close_bridge_session(NSMutableDictionary *bridge, const KeyStore *store) {
    if (!bridge || [bridge[@"closed"] boolValue]) return;
    persist_client(bridge, store);
    bridge[@"closed"] = @YES;
    if (bridge[@"client"] && client_states[bridge[@"client"]] && ![bridge[@"forgotten"] boolValue]) {
        prune_unlock_sessions(bridge[@"sessions"], bridge[@"session_kinds"], store, 0);
        prune_saved_pairing_sessions(bridge[@"sessions"], bridge[@"session_kinds"], store, YES);
        [bridge removeObjectForKey:@"connection"];
        return;
    }
    NSMutableSet<NSNumber *> *sessions = bridge[@"sessions"];
    NSMutableDictionary<NSString *, NSDictionary *> *identities = bridge[@"identities"];
    for (NSNumber *session in sessions) store->reset_session(session.intValue);
    for (NSDictionary *identity in identities.allValues) store->unload_bag([identity[@"bag"] intValue]);
    [sessions removeAllObjects];
    [identities removeAllObjects];
    [bridge[@"remote_owners"] removeAllObjects];
    [bridge[@"session_kinds"] removeAllObjects];
    [bridge removeObjectForKey:@"connection"];
}

// Defined with the network service: a saved Mac's record and the Settings entry.
static NSString *client_path(NSString *client);
static void publish_preferences(void);

static NSDictionary *bridge_request(NSMutableDictionary *bridge, const KeyStore *store,
                                    NSDictionary *request, BOOL *close) {
    KeyStore keys = *store;
    NSData *dcrt = bridge[@"dcrt"];
    NSMutableDictionary<NSString *, NSDictionary *> *identities = bridge[@"identities"];
    NSMutableSet<NSNumber *> *sessions = bridge[@"sessions"];
    NSMutableDictionary<NSString *, NSDictionary *> *remote_owners = bridge[@"remote_owners"];
        NSString *operation = request[@"operation"];
        if ([operation isEqual:@"exit"]) {
            *close = YES;
            return @{@"closed": @YES};
        }
        if ([operation isEqual:@"generate"]) {
            BOOL attested = [request[@"attested"] boolValue];
            int key_class = request[@"key_class"] ? [request[@"key_class"] intValue] : 9;
            if (key_class != 9 && key_class != 10 && key_class != 11) {
                return @{@"error": @"invalid_key_class"};
            }
            if (identities.count >= 8 || (attested && !dcrt.length)) {
                return @{@"error": @"identity_limit_or_missing_dcrt"};
            }
            NSDictionary *generated = generate_identity(&keys, dcrt, attested, key_class, identities);
            if ([generated[@"status"] intValue] == 0 && generated[@"identity"]) persist_client(bridge, store);
            return generated;
        }
        if ([operation isEqual:@"forget"]) {
            // Reset: drop this Mac's saved keys, pairing sessions and record so
            // iPhone Mirroring pairs from scratch. Other saved Macs are untouched.
            // Closing the forgotten session resets its AKS sessions and unloads
            // its keybags instead of keeping them for a reconnect.
            NSString *client = bridge[@"client"];
            if (!client) return @{@"error": @"client_not_saved"};
            bridge[@"forgotten"] = @YES;
            [client_states removeObjectForKey:client];
            BOOL removed = unlink(client_path(client).fileSystemRepresentation) == 0 || errno == ENOENT;
            publish_preferences();
            *close = YES;
            return removed ? @{@"status": @0, @"forgotten": @YES} : @{@"error": @"client_record_not_removed"};
        }
        if ([operation isEqual:@"identities"]) {
            // Keys restored for this Mac, so its broker recognizes sharingd's saved keys.
            NSMutableArray *list = [NSMutableArray array];
            for (NSDictionary *identity in identities.allValues) {
                [list addObject:@{@"identity": identity[@"identifier"],
                                  @"ltk": [identity[@"ltk"] base64EncodedStringWithOptions:0],
                                  @"key_class": identity[@"key_class"], @"attested": identity[@"attested"],
                                  @"created": identity[@"created"] ?: @0}];
            }
            return @{@"status": @0, @"identities": list, @"persistent": @(bridge[@"client"] != nil)};
        }
        if ([operation isEqual:@"validate"]) {
            NSDictionary *identity = identities[request[@"identity"] ?: @""];
            if (!identity) {
                return @{@"error": @"identity_not_owned"};
            }
            NSData *key = identity[@"ltk"];
            NSMutableDictionary *response = result(keys.validate_key([identity[@"bag"] intValue], [identity[@"key_class"] intValue], key.bytes, key.length));
            response[@"operation_stage"] = @"aks_validate_local_key";
            return response;
        }
        if ([operation isEqual:@"get_state"] || [operation isEqual:@"drop"]) {
            NSString *encoded = request[@"data"];
            NSDictionary *identity = remote_owners[encoded ?: @""];
            NSData *key = [encoded isKindOfClass:NSString.class] ? [[NSData alloc] initWithBase64EncodedString:encoded options:0] : nil;
            if (!identity || !key.length) {
                return @{@"error": @"remote_key_not_owned"};
            }
            if ([operation isEqual:@"drop"]) {
                int status = keys.peer_drop([identity[@"bag"] intValue], key.bytes, key.length);
                if (status == 0) {
                    [remote_owners removeObjectForKey:encoded];
                    persist_client(bridge, store);
                }
                return result(status);
            } else {
                uint8_t state[104] = {0};
                int status = keys.peer_state([identity[@"bag"] intValue], key.bytes, key.length, state);
                NSMutableDictionary *response = result(status);
                response[@"data"] = [[NSData dataWithBytes:state length:sizeof(state)] base64EncodedStringWithOptions:0];
                response[@"bytes"] = @(sizeof(state));
                return response;
            }
        }
        if ([operation isEqual:@"session"] || [operation isEqual:@"session_signed"] || [operation isEqual:@"sign_remote"]) {
            NSDictionary *identity = identities[request[@"identity"] ?: @""];
            NSString *encoded = request[@"remote_ltk"];
            NSData *remote = [encoded isKindOfClass:NSString.class] ? [[NSData alloc] initWithBase64EncodedString:encoded options:0] : nil;
            if (!identity || !remote.length || remote.length > 65536 ||
                (![operation isEqual:@"sign_remote"] && sessions.count >= 16)) {
                return @{@"error": @"invalid_identity_key_or_session_limit"};
            }
            NSData *local = identity[@"ltk"];
            unsigned int flags = [request[@"flags"] unsignedIntValue];
            NSString *params_encoded = request[@"parameters"];
            NSData *session_params = nil;
            if ([params_encoded isKindOfClass:NSString.class] && params_encoded.length) {
                session_params = [[NSData alloc] initWithBase64EncodedString:params_encoded options:0];
                if (!session_params) return @{@"error": @"invalid_request_fields"};
            }
            if (session_params.length > 65536) {
                return @{@"error": @"parameters_too_large"};
            }
            int remote_class = request[@"remote_key_class"] ? [request[@"remote_key_class"] intValue] : 9;
            if (remote_class != 9 && remote_class != 10 && remote_class != 11) {
                return @{@"error": @"invalid_remote_key_class"};
            }
            void *signed_key = NULL;
            size_t signed_size = 0;
            int sign_status = 0;
            if ([operation isEqual:@"session_signed"]) {
                if (remote_owners[encoded] != identity) {
                    return @{@"error": @"signed_remote_key_not_owned"};
                }
                signed_size = remote.length;
                signed_key = malloc(signed_size);
                if (!signed_key) {
                    return result((int)0xe00002bd);
                }
                memcpy(signed_key, remote.bytes, signed_size);
            } else {
                sign_status = keys.sign_key([identity[@"bag"] intValue], [identity[@"key_class"] intValue],
                                       local.bytes, local.length, remote_class, remote.bytes, remote.length,
                                       &signed_key, &signed_size);
                if (sign_status == 0 && signed_key && signed_size && signed_size <= 65536)
                    remote_owners[[[NSData dataWithBytes:signed_key length:signed_size] base64EncodedStringWithOptions:0]] = identity;
            }
            if (sign_status == 0 && (!signed_key || !signed_size || signed_size > 65536)) {
                clear_blob(signed_key, signed_size);
                return invalid_native_result(@"invalid_signed_key_result", @"aks_sign_signing_key");
            }
            if ([operation isEqual:@"sign_remote"]) {
                if (sign_status == 0) persist_client(bridge, store);
                NSMutableDictionary *response = result(sign_status);
                if (sign_status == 0 && signed_key && signed_size) {
                    response[@"data"] = [[NSData dataWithBytes:signed_key length:signed_size] base64EncodedStringWithOptions:0];
                    response[@"bytes"] = @(signed_size);
                }
                clear_blob(signed_key, signed_size);
                return response;
            }
            int session = -1;
            int status = sign_status;
            NSMutableDictionary *kinds = bridge[@"session_kinds"];
            if (sign_status == 0 && signed_key && signed_size) {
                status = keys.remote_session([identity[@"bag"] intValue], flags,
                                        local.bytes, local.length, signed_key, signed_size,
                                        session_params.bytes, session_params.length, &session);
                if (status == (int)0xe00002bd) {
                    prune_unlock_sessions(sessions, kinds, &keys, 0);
                    if (bridge[@"client"]) prune_saved_pairing_sessions(sessions, kinds, &keys, NO);
                    session = -1;
                    status = keys.remote_session([identity[@"bag"] intValue], flags,
                                            local.bytes, local.length, signed_key, signed_size,
                                            session_params.bytes, session_params.length, &session);
                }
            }
            NSMutableDictionary *response = result(status);
            response[@"sign_status_hex"] = [NSString stringWithFormat:@"0x%08x", sign_status];
            response[@"signed_bytes"] = @(signed_size);
            if (status == 0 && session >= 0) {
                if (unlock_session_flags(flags)) prune_unlock_sessions(sessions, kinds, &keys, 2);
                static unsigned long long order;
                NSMutableDictionary *kind = [@{@"flags": @(flags), @"order": @(++order)} mutableCopy];
                if (bridge[@"client"] && pairing_session_flags(flags)) {
                    NSData *signed_peer = [NSData dataWithBytesNoCopy:signed_key length:signed_size freeWhenDone:NO];
                    kind[@"peer"] = @[identity[@"identifier"], digest(signed_peer), @(flags)];
                }
                kinds[@(session)] = kind;
                [sessions addObject:@(session)];
                response[@"session"] = @(session);
            } else if (status == 0) {
                [response addEntriesFromDictionary:invalid_native_result(@"invalid_session_handle", @"aks_remote_session")];
            }
            clear_blob(signed_key, signed_size);
            return response;
        }
        if ([operation isEqual:@"step"] || [operation isEqual:@"reset"] ||
            [operation isEqual:@"token"] || [operation isEqual:@"confirm"] || [operation isEqual:@"setup"]) {
            NSNumber *session = request[@"session"];
            if (!session || ![sessions containsObject:session]) {
                return @{@"error": @"session_not_owned"};
            }
            if ([operation isEqual:@"reset"]) {
                NSDictionary *reset = reset_owned_session(sessions, session, keys.reset_session);
                if (![sessions containsObject:session]) [bridge[@"session_kinds"] removeObjectForKey:session];
                return reset;
            }
            NSString *encoded = request[@"data"];
            NSData *input = nil;
            if ([encoded isKindOfClass:NSString.class] && encoded.length) {
                input = [[NSData alloc] initWithBase64EncodedString:encoded options:0];
                if (!input) return @{@"error": @"invalid_request_fields"};
            }
            if (input.length > 65536) {
                return @{@"error": @"token_too_large"};
            }
            void *output = NULL;
            size_t size = 0;
            int status;
            if ([operation isEqual:@"token"])
                status = keys.session_token(session.intValue, &output, &size);
            else if ([operation isEqual:@"confirm"])
                status = keys.peer_confirm(session.intValue, &output, &size);
            else if ([operation isEqual:@"setup"])
                status = keys.peer_setup(session.intValue, input.bytes, input.length, &output, &size);
            else
                status = keys.remote_step(session.intValue, input.bytes, input.length, &output, &size);
            NSMutableDictionary *response = result(status);
            // Empty output is permitted by step/setup/confirmation.
            // A nonzero length still requires a bounded native buffer.
            if (status == 0 && ((size && !output) || size > 65536)) {
                NSString *stage = [operation isEqual:@"token"] ? @"aks_remote_session_token" :
                    [operation isEqual:@"confirm"] ? @"aks_remote_peer_confirm" :
                    [operation isEqual:@"setup"] ? @"aks_remote_peer_setup" : @"aks_remote_session_step";
                response = invalid_native_result(@"invalid_session_output", stage);
            } else if (status == 0 && output && size) {
                NSData *data = [NSData dataWithBytes:output length:size];
                response[@"data"] = [data base64EncodedStringWithOptions:0];
            }
            response[@"bytes"] = @(size);
            clear_blob(output, size);
            // Confirmation and setup change the paired peer recorded in the keybag.
            if ([response[@"status"] intValue] == 0 &&
                ([operation isEqual:@"confirm"] || [operation isEqual:@"setup"])) {
                NSMutableDictionary *kind = bridge[@"session_kinds"][session];
                if (kind[@"peer"]) kind[@"confirmed"] = @YES;
                persist_client(bridge, store);
            }
            return response;
        }
        return @{@"error": @"unknown_operation"};
}

#ifndef MIRRA_BRIDGE_REVISION
#define MIRRA_BRIDGE_REVISION 0
#endif

static NSMutableDictionary *capability_report(void *library, KeyStore *keys, BOOL *available) {
    NSMutableArray<NSString *> *missing = load_keystore(keys, library, dlsym, mapped_keystore_symbol);
    *available = missing.count == 0;
    NSMutableDictionary *report = [@{@"protocol_version": @2, @"bridge_revision": @(MIRRA_BRIDGE_REVISION),
        @"required_symbols_available": @(*available), @"missing_symbols": missing,
        @"process_architecture": process_architecture(), @"minimum_ios": @"15.0",
        @"product_type": system_value("hw.machine"), @"os_build": system_value("kern.osversion"),
        @"os_version": system_value("kern.osproductversion"), @"end_to_end_verified": @NO} mutableCopy];
#if KEYSTORE_SYMBOL_TARGET
    if (cache_discovery_supported([report[@"os_version"] UTF8String],
                                  [report[@"os_build"] UTF8String],
                                  [report[@"process_architecture"] UTF8String])) {
        NSMutableDictionary *resolution = [@{@"shared_cache_discovery": @YES,
            @"cache_symbols_checked": @(cache_lookup.file_checked),
            @"cache_symbols_available": @(cache_lookup.file.mapping != NULL),
            @"loaded_symbols_resolved": @(cache_lookup.live_resolved),
            @"cache_file_symbols_resolved": @(cache_lookup.file_resolved)} mutableCopy];
        if (cache_lookup.error) resolution[@"error"] = @(cache_lookup.error);
        report[@"keystore_resolution"] = resolution;
    }
#endif
    if (!*available) {
        report[@"ready"] = @NO;
        report[@"error"] = library ? @"required_keystore_symbols_unavailable" : @"keystore_library_unavailable";
    }
    return report;
}

// ---------------------------------------------------------------------------
// Network service: TLS 1.2 ECDHE-PSK (ChaCha20-Poly1305) on one TCP port.
// The pre-shared key is derived from the pairing token shown in Settings, so
// only a Mac holding that token can complete the handshake. Stateless queries
// use HTTP/1.1; a keystore session uses one WebSocket connection.

#define MIRRA_MESSAGE_LIMIT 262144
#define MIRRA_HEADER_LIMIT 16384
#define MIRRA_BODY_LIMIT 4096
#define MIRRA_CONNECTION_LIMIT 16
#define MIRRA_SESSION_LIMIT 4
#define MIRRA_DEFAULT_PORT 47820
#define MIRRA_TOKEN_LENGTH 24
#define MIRRA_CLIENT_LIMIT 8
#define MIRRA_CLIENT_RECORD_LIMIT 1048576
static const char MIRRA_PSK_IDENTITY[] = "mirra-bridge-v1";
static const char MIRRA_PSK_CONTEXT[] = "mirra-bridge-psk-v1";
static const char MIRRA_TOKEN_ALPHABET[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
static const char MIRRA_WEBSOCKET_GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static dispatch_queue_t bridge_queue;
static KeyStore bridge_keys;
static BOOL bridge_available;
static NSDictionary *bridge_capabilities;
static NSString *bridge_directory;
static NSString *bridge_token;
static int bridge_port;
static NSUInteger bridge_connections;
static NSMutableArray<NSMutableDictionary *> *bridge_open_sessions;

// Crockford base32: case-insensitive, hyphens ignored, O->0 and I/L->1.
static NSString *normalized_token(NSString *value) {
    NSMutableString *token = [NSMutableString string];
    for (NSUInteger i = 0; i < value.length; i++) {
        unichar c = [value characterAtIndex:i];
        if (c == '-' || c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        if (c >= 'a' && c <= 'z') c = (unichar)(c - 'a' + 'A');
        if (c == 'O') c = '0';
        if (c == 'I' || c == 'L') c = '1';
        if (c > 127 || !strchr(MIRRA_TOKEN_ALPHABET, (int)c) || c == 0) return nil;
        [token appendFormat:@"%C", c];
    }
    return token.length == MIRRA_TOKEN_LENGTH ? token : nil;
}

static NSString *display_token(NSString *token) {
    NSMutableArray<NSString *> *groups = [NSMutableArray array];
    for (NSUInteger i = 0; i < token.length; i += 4)
        [groups addObject:[token substringWithRange:NSMakeRange(i, 4)]];
    return [groups componentsJoinedByString:@"-"];
}

static NSString *certificate_path(void) {
    return [bridge_directory stringByAppendingPathComponent:@"certificate.der"];
}

static NSData *installed_certificate(void) {
    NSData *data = [NSData dataWithContentsOfFile:certificate_path()];
    return data.length && data.length <= 1048576 ? data : nil;
}

static BOOL write_private_file(NSString *path, NSData *data) {
    // Publish complete bytes with rename; a partial file never looks valid.
    NSString *temporary = [path stringByAppendingFormat:@".%@", NSUUID.UUID.UUIDString];
    int fd = open(temporary.fileSystemRepresentation, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return NO;
    const uint8_t *bytes = data.bytes;
    size_t written = 0;
    while (written < data.length) {
        ssize_t count = write(fd, bytes + written, data.length - written);
        if (count <= 0) { close(fd); unlink(temporary.fileSystemRepresentation); return NO; }
        written += (size_t)count;
    }
    if (fsync(fd) != 0) { close(fd); unlink(temporary.fileSystemRepresentation); return NO; }
    close(fd);
    if (rename(temporary.fileSystemRepresentation, path.fileSystemRepresentation) != 0) {
        unlink(temporary.fileSystemRepresentation);
        return NO;
    }
    return YES;
}

// ---------------------------------------------------------------------------
// Saved Macs. Each Mac sends a stable hardware identifier with its session.
// Its keybags (saved by AppleKeyStore, unlocked with their own random
// passcodes) and paired peers are kept in clients/<ID>.plist, so restarting
// Mirra or this service does not require pairing iPhone Mirroring again.
// The Settings entry lists these Macs and can remove one.

static void publish_preferences(void);

static NSString *clients_directory(void) {
    return [bridge_directory stringByAppendingPathComponent:@"clients"];
}

static NSString *valid_client_id(NSString *value) {
    if (![value isKindOfClass:NSString.class] || value.length < 8 || value.length > 64) return nil;
    NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:@"0123456789ABCDEFabcdef-"];
    if ([value rangeOfCharacterFromSet:allowed.invertedSet].location != NSNotFound) return nil;
    return value.uppercaseString;
}

static NSString *client_path(NSString *client) {
    return [clients_directory() stringByAppendingPathComponent:[client stringByAppendingPathExtension:@"plist"]];
}

static BOOL ensure_clients_directory(void) {
    NSString *directory = clients_directory();
    if (mkdir(directory.fileSystemRepresentation, 0700) != 0 && errno != EEXIST) return NO;
    struct stat info;
    return lstat(directory.fileSystemRepresentation, &info) == 0 && S_ISDIR(info.st_mode) &&
        info.st_uid == getuid() && !(info.st_mode & 077);
}

static NSDictionary *read_client(NSString *client) {
    struct stat info;
    NSString *path = client_path(client);
    if (lstat(path.fileSystemRepresentation, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_uid != getuid() || info.st_size > MIRRA_CLIENT_RECORD_LIMIT) return nil;
    NSData *data = [NSData dataWithContentsOfFile:path];
    id value = data ? [NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:NULL] : nil;
    return [value isKindOfClass:NSDictionary.class] ? value : nil;
}

static NSArray<NSString *> *saved_clients(void) {
    NSMutableArray<NSString *> *clients = [NSMutableArray array];
    for (NSString *name in [NSFileManager.defaultManager contentsOfDirectoryAtPath:clients_directory() error:NULL]) {
        if (![name.pathExtension isEqual:@"plist"]) continue;
        NSString *client = valid_client_id(name.stringByDeletingPathExtension);
        if (client && [client isEqual:name.stringByDeletingPathExtension]) [clients addObject:client];
    }
    return clients;
}

static NSString *client_name(NSString *value) {
    if (![value isKindOfClass:NSString.class]) return @"Mac";
    NSMutableString *name = [NSMutableString string];
    [value enumerateSubstringsInRange:NSMakeRange(0, value.length) options:NSStringEnumerationByComposedCharacterSequences
                           usingBlock:^(NSString *character, NSRange range, NSRange enclosing, BOOL *stop) {
        (void)range; (void)enclosing;
        if ([character rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location == NSNotFound) [name appendString:character];
        if (name.length >= 64) *stop = YES;
    }];
    NSString *trimmed = [name stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    return trimmed.length ? trimmed : @"Mac";
}

static void persist_client(NSMutableDictionary *bridge, const KeyStore *store) {
    NSString *client = bridge[@"client"];
    if (!client || [bridge[@"closed"] boolValue] || [bridge[@"forgotten"] boolValue] || !persistence_available(store)) return;
    NSDictionary *previous = read_client(client);
    NSDictionary *previous_identities = [previous[@"identities"] isKindOfClass:NSDictionary.class] ? previous[@"identities"] : [NSDictionary dictionary];
    // Keep entries that could not be loaded this time; Settings can remove the Mac.
    NSMutableDictionary *saved = [previous_identities mutableCopy];
    NSDictionary<NSString *, NSDictionary *> *identities = bridge[@"identities"];
    for (NSString *identifier in identities) {
        NSDictionary *identity = identities[identifier];
        if (![identity[@"passcode"] isKindOfClass:NSData.class]) continue;
        void *blob = NULL;
        int length = 0;
        int status = store->save_bag([identity[@"bag"] intValue], &blob, &length);
        if (status != 0 || !blob || length <= 0 || length > MIRRA_CLIENT_RECORD_LIMIT / 4) {
            clear_blob(blob, length > 0 ? (size_t)length : 0);
            bridge[@"persist_status"] = @(status ?: -1);
            continue;
        }
        NSData *bag = [NSData dataWithBytes:blob length:(NSUInteger)length];
        clear_blob(blob, (size_t)length);
        saved[identifier] = @{@"bag": bag, @"passcode": identity[@"passcode"], @"ltk": identity[@"ltk"],
                              @"key_class": identity[@"key_class"], @"attested": identity[@"attested"],
                              @"created": identity[@"created"] ?: @0};
    }
    NSMutableDictionary *owners = [NSMutableDictionary dictionary];
    if ([previous[@"remote_owners"] isKindOfClass:NSDictionary.class]) {
        // Owners of keys whose identity is not loaded now are carried over unchanged.
        for (NSString *encoded in previous[@"remote_owners"]) {
            NSString *identifier = previous[@"remote_owners"][encoded];
            if ([identifier isKindOfClass:NSString.class] && !identities[identifier]) owners[encoded] = identifier;
        }
    }
    NSDictionary<NSString *, NSDictionary *> *remote_owners = bridge[@"remote_owners"];
    for (NSString *encoded in remote_owners) {
        NSString *identifier = remote_owners[encoded][@"identifier"];
        if (identifier && saved[identifier]) owners[encoded] = identifier;
    }
    if (!saved.count && !previous) return;
    NSNumber *now = @((long long)time(NULL));
    NSDictionary *record = @{@"version": @1, @"client": client, @"name": bridge[@"client_name"] ?: @"Mac",
                             @"created": previous[@"created"] ?: now, @"last_seen": now,
                             @"identities": saved, @"remote_owners": owners};
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:record format:NSPropertyListBinaryFormat_v1_0
                                                            options:0 error:NULL];
    if (!data || data.length > MIRRA_CLIENT_RECORD_LIMIT || !ensure_clients_directory() ||
        !write_private_file(client_path(client), data)) {
        bridge[@"persist_status"] = @(-1);
        return;
    }
    if (!bridge[@"client_published"]) {
        bridge[@"client_published"] = @YES;
        publish_preferences();
    }
}

static void restore_client(NSMutableDictionary *bridge, const KeyStore *store) {
    NSDictionary *record = read_client(bridge[@"client"]);
    NSDictionary *saved = [record[@"identities"] isKindOfClass:NSDictionary.class] ? record[@"identities"] : nil;
    NSMutableDictionary *identities = bridge[@"identities"];
    NSUInteger restored = 0, failed = 0;
    for (NSString *identifier in saved) {
        NSDictionary *entry = saved[identifier];
        if (identities.count >= 8) break;
        if (![entry isKindOfClass:NSDictionary.class] || ![entry[@"bag"] isKindOfClass:NSData.class] ||
            ![entry[@"passcode"] isKindOfClass:NSData.class] || ![entry[@"ltk"] isKindOfClass:NSData.class] ||
            ![entry[@"key_class"] isKindOfClass:NSNumber.class]) { failed++; continue; }
        NSData *bag_data = entry[@"bag"], *passcode = entry[@"passcode"];
        int bag = -1;
        int status = store->load_bag(bag_data.bytes, (int)bag_data.length, &bag);
        if (status == 0 && bag >= 0) status = store->unlock_bag(bag, passcode.bytes, (int)passcode.length);
        if (status != 0 || bag < 0) {
            if (bag >= 0) store->unload_bag(bag);
            failed++;
            continue;
        }
        identities[identifier] = @{@"bag": @(bag), @"ltk": entry[@"ltk"], @"attested": entry[@"attested"] ?: @NO,
                                   @"key_class": entry[@"key_class"], @"identifier": identifier,
                                   @"passcode": passcode, @"created": entry[@"created"] ?: @0};
        restored++;
    }
    NSMutableDictionary *remote_owners = bridge[@"remote_owners"];
    if ([record[@"remote_owners"] isKindOfClass:NSDictionary.class]) {
        for (NSString *encoded in record[@"remote_owners"]) {
            NSDictionary *identity = identities[record[@"remote_owners"][encoded]];
            if (identity && [encoded isKindOfClass:NSString.class]) remote_owners[encoded] = identity;
        }
    }
    bridge[@"restored_identities"] = @(restored);
    bridge[@"restore_failures"] = @(failed);
}

__attribute__((unused)) static void forget_client(NSString *client) {
    for (NSMutableDictionary *bridge in [bridge_open_sessions copy]) {
        if (![bridge[@"client"] isEqual:client]) continue;
        bridge[@"forgotten"] = @YES;
        nw_connection_t connection = bridge[@"connection"];
        if (connection) nw_connection_cancel(connection);
    }
    NSMutableDictionary *state = client_states[client];
    if (state) {
        release_client_state(state, &bridge_keys);
        [client_states removeObjectForKey:client];
    }
    unlink(client_path(client).fileSystemRepresentation);
}

__attribute__((unused)) static CFStringRef preferences_user(void) {
    // Settings reads mobile's domain. A root service writes it explicitly;
    // a service running as mobile uses its own (current-user) domain.
    return getuid() == 0 ? CFSTR("mobile") : kCFPreferencesCurrentUser;
}

__attribute__((unused)) static void handle_forget_requests(void) {
#if TARGET_OS_IPHONE && !defined(MIRRA_NO_PREFERENCES)
    CFStringRef domain = CFSTR("com.mirra.bridge");
    CFPreferencesSynchronize(domain, preferences_user(), kCFPreferencesAnyHost);
    CFPropertyListRef value = CFPreferencesCopyValue(CFSTR("forget_clients"), domain, preferences_user(), kCFPreferencesAnyHost);
    NSArray *requests = CFBridgingRelease(value);
    if (![requests isKindOfClass:NSArray.class] || !requests.count) return;
    for (id request in requests) {
        NSString *client = valid_client_id(request);
        if (client) forget_client(client);
    }
    CFPreferencesSetValue(CFSTR("forget_clients"), NULL, domain, preferences_user(), kCFPreferencesAnyHost);
    CFPreferencesSynchronize(domain, preferences_user(), kCFPreferencesAnyHost);
    publish_preferences();
#endif
}

__attribute__((unused)) static NSArray<NSDictionary *> *client_summaries(void) {
    NSMutableArray *summaries = [NSMutableArray array];
    for (NSString *client in saved_clients()) {
        NSDictionary *record = read_client(client);
        if (!record) continue;
        BOOL active = NO;
        for (NSDictionary *bridge in bridge_open_sessions)
            if ([bridge[@"client"] isEqual:client] && ![bridge[@"closed"] boolValue]) active = YES;
        NSNumber *seen = [record[@"last_seen"] isKindOfClass:NSNumber.class] ? record[@"last_seen"] : @0;
        NSString *last = @"";
        if (seen.longLongValue > 0) {
            time_t when = (time_t)seen.longLongValue;
            struct tm parts;
            char text[32];
            if (localtime_r(&when, &parts) && strftime(text, sizeof(text), "%Y-%m-%d %H:%M", &parts)) last = @(text);
        }
        [summaries addObject:@{@"id": client, @"name": client_name(record[@"name"]), @"last_seen": last,
                               @"last_seen_time": seen, @"active": @(active)}];
    }
    [summaries sortUsingDescriptors:@[[NSSortDescriptor sortDescriptorWithKey:@"last_seen_time" ascending:NO]]];
    return summaries;
}

static NSString *load_or_create_token(void) {
    NSString *path = [bridge_directory stringByAppendingPathComponent:@"token"];
    NSString *saved = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:NULL];
    if (saved) return normalized_token(saved);  // A damaged token is never replaced silently.
    uint8_t random[MIRRA_TOKEN_LENGTH];
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(random), random) != 0) return nil;
    NSMutableString *token = [NSMutableString string];
    // 32 divides 256, so masking keeps every symbol equally likely.
    for (size_t i = 0; i < sizeof(random); i++) [token appendFormat:@"%c", MIRRA_TOKEN_ALPHABET[random[i] & 31]];
    volatile uint8_t *secret = random;
    for (size_t i = 0; i < sizeof(random); i++) secret[i] = 0;
    NSData *data = [[display_token(token) stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding];
    int fd = open(path.fileSystemRepresentation, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) return nil;
    BOOL complete = write(fd, data.bytes, data.length) == (ssize_t)data.length && fsync(fd) == 0;
    close(fd);
    if (!complete) { unlink(path.fileSystemRepresentation); return nil; }
    return token;
}

static NSData *pre_shared_key(NSString *token) {
    NSMutableData *material = [NSMutableData dataWithBytes:MIRRA_PSK_CONTEXT length:sizeof(MIRRA_PSK_CONTEXT)];
    [material appendData:[token dataUsingEncoding:NSUTF8StringEncoding]];
    NSMutableData *key = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(material.bytes, (CC_LONG)material.length, key.mutableBytes);
    [material resetBytesInRange:NSMakeRange(0, material.length)];
    return key;
}

__attribute__((unused)) static NSString *wifi_address(void) {
    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0) return @"";
    NSString *found = @"";
    for (struct ifaddrs *item = list; item; item = item->ifa_next) {
        if (!item->ifa_addr || item->ifa_addr->sa_family != AF_INET || !(item->ifa_flags & IFF_UP)) continue;
        if (strcmp(item->ifa_name, "en0")) continue;
        char text[INET_ADDRSTRLEN] = {0};
        const struct sockaddr_in *address = (const struct sockaddr_in *)(const void *)item->ifa_addr;
        if (inet_ntop(AF_INET, &address->sin_addr, text, sizeof(text))) { found = @(text); break; }
    }
    freeifaddrs(list);
    return found;
}

__attribute__((unused)) static NSString *service_status(void) {
    if (!bridge_available) return @"Keystore unavailable";
    return installed_certificate() ? @"Ready" : @"Waiting for Mac setup";
}

// Settings shows these values through the PreferenceLoader entry.
static void publish_preferences(void) {
#if TARGET_OS_IPHONE && !defined(MIRRA_NO_PREFERENCES)
    CFStringRef domain = CFSTR("com.mirra.bridge");
    CFStringRef user = preferences_user();
    NSArray *clients = client_summaries();
    NSDictionary *values = @{@"token": display_token(bridge_token), @"port": [NSString stringWithFormat:@"%d", bridge_port],
                             @"address": wifi_address(), @"status": service_status(), @"clients": clients,
                             @"client_count": [NSString stringWithFormat:@"%lu", (unsigned long)clients.count],
                             @"persistence": @(persistence_available(&bridge_keys))};
    for (NSString *key in values)
        CFPreferencesSetValue((__bridge CFStringRef)key, (__bridge CFPropertyListRef)values[key], domain,
                              user, kCFPreferencesAnyHost);
    CFPreferencesSynchronize(domain, user, kCFPreferencesAnyHost);
    // An open Settings page refreshes itself.
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         CFSTR("com.mirra.bridge.changed"), NULL, NULL, true);
#endif
}

static NSMutableDictionary *service_report(void) {
    NSMutableDictionary *report = [bridge_capabilities mutableCopy];
    [report removeObjectForKey:@"ready"];
    NSData *certificate = installed_certificate();
    report[@"service"] = @"mirra-bridge";
    report[@"certificate_available"] = @((BOOL)(certificate != nil));
    if (certificate) report[@"dcrt_sha256"] = digest(certificate);
    report[@"active_sessions"] = @(bridge_open_sessions.count);
    report[@"saved_macs"] = @(saved_clients().count);
    report[@"persistent_identities"] = @(persistence_available(&bridge_keys));
    return report;
}

static dispatch_data_t dispatch_bytes(NSData *data) {
    return dispatch_data_create(data.bytes, data.length, bridge_queue, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
}

static void http_reply(nw_connection_t connection, int status, NSString *type, NSData *body) {
    NSString *reason = status == 200 ? @"OK" : status == 101 ? @"Switching Protocols" : status == 400 ? @"Bad Request" :
        status == 404 ? @"Not Found" : status == 405 ? @"Method Not Allowed" : status == 409 ? @"Conflict" :
        status == 413 ? @"Payload Too Large" : status == 431 ? @"Request Header Fields Too Large" :
        status == 503 ? @"Service Unavailable" : @"Internal Server Error";
    NSString *head = [NSString stringWithFormat:@"HTTP/1.1 %d %@\r\nContent-Type: %@\r\nContent-Length: %lu\r\n"
                      "Cache-Control: no-store\r\nConnection: close\r\n\r\n", status, reason, type, (unsigned long)body.length];
    NSMutableData *data = [[head dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    [data appendData:body];
    nw_connection_send(connection, dispatch_bytes(data), NW_CONNECTION_FINAL_MESSAGE_CONTEXT, true, ^(nw_error_t error) {
        (void)error;
        nw_connection_cancel(connection);
    });
}

static void http_json(nw_connection_t connection, int status, NSDictionary *value) {
    NSData *body = [NSJSONSerialization dataWithJSONObject:value options:0 error:NULL] ?: [NSData data];
    http_reply(connection, status, @"application/json", body);
}

static void websocket_send(nw_connection_t connection, uint8_t opcode, NSData *payload, BOOL final) {
    NSMutableData *frame = [NSMutableData data];
    uint8_t head[10] = {(uint8_t)(0x80 | opcode)};
    size_t size = 2;
    if (payload.length < 126) {
        head[1] = (uint8_t)payload.length;
    } else if (payload.length <= 0xffff) {
        head[1] = 126; head[2] = (uint8_t)(payload.length >> 8); head[3] = (uint8_t)payload.length; size = 4;
    } else {
        head[1] = 127;
        for (int i = 0; i < 8; i++) head[2 + i] = (uint8_t)((uint64_t)payload.length >> (56 - 8 * i));
        size = 10;
    }
    [frame appendBytes:head length:size];
    [frame appendData:payload];
    nw_connection_send(connection, dispatch_bytes(frame), NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t error) {
        (void)error;
        if (final) nw_connection_cancel(connection);
    });
}

static void websocket_json(nw_connection_t connection, NSDictionary *value, BOOL final) {
    websocket_send(connection, 0x1, [NSJSONSerialization dataWithJSONObject:value options:0 error:NULL] ?: [NSData data], final);
}

static void websocket_close(nw_connection_t connection, uint16_t code) {
    uint8_t payload[2] = {(uint8_t)(code >> 8), (uint8_t)code};
    websocket_send(connection, 0x8, [NSData dataWithBytes:payload length:sizeof(payload)], YES);
}

static void release_connection(NSMutableDictionary *context) {
    if ([context[@"released"] boolValue]) return;
    context[@"released"] = @YES;
    NSMutableDictionary *bridge = context[@"session"];
    if (bridge) {
        close_bridge_session(bridge, &bridge_keys);
        [bridge_open_sessions removeObjectIdenticalTo:bridge];
        [context removeObjectForKey:@"session"];
    }
    if (bridge_connections) bridge_connections--;
}

static NSString *websocket_accept(NSString *key) {
    NSData *material = [[key stringByAppendingString:@(MIRRA_WEBSOCKET_GUID)] dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t value[CC_SHA1_DIGEST_LENGTH];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    // RFC 6455 fixes SHA-1 for the handshake; it carries no secret here.
    CC_SHA1(material.bytes, (CC_LONG)material.length, value);
#pragma clang diagnostic pop
    return [[NSData dataWithBytes:value length:sizeof(value)] base64EncodedStringWithOptions:0];
}

static void open_websocket(nw_connection_t connection, NSMutableDictionary *context, NSDictionary *headers,
                           NSDictionary<NSString *, NSString *> *query) {
    NSString *upgrade = [headers[@"upgrade"] lowercaseString];
    NSString *connection_header = [headers[@"connection"] lowercaseString];
    NSString *key = headers[@"sec-websocket-key"];
    NSData *decoded = key ? [[NSData alloc] initWithBase64EncodedString:key options:0] : nil;
    if (![upgrade isEqual:@"websocket"] || ![connection_header containsString:@"upgrade"] ||
        ![headers[@"sec-websocket-version"] isEqual:@"13"] || decoded.length != 16) {
        http_json(connection, 400, @{@"error": @"websocket_upgrade_required"});
        return;
    }
    NSString *client = query[@"client"] ? valid_client_id(query[@"client"]) : nil;
    if (query[@"client"] && !client) {
        http_json(connection, 400, @{@"error": @"invalid_client"});
        return;
    }
    if (client) {
        // A reconnecting Mac replaces its earlier session; the keybags it saved
        // must not be loaded twice.
        for (NSMutableDictionary *previous in [bridge_open_sessions copy]) {
            if (![previous[@"client"] isEqual:client]) continue;
            nw_connection_t old = previous[@"connection"];
            close_bridge_session(previous, &bridge_keys);
            [bridge_open_sessions removeObjectIdenticalTo:previous];
            if (old) nw_connection_cancel(old);
        }
    }
    if (bridge_open_sessions.count >= MIRRA_SESSION_LIMIT) {
        http_json(connection, 503, @{@"error": @"session_limit"});
        return;
    }
    NSString *head = [NSString stringWithFormat:@"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                      "Connection: Upgrade\r\nSec-WebSocket-Accept: %@\r\n\r\n", websocket_accept(key)];
    nw_connection_send(connection, dispatch_bytes([head dataUsingEncoding:NSUTF8StringEncoding]),
                       NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, false, ^(nw_error_t error) { (void)error; });
    context[@"mode"] = @"websocket";
    NSMutableDictionary *greeting = [bridge_capabilities mutableCopy];
    if (!bridge_available) {
        websocket_json(connection, greeting, NO);
        websocket_close(connection, 1011);
        return;
    }
    NSData *dcrt = installed_certificate();
    if (!dcrt) {
        websocket_json(connection, @{@"ready": @NO, @"error": @"device_certificate_unavailable"}, NO);
        websocket_close(connection, 1011);
        return;
    }
    NSMutableDictionary *bridge = new_bridge_session(dcrt);
    bridge[@"connection"] = connection;
    if (client && persistence_available(&bridge_keys)) {
        BOOL known = read_client(client) != nil;
        if (known || saved_clients().count < MIRRA_CLIENT_LIMIT) {
            bridge[@"client"] = client;
            bridge[@"client_name"] = client_name(query[@"name"]);
            NSMutableDictionary *state = client_states[client];
            if (state) {
                for (NSString *name in @[@"identities", @"sessions", @"remote_owners", @"session_kinds"])
                    bridge[name] = state[name];
                bridge[@"restored_identities"] = @([state[@"identities"] count]);
                bridge[@"kept_sessions"] = @([state[@"sessions"] count]);
            } else {
                restore_client(bridge, &bridge_keys);
                client_states[client] = [@{@"identities": bridge[@"identities"], @"sessions": bridge[@"sessions"],
                                           @"remote_owners": bridge[@"remote_owners"],
                                           @"session_kinds": bridge[@"session_kinds"]} mutableCopy];
            }
            if (known) persist_client(bridge, &bridge_keys);  // Records the time and current name.
        }
    }
    context[@"session"] = bridge;
    [bridge_open_sessions addObject:bridge];
    greeting[@"ready"] = @YES;
    greeting[@"client_saved"] = @(bridge[@"client"] != nil);
    greeting[@"restored_identities"] = bridge[@"restored_identities"] ?: @0;
    greeting[@"restore_failures"] = bridge[@"restore_failures"] ?: @0;
    greeting[@"kept_sessions"] = bridge[@"kept_sessions"] ?: @0;
    if (client && !bridge[@"client"])
        greeting[@"client_saved_error"] = persistence_available(&bridge_keys) ? @"client_limit" : @"persistence_unavailable";
    greeting[@"dcrt_bytes"] = @(dcrt.length);
    greeting[@"dcrt_sha256"] = digest(dcrt);
    websocket_json(connection, greeting, NO);
}

static BOOL websocket_message(nw_connection_t connection, NSMutableDictionary *context, NSData *payload) {
    NSDictionary *request = [NSJSONSerialization JSONObjectWithData:payload options:0 error:NULL];
    if (![request isKindOfClass:NSDictionary.class]) { websocket_json(connection, @{@"error": @"invalid_json"}, NO); return YES; }
    if (!valid_request_fields(request)) { websocket_json(connection, @{@"error": @"invalid_request_fields"}, NO); return YES; }
    BOOL close = NO;
    NSDictionary *response = bridge_request(context[@"session"], &bridge_keys, request, &close);
    websocket_json(connection, response, NO);
    if (close) {
        websocket_close(connection, 1000);
        return NO;
    }
    return YES;
}

// Returns NO once the connection is being closed.
static BOOL websocket_frames(nw_connection_t connection, NSMutableDictionary *context) {
    NSMutableData *buffer = context[@"buffer"];
    while (buffer.length >= 2) {
        const uint8_t *bytes = buffer.bytes;
        uint8_t opcode = bytes[0] & 0x0f;
        uint64_t length = bytes[1] & 0x7f;
        size_t header = 2;
        if ((bytes[0] & 0x70) || !(bytes[1] & 0x80)) { websocket_close(connection, 1002); return NO; }
        if (length == 126) {
            if (buffer.length < 4) return YES;
            length = ((uint64_t)bytes[2] << 8) | bytes[3]; header = 4;
        } else if (length == 127) {
            if (buffer.length < 10) return YES;
            length = 0;
            for (int i = 0; i < 8; i++) length = (length << 8) | bytes[2 + i];
            header = 10;
        }
        if (length > MIRRA_MESSAGE_LIMIT) {
            websocket_json(connection, @{@"error": @"request_too_large"}, NO);
            websocket_close(connection, 1009);
            return NO;
        }
        if (buffer.length < header + 4 + length) return YES;
        const uint8_t *mask = bytes + header;
        NSMutableData *payload = [NSMutableData dataWithBytes:bytes + header + 4 length:(NSUInteger)length];
        uint8_t *data = payload.mutableBytes;
        for (uint64_t i = 0; i < length; i++) data[i] ^= mask[i & 3];
        BOOL final = (bytes[0] & 0x80) != 0;
        [buffer replaceBytesInRange:NSMakeRange(0, header + 4 + (NSUInteger)length) withBytes:NULL length:0];
        if (opcode == 0x8) { websocket_close(connection, 1000); return NO; }
        if (opcode == 0x9) { websocket_send(connection, 0xA, payload, NO); continue; }
        if (opcode == 0xA) continue;
        if (opcode != 0x1 || !final) { websocket_close(connection, 1003); return NO; }
        if (!context[@"session"]) { websocket_close(connection, 1011); return NO; }
        if (!websocket_message(connection, context, payload)) return NO;
    }
    return YES;
}

static dispatch_queue_t certificate_queue(void) {
    static dispatch_once_t once;
    static dispatch_queue_t queue;
    dispatch_once(&once, ^{
        queue = dispatch_queue_create("com.mirra.bridge.certificate", DISPATCH_QUEUE_SERIAL);
    });
    return queue;
}

static void certificate_route(nw_connection_t connection, NSMutableDictionary *context, NSData *body) {
    NSDictionary *request = body.length ? [NSJSONSerialization JSONObjectWithData:body options:0 error:NULL] : [NSDictionary dictionary];
    if (![request isKindOfClass:NSDictionary.class] ||
        (request[@"issue"] && ![request[@"issue"] isKindOfClass:NSNumber.class])) {
        http_json(connection, 400, @{@"error": @"invalid_request_fields"});
        return;
    }
    BOOL issue = [request[@"issue"] boolValue];
    NSString *replace_digest = request[@"replace_expired_sha256"];
    if (replace_digest) {
        NSCharacterSet *hex = [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"];
        if (!issue || ![replace_digest isKindOfClass:NSString.class] || replace_digest.length != 64 ||
            [replace_digest rangeOfCharacterFromSet:hex.invertedSet].location != NSNotFound) {
            http_json(connection, 400, @{@"error": @"invalid_request_fields"});
            return;
        }
        NSData *current = installed_certificate();
        if (current && ![digest(current) isEqualToString:replace_digest]) {
            http_json(connection, 200, @{@"certificate_exported": @YES, @"bytes": @(current.length),
                @"sha256": digest(current), @"issuance_requested": @NO});
            return;
        }
    }
    // Certificate issuance can wait up to 52s; keep bridge_queue free for live WebSocket RPCs.
    dispatch_async(certificate_queue(), ^{
        NSData *certificate = nil;
        NSDictionary *result = copy_certificate(issue, replace_digest, &certificate);
        dispatch_async(bridge_queue, ^{
            if ([context[@"released"] boolValue]) return;
            if (!certificate) { http_json(connection, 409, result); return; }
            if (!write_private_file(certificate_path(), certificate)) {
                http_json(connection, 500, @{@"error": @"certificate_write_failed"});
                return;
            }
            publish_preferences();
            http_json(connection, 200, result);
        });
    });
}

// Returns YES when the request is complete and has been answered.
static BOOL http_request(nw_connection_t connection, NSMutableDictionary *context) {
    NSMutableData *buffer = context[@"buffer"];
    NSRange end = [buffer rangeOfData:[NSData dataWithBytes:"\r\n\r\n" length:4] options:0
                                range:NSMakeRange(0, buffer.length)];
    if (end.location == NSNotFound || end.location > MIRRA_HEADER_LIMIT) {
        if (buffer.length > MIRRA_HEADER_LIMIT) { http_json(connection, 431, @{@"error": @"headers_too_large"}); return YES; }
        return NO;
    }
    NSString *head = [[NSString alloc] initWithData:[buffer subdataWithRange:NSMakeRange(0, end.location)]
                                           encoding:NSUTF8StringEncoding];
    NSArray<NSString *> *lines = [head componentsSeparatedByString:@"\r\n"];
    NSArray<NSString *> *start = [lines.firstObject componentsSeparatedByString:@" "];
    if (!head || start.count != 3 || ![start[2] isEqual:@"HTTP/1.1"]) {
        http_json(connection, 400, @{@"error": @"invalid_request"});
        return YES;
    }
    NSMutableDictionary<NSString *, NSString *> *headers = [NSMutableDictionary dictionary];
    for (NSUInteger i = 1; i < lines.count; i++) {
        NSRange colon = [lines[i] rangeOfString:@":"];
        if (colon.location == NSNotFound || colon.location == 0) {
            http_json(connection, 400, @{@"error": @"invalid_request"});
            return YES;
        }
        NSString *name = [[lines[i] substringToIndex:colon.location] lowercaseString];
        NSString *value = [[lines[i] substringFromIndex:colon.location + 1]
                           stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        headers[name] = value;
    }
    NSInteger length = headers[@"content-length"] ? headers[@"content-length"].integerValue : 0;
    if (length < 0 || length > MIRRA_BODY_LIMIT || headers[@"transfer-encoding"]) {
        http_json(connection, 413, @{@"error": @"request_too_large"});
        return YES;
    }
    NSUInteger body_start = end.location + 4;
    if (buffer.length < body_start + (NSUInteger)length) return NO;
    NSData *body = [buffer subdataWithRange:NSMakeRange(body_start, (NSUInteger)length)];
    [buffer replaceBytesInRange:NSMakeRange(0, body_start + (NSUInteger)length) withBytes:NULL length:0];
    NSString *method = start[0], *target = start[1];
    NSRange separator = [target rangeOfString:@"?"];
    NSString *path = separator.location == NSNotFound ? target : [target substringToIndex:separator.location];
    NSMutableDictionary<NSString *, NSString *> *query = [NSMutableDictionary dictionary];
    if (separator.location != NSNotFound) {
        for (NSString *pair in [[target substringFromIndex:separator.location + 1] componentsSeparatedByString:@"&"]) {
            NSRange equals = [pair rangeOfString:@"="];
            if (equals.location == NSNotFound) continue;
            NSString *name = [[pair substringToIndex:equals.location] stringByRemovingPercentEncoding];
            NSString *value = [[[pair substringFromIndex:equals.location + 1]
                                stringByReplacingOccurrencesOfString:@"+" withString:@" "] stringByRemovingPercentEncoding];
            if (name && value && value.length <= 256) query[name] = value;
        }
    }
    if ([path isEqual:@"/v1/status"] && [method isEqual:@"GET"]) {
        http_json(connection, 200, service_report());
    } else if ([path isEqual:@"/v1/certificate"] && [method isEqual:@"GET"]) {
        NSData *certificate = installed_certificate();
        if (certificate) http_reply(connection, 200, @"application/octet-stream", certificate);
        else http_json(connection, 404, @{@"error": @"device_certificate_unavailable"});
    } else if ([path isEqual:@"/v1/certificate"] && [method isEqual:@"POST"]) {
        if (!bridge_available) http_json(connection, 409, service_report());
        else certificate_route(connection, context, body);
    } else if ([path isEqual:@"/v1/session"] && [method isEqual:@"GET"]) {
        open_websocket(connection, context, headers, query);
        if ([context[@"mode"] isEqual:@"websocket"]) websocket_frames(connection, context);
    } else if ([@[@"/v1/status", @"/v1/certificate", @"/v1/session"] containsObject:path]) {
        http_json(connection, 405, @{@"error": @"method_not_allowed"});
    } else {
        http_json(connection, 404, @{@"error": @"not_found"});
    }
    return YES;
}

static void receive_more(nw_connection_t connection, NSMutableDictionary *context) {
    nw_connection_receive(connection, 1, 65536, ^(dispatch_data_t content, nw_content_context_t message,
                                                  bool complete, nw_error_t error) {
        (void)message;
        if (content) {
            NSMutableData *buffer = context[@"buffer"];
            dispatch_data_apply(content, ^bool(dispatch_data_t region, size_t offset, const void *bytes, size_t size) {
                (void)region; (void)offset;
                [buffer appendBytes:bytes length:size];
                return true;
            });
        }
        BOOL websocket = [context[@"mode"] isEqual:@"websocket"];
        if (websocket) {
            if (!websocket_frames(connection, context)) return;
        } else if ([context[@"answered"] boolValue] || http_request(connection, context)) {
            context[@"answered"] = @YES;
            if (![context[@"mode"] isEqual:@"websocket"]) return;  // The reply closes the connection.
        }
        if (error || complete) { nw_connection_cancel(connection); return; }
        receive_more(connection, context);
    });
}

static void accept_connection(nw_connection_t connection) {
    if (bridge_connections >= MIRRA_CONNECTION_LIMIT) { nw_connection_cancel(connection); return; }
    bridge_connections++;
    NSMutableDictionary *context = [@{@"buffer": [NSMutableData data], @"mode": @"http"} mutableCopy];
    nw_connection_set_queue(connection, bridge_queue);
    nw_connection_set_state_changed_handler(connection, ^(nw_connection_state_t state, nw_error_t error) {
        (void)error;
        if (state == nw_connection_state_failed) nw_connection_cancel(connection);
        if (state == nw_connection_state_cancelled) release_connection(context);
    });
    nw_connection_start(connection);
    // A peer that never finishes its request must not hold a connection slot.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC), bridge_queue, ^{
        // An answered request is closed by its reply; cancelling here could
        // abort a reply queued after a long certificate request.
        if (![context[@"mode"] isEqual:@"websocket"] && ![context[@"answered"] boolValue] &&
            ![context[@"released"] boolValue]) nw_connection_cancel(connection);
    });
    receive_more(connection, context);
}

#if TARGET_OS_IPHONE && !defined(MIRRA_NO_PREFERENCES)
static void forget_notification(CFNotificationCenterRef center, void *observer, CFNotificationName name,
                                const void *object, CFDictionaryRef info) {
    (void)center; (void)observer; (void)name; (void)object; (void)info;
    dispatch_async(bridge_queue, ^{ handle_forget_requests(); });
}
#endif

static int serve(NSString *directory, int port) {
    bridge_queue = dispatch_queue_create("com.mirra.bridge", DISPATCH_QUEUE_SERIAL);
    bridge_directory = directory;
    bridge_port = port;
    bridge_open_sessions = [NSMutableArray array];
    client_states = [NSMutableDictionary dictionary];
    struct stat info;
    if (lstat(directory.fileSystemRepresentation, &info) != 0 || !S_ISDIR(info.st_mode) ||
        info.st_uid != getuid() || (info.st_mode & 077)) {
        reply(@{@"ready": @NO, @"error": @"service_directory_unavailable"});
        return 1;
    }
    bridge_token = load_or_create_token();
    if (!bridge_token) { reply(@{@"ready": @NO, @"error": @"pairing_token_unavailable"}); return 1; }
    BOOL available = NO;
    bridge_capabilities = capability_report(keystore_library(), &bridge_keys, &available);
    bridge_available = available;
    NSData *key = pre_shared_key(bridge_token);
    dispatch_data_t psk = dispatch_bytes(key);
    dispatch_data_t identity = dispatch_data_create(MIRRA_PSK_IDENTITY, strlen(MIRRA_PSK_IDENTITY), bridge_queue,
                                                    DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    nw_parameters_t parameters = nw_parameters_create_secure_tcp(^(nw_protocol_options_t tls) {
        sec_protocol_options_t options = nw_tls_copy_sec_protocol_options(tls);
        sec_protocol_options_add_pre_shared_key(options, psk, identity);
        sec_protocol_options_set_tls_pre_shared_key_identity_hint(options, identity);
        sec_protocol_options_append_tls_ciphersuite(options, (tls_ciphersuite_t)0xCCAC);  // ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
        sec_protocol_options_set_min_tls_protocol_version(options, tls_protocol_version_TLSv12);
        sec_protocol_options_set_max_tls_protocol_version(options, tls_protocol_version_TLSv12);
    }, ^(nw_protocol_options_t tcp) {
        // Detect a Mac that disappeared so its keybags are released promptly.
        nw_tcp_options_set_enable_keepalive(tcp, true);
        nw_tcp_options_set_keepalive_idle_time(tcp, 10);
        nw_tcp_options_set_keepalive_interval(tcp, 5);
        nw_tcp_options_set_keepalive_count(tcp, 3);
    });
    nw_parameters_set_reuse_local_address(parameters, true);
    char port_text[8];
    snprintf(port_text, sizeof(port_text), "%d", port);
    nw_listener_t listener = nw_listener_create_with_port(port_text, parameters);
    if (!listener) { reply(@{@"ready": @NO, @"error": @"service_listener_unavailable"}); return 1; }
    __block int code = 0;
    nw_listener_set_queue(listener, bridge_queue);
    nw_listener_set_new_connection_handler(listener, ^(nw_connection_t connection) { accept_connection(connection); });
    nw_listener_set_state_changed_handler(listener, ^(nw_listener_state_t state, nw_error_t error) {
        if (state == nw_listener_state_ready) {
            bridge_port = nw_listener_get_port(listener);
            publish_preferences();
            reply(@{@"listening": @YES, @"port": @(bridge_port), @"keystore_available": @(bridge_available)});
        } else if (state == nw_listener_state_failed) {
            code = 1;
            reply(@{@"listening": @NO, @"error": @"service_listener_failed",
                    @"error_code": @(error ? nw_error_get_error_code(error) : 0)});
            CFRunLoopStop(CFRunLoopGetMain());
        }
    });
    nw_listener_start(listener);
    // Refresh the Settings entry when the Wi-Fi address changes.
    dispatch_source_t refresh = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, bridge_queue);
    dispatch_source_set_timer(refresh, dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC), 30 * NSEC_PER_SEC, NSEC_PER_SEC);
    dispatch_source_set_event_handler(refresh, ^{ publish_preferences(); });
    dispatch_resume(refresh);
#if TARGET_OS_IPHONE && !defined(MIRRA_NO_PREFERENCES)
    // The Settings entry asks to remove a saved Mac through this notification.
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL,
        forget_notification, CFSTR("com.mirra.bridge.forget"), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    dispatch_async(bridge_queue, ^{ handle_forget_requests(); });
#endif
    // launchd stops the service with SIGTERM; release every keybag first.
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    dispatch_source_t terminate = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGTERM, 0, dispatch_get_main_queue());
    dispatch_source_t interrupt = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGINT, 0, dispatch_get_main_queue());
    dispatch_source_set_event_handler(terminate, ^{ CFRunLoopStop(CFRunLoopGetMain()); });
    dispatch_source_set_event_handler(interrupt, ^{ CFRunLoopStop(CFRunLoopGetMain()); });
    dispatch_resume(terminate);
    dispatch_resume(interrupt);
    // The main run loop also services callbacks some private APIs deliver
    // to the main queue during certificate issuance.
    CFRunLoopRun();
    dispatch_sync(bridge_queue, ^{
        dispatch_source_cancel(refresh);
        nw_listener_cancel(listener);
        for (NSMutableDictionary *bridge in bridge_open_sessions) close_bridge_session(bridge, &bridge_keys);
        for (NSMutableDictionary *state in client_states.allValues) release_client_state(state, &bridge_keys);
        [client_states removeAllObjects];
        [bridge_open_sessions removeAllObjects];
    });
    return code;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc == 3 && (!strcmp(argv[1], "--export-certificate") || !strcmp(argv[1], "--issue-certificate")))
            return export_certificate(argv[2], !strcmp(argv[1], "--issue-certificate"));
        if (argc == 2 && !strcmp(argv[1], "--capabilities")) {
            KeyStore keys = {0};
            BOOL available = NO;
            reply(capability_report(keystore_library(), &keys, &available));
            return available ? 0 : 1;
        }
        if ((argc == 3 || argc == 5) && !strcmp(argv[1], "--serve")) {
            int port = MIRRA_DEFAULT_PORT;
            if (argc == 5) {
                char *end = NULL;
                long value = strcmp(argv[3], "--port") ? -1 : strtol(argv[4], &end, 10);
                if (value < 0 || value > 65535 || !end || *end) {
                    reply(@{@"ready": @NO, @"error": @"invalid_service_port"});
                    return 1;
                }
                port = (int)value;
            }
            if (argv[2][0] != '/') { reply(@{@"ready": @NO, @"error": @"service_directory_unavailable"}); return 1; }
            return serve(@(argv[2]), port);
        }
        reply(@{@"ready": @NO, @"error": @"usage: --capabilities | --serve <directory> [--port <port>]"});
        return 1;
    }
}
