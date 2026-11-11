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

// Experimental AKS endpoint over stdin/stdout (carried by authenticated SSH).
// All identities live in newly allocated unsaved keybags. Only session IDs
// created by this process can be stepped/reset. System keybags are not used.
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
    return missing;
}

static int export_certificate(const char *output, BOOL issue) {
    diagnostic(@{@"operation": issue ? @"issue_certificate" : @"export_certificate", @"stage": @"begin"});
#if TARGET_OS_IPHONE
    void *ma = dlopen("/System/Library/PrivateFrameworks/MobileActivation.framework/MobileActivation", RTLD_LAZY | RTLD_LOCAL);
    typedef NSData *(*CopyDCRT)(NSError *__autoreleasing *);
    CopyDCRT copy = ma ? (CopyDCRT)dlsym(ma, "MAECopyDCRTWithError") : NULL;
    diagnostic(@{@"stage": @"resolve_certificate_api", @"framework_loaded": @(ma != NULL), @"copy_available": @(copy != NULL)});
    if (!copy) { reply(@{@"error": @"certificate_api_unavailable"}); return 1; }
    struct stat info;
    if (lstat(output, &info) == 0) { reply(@{@"error": @"output_already_exists"}); return 1; }
    if (issue) {
        typedef void (*IssueDCRT)(NSDictionary *, void *, void (^)(NSError *));
        IssueDCRT request = (IssueDCRT)dlsym(ma, "MAEIssueDCRTWithCallback");
        diagnostic(@{@"stage": @"resolve_issuance_api", @"issue_available": @(request != NULL)});
        if (!request) { reply(@{@"error": @"certificate_issuance_api_unavailable"}); return 1; }
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
            if (dispatch_semaphore_wait(done, DISPATCH_TIME_NOW) == 0) { completed = YES; break; }
            [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
        }
        if (!completed || issue_error) {
            diagnostic(@{@"stage": @"issuance_failed", @"completed": @(completed), @"error_code": @(issue_error.code)});
            reply(@{@"error": @"certificate_issuance_failed", @"completed": @(completed),
                    @"error_code": @(issue_error.code), @"error_domain": issue_error.domain ?: @""});
            return 1;
        }
    }
    NSError *error = nil;
    diagnostic(@{@"stage": @"MAECopyDCRTWithError_call"});
    NSData *data = copy(&error);
    NSUInteger certificate_bytes = [data isKindOfClass:NSData.class] ? data.length : 0;
    diagnostic(@{@"stage": @"MAECopyDCRTWithError_result", @"bytes": @(certificate_bytes), @"error_code": @(error.code), @"error_domain": error.domain ?: @""});
    if (![data isKindOfClass:NSData.class] || !data.length || data.length > 1048576) {
        reply(@{@"error": @"cached_certificate_unavailable", @"error_code": @(error.code),
                @"error_domain": error.domain ?: @""});
        return 1;
    }
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
    reply(@{@"certificate_exported": @YES, @"bytes": @(data.length), @"sha256": digest(data), @"issuance_requested": @(issue)});
    return 0;
#else
    (void)output; (void)issue;
    reply(@{@"error": @"certificate_export_requires_ios_backend"});
    return 1;
#endif
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc == 3 && (!strcmp(argv[1], "--export-certificate") || !strcmp(argv[1], "--issue-certificate")))
            return export_certificate(argv[2], !strcmp(argv[1], "--issue-certificate"));
        BOOL capabilities = argc == 2 && !strcmp(argv[1], "--capabilities");
        if (argc != 2) { reply(@{@"ready": @NO, @"error": @"certificate_path_or_capabilities_required"}); return 1; }
        void *library = keystore_library();
        KeyStore keys = {0};
        NSMutableArray<NSString *> *missing = load_keystore(&keys, library, dlsym, mapped_keystore_symbol);
        BOOL available = missing.count == 0;
        NSMutableDictionary *capability_report = [@{@"protocol_version": @1,
            @"required_symbols_available": @(available), @"missing_symbols": missing,
            @"process_architecture": process_architecture(), @"minimum_ios": @"15.0",
            @"product_type": system_value("hw.machine"), @"os_build": system_value("kern.osversion"),
            @"os_version": system_value("kern.osproductversion"), @"end_to_end_verified": @NO} mutableCopy];
#if KEYSTORE_SYMBOL_TARGET
        if (cache_discovery_supported([capability_report[@"os_version"] UTF8String],
                                      [capability_report[@"os_build"] UTF8String],
                                      [capability_report[@"process_architecture"] UTF8String])) {
            NSMutableDictionary *resolution = [@{@"shared_cache_discovery": @YES,
                @"cache_symbols_checked": @(cache_lookup.file_checked),
                @"cache_symbols_available": @(cache_lookup.file.mapping != NULL),
                @"loaded_symbols_resolved": @(cache_lookup.live_resolved),
                @"cache_file_symbols_resolved": @(cache_lookup.file_resolved)} mutableCopy];
            if (cache_lookup.error) resolution[@"error"] = @(cache_lookup.error);
            capability_report[@"keystore_resolution"] = resolution;
        }
#endif
        if (!available) {
            capability_report[@"ready"] = @NO;
            capability_report[@"error"] = library ? @"required_keystore_symbols_unavailable" : @"keystore_library_unavailable";
        }
        if (capabilities) {
            reply(capability_report);
            return available ? 0 : 1;
        }
        if (!available) {
            reply(capability_report);
            return 1;
        }
        NSData *dcrt = argc == 2 ? [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:argv[1]]] : nil;
        if (!dcrt.length || dcrt.length > 1048576) { reply(@{@"ready": @NO, @"error": @"device_certificate_unavailable"}); return 1; }
        NSMutableDictionary<NSString *, NSDictionary *> *identities = [NSMutableDictionary dictionary];
        NSMutableSet<NSNumber *> *sessions = [NSMutableSet set];
        NSMutableDictionary<NSString *, NSDictionary *> *remote_owners = [NSMutableDictionary dictionary];
        capability_report[@"ready"] = @YES;
        capability_report[@"dcrt_bytes"] = @(dcrt.length);
        capability_report[@"dcrt_sha256"] = digest(dcrt);
        reply(capability_report);
        char *line = NULL;
        size_t capacity = 0;
        ssize_t count;
        while ((count = getline(&line, &capacity, stdin)) > 0) {
            @autoreleasepool {
                if (count > 262144) {
                    reply(@{@"error": @"request_too_large"});
                    break;
                }
                NSDictionary *request = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:line length:(NSUInteger)count] options:0 error:NULL];
                if (![request isKindOfClass:NSDictionary.class]) {
                    reply(@{@"error": @"invalid_json"});
                    continue;
                }
                NSString *operation = request[@"operation"];
                if ([operation isEqual:@"exit"]) {
                    reply(@{@"closed": @YES});
                    break;
                }
                if ([operation isEqual:@"generate"]) {
                    BOOL attested = [request[@"attested"] boolValue];
                    int key_class = request[@"key_class"] ? [request[@"key_class"] intValue] : 9;
                    if (key_class != 9 && key_class != 10 && key_class != 11) {
                        reply(@{@"error": @"invalid_key_class"});
                        continue;
                    }
                    if (identities.count >= 8 || (attested && !dcrt.length)) {
                        reply(@{@"error": @"identity_limit_or_missing_dcrt"});
                        continue;
                    }
                    uint8_t passcode[32];
                    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(passcode), passcode) != 0) return 1;
                    int bag = -1;
                    int status = keys.create_bag(passcode, sizeof(passcode), 0, &bag);
                    memset(passcode, 0, sizeof(passcode));
                    void *blob = NULL;
                    size_t size = 0;
                    if (status == 0 && bag >= 0) {
                        if (!attested) {
                            status = keys.create_key(bag, key_class, &blob, &size);
                        } else {
                            void *params = keys.params_create(NULL, 0);
                            int64_t flag = 4;
                            const void *der = NULL;
                            size_t der_size = 0;
                            status = keys.params_data(params, 21, dcrt.bytes, dcrt.length);
                            if (status == 0) status = keys.params_number(params, 20, &flag);
                            if (status == 0) status = keys.params_der(params, &der, &der_size);
                            if (status == 0) status = keys.create_key_params(bag, key_class, der, der_size, &blob, &size);
                        }
                    }
                    NSMutableDictionary *response = result(status);
                    if (status == 0 && blob && size && size <= 65536) {
                        NSString *identifier = NSUUID.UUID.UUIDString;
                        NSData *ltk = [NSData dataWithBytes:blob length:size];
                        identities[identifier] = @{@"bag": @(bag), @"ltk": ltk, @"attested": @(attested), @"key_class": @(key_class)};
                        response[@"identity"] = identifier;
                        response[@"ltk"] = [ltk base64EncodedStringWithOptions:0];
                        response[@"bytes"] = @(size);
                        response[@"key_class"] = @(key_class);
                    } else if (bag >= 0) {
                        keys.unload_bag(bag);
                    }
                    clear_blob(blob, size);
                    reply(response);
                    continue;
                }
                if ([operation isEqual:@"validate"]) {
                    NSDictionary *identity = identities[request[@"identity"] ?: @""];
                    if (!identity) {
                        reply(@{@"error": @"identity_not_owned"});
                        continue;
                    }
                    NSData *key = identity[@"ltk"];
                    reply(result(keys.validate_key([identity[@"bag"] intValue], [identity[@"key_class"] intValue], key.bytes, key.length)));
                    continue;
                }
                if ([operation isEqual:@"get_state"] || [operation isEqual:@"drop"]) {
                    NSString *encoded = request[@"data"];
                    NSDictionary *identity = remote_owners[encoded ?: @""];
                    NSData *key = [encoded isKindOfClass:NSString.class] ? [[NSData alloc] initWithBase64EncodedString:encoded options:0] : nil;
                    if (!identity || !key.length) {
                        reply(@{@"error": @"remote_key_not_owned"});
                        continue;
                    }
                    if ([operation isEqual:@"drop"]) {
                        int status = keys.peer_drop([identity[@"bag"] intValue], key.bytes, key.length);
                        if (status == 0) [remote_owners removeObjectForKey:encoded];
                        reply(result(status));
                    } else {
                        uint8_t state[104] = {0};
                        int status = keys.peer_state([identity[@"bag"] intValue], key.bytes, key.length, state);
                        NSMutableDictionary *response = result(status);
                        response[@"data"] = [[NSData dataWithBytes:state length:sizeof(state)] base64EncodedStringWithOptions:0];
                        response[@"bytes"] = @(sizeof(state));
                        reply(response);
                    }
                    continue;
                }
                if ([operation isEqual:@"session"] || [operation isEqual:@"session_signed"] || [operation isEqual:@"sign_remote"]) {
                    NSDictionary *identity = identities[request[@"identity"] ?: @""];
                    NSString *encoded = request[@"remote_ltk"];
                    NSData *remote = [encoded isKindOfClass:NSString.class] ? [[NSData alloc] initWithBase64EncodedString:encoded options:0] : nil;
                    if (!identity || !remote.length || remote.length > 65536 || sessions.count >= 16) {
                        reply(@{@"error": @"invalid_identity_key_or_session_limit"});
                        continue;
                    }
                    NSData *local = identity[@"ltk"];
                    unsigned int flags = [request[@"flags"] unsignedIntValue];
                    NSString *params_encoded = request[@"parameters"];
                    NSData *session_params = [params_encoded isKindOfClass:NSString.class] ? [[NSData alloc] initWithBase64EncodedString:params_encoded options:0] : nil;
                    if (session_params.length > 65536) {
                        reply(@{@"error": @"parameters_too_large"});
                        continue;
                    }
                    int remote_class = request[@"remote_key_class"] ? [request[@"remote_key_class"] intValue] : 9;
                    if (remote_class != 9 && remote_class != 10 && remote_class != 11) {
                        reply(@{@"error": @"invalid_remote_key_class"});
                        continue;
                    }
                    void *signed_key = NULL;
                    size_t signed_size = 0;
                    int sign_status = 0;
                    if ([operation isEqual:@"session_signed"]) {
                        if (remote_owners[encoded] != identity) {
                            reply(@{@"error": @"signed_remote_key_not_owned"});
                            continue;
                        }
                        signed_size = remote.length;
                        signed_key = malloc(signed_size);
                        if (!signed_key) {
                            reply(result((int)0xe00002bd));
                            continue;
                        }
                        memcpy(signed_key, remote.bytes, signed_size);
                    } else {
                        sign_status = keys.sign_key([identity[@"bag"] intValue], [identity[@"key_class"] intValue],
                                               local.bytes, local.length, remote_class, remote.bytes, remote.length,
                                               &signed_key, &signed_size);
                        if (sign_status == 0 && signed_key && signed_size)
                            remote_owners[[[NSData dataWithBytes:signed_key length:signed_size] base64EncodedStringWithOptions:0]] = identity;
                    }
                    if ([operation isEqual:@"sign_remote"]) {
                        NSMutableDictionary *response = result(sign_status);
                        if (sign_status == 0 && signed_key && signed_size) {
                            response[@"data"] = [[NSData dataWithBytes:signed_key length:signed_size] base64EncodedStringWithOptions:0];
                            response[@"bytes"] = @(signed_size);
                        }
                        clear_blob(signed_key, signed_size);
                        reply(response);
                        continue;
                    }
                    int session = -1;
                    int status = sign_status;
                    if (sign_status == 0 && signed_key && signed_size)
                        status = keys.remote_session([identity[@"bag"] intValue], flags,
                                                local.bytes, local.length, signed_key, signed_size,
                                                session_params.bytes, session_params.length, &session);
                    NSMutableDictionary *response = result(status);
                    response[@"sign_status_hex"] = [NSString stringWithFormat:@"0x%08x", sign_status];
                    response[@"signed_bytes"] = @(signed_size);
                    clear_blob(signed_key, signed_size);
                    if (status == 0 && session >= 0) {
                        [sessions addObject:@(session)];
                        response[@"session"] = @(session);
                    }
                    reply(response);
                    continue;
                }
                if ([operation isEqual:@"step"] || [operation isEqual:@"reset"] ||
                    [operation isEqual:@"token"] || [operation isEqual:@"confirm"] || [operation isEqual:@"setup"]) {
                    NSNumber *session = request[@"session"];
                    if (!session || ![sessions containsObject:session]) {
                        reply(@{@"error": @"session_not_owned"});
                        continue;
                    }
                    if ([operation isEqual:@"reset"]) {
                        reply(reset_owned_session(sessions, session, keys.reset_session));
                        continue;
                    }
                    NSString *encoded = request[@"data"];
                    NSData *input = [encoded isKindOfClass:NSString.class] ? [[NSData alloc] initWithBase64EncodedString:encoded options:0] : nil;
                    if (input.length > 65536) {
                        reply(@{@"error": @"token_too_large"});
                        continue;
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
                    if (output && size && size <= 65536) {
                        NSData *data = [NSData dataWithBytes:output length:size];
                        response[@"data"] = [data base64EncodedStringWithOptions:0];
                    }
                    response[@"bytes"] = @(size);
                    clear_blob(output, size);
                    reply(response);
                    continue;
                }
                reply(@{@"error": @"unknown_operation"});
            }
        }
        free(line);
        for (NSNumber *session in sessions) keys.reset_session(session.intValue);
        for (NSDictionary *identity in identities.allValues) keys.unload_bag([identity[@"bag"] intValue]);
    }
    return 0;
}
