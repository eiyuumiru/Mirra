#ifndef MIRRA_CACHE_SYMBOLS_H
#define MIRRA_CACHE_SYMBOLS_H

#include <mach-o/nlist.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Project-authored reader for Apple's dyld cache local-symbol format. The
// 32/64-bit entry layouts and UUID fields are documented in dyld-955's
// cache-builder/dyld_cache_format.h and common/DyldSharedCache.cpp.
// Addresses come from the active cache's symbols, never from another build.
enum { CACHE_UUID_OFFSET = 88, CACHE_SYMBOL_UUID_OFFSET = 400,
       CACHE_HEADER_BYTES = CACHE_SYMBOL_UUID_OFFSET + 16 };

typedef struct {
    unsigned char magic[16], uuid[16], symbols_uuid[16];
    uint32_t mapping_offset;
    uint64_t symbols_offset, symbols_size;
    bool wide_entries;
} CacheHeader;

typedef struct {
    uint32_t nlist_offset, nlist_count, strings_offset, strings_size,
             entries_offset, entries_count;
} CacheSymbolsInfo;

typedef struct {
    const unsigned char *bytes;
    size_t length;
    CacheSymbolsInfo info;
    bool wide_entries;
} CacheSymbols;

typedef struct { uint64_t value; unsigned char section; } CacheSymbol;
typedef enum { CACHE_SYMBOL_INVALID = -1, CACHE_SYMBOL_MISSING = 0,
               CACHE_SYMBOL_FOUND = 1 } CacheSymbolResult;

static inline bool cache_range(size_t length, uint64_t offset, uint64_t size) {
    return offset <= length && size <= length - offset;
}

static inline bool cache_uuid_present(const unsigned char uuid[16]) {
    for (unsigned i = 0; i < 16; i++) if (uuid[i]) return true;
    return false;
}

static inline bool cache_header(const void *bytes, size_t length, CacheHeader *output) {
    static const char magic[][16] = {"dyld_v1   arm64", "dyld_v1  arm64e",
                                    "dyld_v0   arm64", "dyld_v0  arm64e"};
    if (!bytes || !output || length < CACHE_UUID_OFFSET + 16) return false;
    const unsigned char *data = bytes;
    bool supported = false;
    for (size_t i = 0; i < sizeof(magic) / sizeof(*magic); i++)
        if (!memcmp(data, magic[i], sizeof(*magic))) supported = true;
    if (!supported) return false;
    CacheHeader header = {0};
    memcpy(header.magic, data, sizeof(header.magic));
    memcpy(&header.mapping_offset, data + 16, 4);
    memcpy(&header.symbols_offset, data + 72, 8);
    memcpy(&header.symbols_size, data + 80, 8);
    memcpy(header.uuid, data + CACHE_UUID_OFFSET, 16);
    if (header.mapping_offset < CACHE_UUID_OFFSET + 16 || header.mapping_offset % 8 ||
        !cache_uuid_present(header.uuid)) return false;
    // dyld uses 64-bit VM offsets starting with this header generation.
    header.wide_entries = header.mapping_offset >= CACHE_SYMBOL_UUID_OFFSET;
    if (header.mapping_offset >= CACHE_HEADER_BYTES) {
        if (length < CACHE_HEADER_BYTES) return false;
        memcpy(header.symbols_uuid, data + CACHE_SYMBOL_UUID_OFFSET, 16);
    }
    *output = header;
    return true;
}

static inline bool cache_disjoint(uint64_t a, uint64_t a_size, uint64_t b, uint64_t b_size) {
    return (a <= b && a_size <= b - a) || (b <= a && b_size <= a - b);
}

static inline bool cache_symbols(const void *bytes, size_t length, bool wide,
                                 CacheSymbols *output) {
    if (!bytes || !output || length < sizeof(CacheSymbolsInfo)) return false;
    CacheSymbolsInfo info;
    memcpy(&info, bytes, sizeof(info));
    uint64_t nlists = (uint64_t)info.nlist_count * sizeof(struct nlist_64);
    uint64_t entries = (uint64_t)info.entries_count * (wide ? 16 : 12);
    if (!info.nlist_count || !info.entries_count || !info.strings_size ||
        info.nlist_offset < sizeof(info) || info.entries_offset < sizeof(info) ||
        info.strings_offset < sizeof(info) ||
        !cache_range(length, info.nlist_offset, nlists) ||
        !cache_range(length, info.entries_offset, entries) ||
        !cache_range(length, info.strings_offset, info.strings_size) ||
        !cache_disjoint(info.nlist_offset, nlists, info.entries_offset, entries) ||
        !cache_disjoint(info.nlist_offset, nlists, info.strings_offset, info.strings_size) ||
        !cache_disjoint(info.entries_offset, entries, info.strings_offset, info.strings_size)) return false;
    *output = (CacheSymbols){.bytes = bytes, .length = length, .info = info,
                             .wide_entries = wide};
    return true;
}

static inline CacheSymbolResult cache_nlist_symbol(const void *bytes, size_t length,
                                                   const void *pool, size_t pool_size,
                                                   const char *name, CacheSymbol *output) {
    if (!name || !output) return CACHE_SYMBOL_INVALID;
    size_t name_size = 0;
    while (name_size < 64 && name[name_size]) name_size++;
    if (!name_size || name_size == 64) return CACHE_SYMBOL_INVALID;
    if (!length) return CACHE_SYMBOL_MISSING;
    if (!bytes || !pool || !pool_size || length % sizeof(struct nlist_64)) return CACHE_SYMBOL_INVALID;
    const unsigned char *nlists = bytes, *strings = pool;
    CacheSymbol found = {0};
    bool present = false;
    for (size_t i = 0; i < length / sizeof(struct nlist_64); i++) {
        struct nlist_64 entry;
        memcpy(&entry, nlists + i * sizeof(entry), sizeof(entry));
        uint32_t index = entry.n_un.n_strx;
        if (index >= pool_size) return CACHE_SYMBOL_INVALID;
        if (name_size + 2 > pool_size - index || strings[index] != '_' ||
            memcmp(strings + index + 1, name, name_size) || strings[index + name_size + 1]) continue;
        if ((entry.n_type & (N_STAB | N_TYPE)) != N_SECT || !entry.n_sect ||
            !entry.n_value || (entry.n_value & 3)) return CACHE_SYMBOL_INVALID;
        if (present && (found.value != entry.n_value || found.section != entry.n_sect))
            return CACHE_SYMBOL_INVALID;
        present = true;
        found = (CacheSymbol){.value = entry.n_value, .section = entry.n_sect};
    }
    if (!present) return CACHE_SYMBOL_MISSING;
    *output = found;
    return CACHE_SYMBOL_FOUND;
}

static inline CacheSymbolResult cache_find_symbol(const CacheSymbols *symbols,
                                                  uint64_t image_offset, const char *name,
                                                  CacheSymbol *output) {
    if (!symbols || !name || !output) return CACHE_SYMBOL_INVALID;
    const CacheSymbolsInfo *info = &symbols->info;
    const unsigned char *entries = symbols->bytes + info->entries_offset;
    size_t entry_size = symbols->wide_entries ? 16 : 12;
    bool image_found = false;
    uint32_t first = 0, count = 0;
    for (uint32_t i = 0; i < info->entries_count; i++) {
        const unsigned char *entry = entries + (size_t)i * entry_size;
        uint64_t offset = 0;
        uint32_t start, size;
        memcpy(&offset, entry, symbols->wide_entries ? 8 : 4);
        memcpy(&start, entry + entry_size - 8, 4);
        memcpy(&size, entry + entry_size - 4, 4);
        if (start > info->nlist_count || size > info->nlist_count - start)
            return CACHE_SYMBOL_INVALID;
        if (offset != image_offset) continue;
        if (image_found) return CACHE_SYMBOL_INVALID;
        image_found = true; first = start; count = size;
    }
    if (!image_found) return CACHE_SYMBOL_MISSING;
    return cache_nlist_symbol(symbols->bytes + info->nlist_offset + (size_t)first * sizeof(struct nlist_64),
                              (size_t)count * sizeof(struct nlist_64),
                              symbols->bytes + info->strings_offset, info->strings_size, name, output);
}

// All iOS 15 versions use this discovery path; no minor-version/build list.
static inline bool cache_platform_supported(const char *version, const char *architecture) {
    if (!version || !architecture ||
        (strcmp(architecture, "arm64") && strcmp(architecture, "arm64e"))) return false;
    if (version[0] != '1' || version[1] != '5') return false;
    const char *part = version + 2;
    while (*part) {
        if (*part++ != '.' || *part < '0' || *part > '9') return false;
        do { part++; } while (*part >= '0' && *part <= '9');
    }
    return true;
}

static inline bool cache_discovery_supported(const char *version, const char *build,
                                            const char *architecture) {
    if (version && *version && strcmp(version, "unavailable"))
        return cache_platform_supported(version, architecture);
    // Product-version sysctl may be absent; iOS 15's product builds use 19.
    return cache_platform_supported("15", architecture) && build &&
           build[0] == '1' && build[1] == '9' && build[2] >= 'A' && build[2] <= 'Z' &&
           build[3] >= '0' && build[3] <= '9';
}

#endif
