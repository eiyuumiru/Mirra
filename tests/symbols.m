// Synthetic Mach-O metadata only; no AKS functions or phone connection.
#define MIRRA_SYMBOL_FIXTURES 1
#define main unused_endpoint_main
#include "../src/phone/endpoint.m"
#undef main
#include <stdio.h>
#include <stdlib.h>

static unsigned checks;
#define CHECK(value) do { checks++; if (!(value)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #value); exit(1); } } while (0)

typedef struct {
    struct mach_header_64 header;
    struct uuid_command uuid;
    struct segment_command_64 segment;
    struct section_64 section;
} Fixture;

static Fixture fixture(unsigned image) {
    Fixture f = {0};
    f.header = (struct mach_header_64){.magic = MH_MAGIC_64, .cputype = CPU_TYPE_ARM64,
        .cpusubtype = CPU_SUBTYPE_ARM64_ALL, .ncmds = 2, .sizeofcmds = sizeof(f) - sizeof(f.header)};
    f.uuid.cmd = LC_UUID; f.uuid.cmdsize = sizeof(f.uuid);
    memcpy(f.uuid.uuid, keystore_images[image].uuid, sizeof(f.uuid.uuid));
    f.segment = (struct segment_command_64){.cmd = LC_SEGMENT_64,
        .cmdsize = sizeof(f.segment) + sizeof(f.section), .vmaddr = 0x100000,
        .vmsize = 0x80000, .initprot = VM_PROT_READ | VM_PROT_EXECUTE, .nsects = 1};
    strcpy(f.segment.segname, "__TEXT");
    strcpy(f.section.segname, "__TEXT"); strcpy(f.section.sectname, "__text");
    f.section.addr = 0x101000; f.section.size = 0x7f000;
    f.section.flags = S_ATTR_PURE_INSTRUCTIONS;
    return f;
}

static void *resolve_fixture(Fixture f, const MappedSymbol *symbol) {
    return image_symbol(&f, sizeof(f), 0x200000, 0x100000, symbol);
}

typedef struct {
    unsigned char bytes[2048];
    size_t length;
    uint64_t offsets[2], delta;
    bool wide;
} CacheFixture;

static CacheSymbolsInfo cache_info(CacheFixture *f) {
    CacheSymbolsInfo info;
    memcpy(&info, f->bytes, sizeof(info));
    return info;
}

static void cache_put_info(CacheFixture *f, CacheSymbolsInfo info) {
    memcpy(f->bytes, &info, sizeof(info));
}

static struct nlist_64 cache_nlist(CacheFixture *f, unsigned index) {
    CacheSymbolsInfo info = cache_info(f);
    struct nlist_64 entry;
    memcpy(&entry, f->bytes + info.nlist_offset + index * sizeof(entry), sizeof(entry));
    return entry;
}

static void cache_put_nlist(CacheFixture *f, unsigned index, struct nlist_64 entry) {
    CacheSymbolsInfo info = cache_info(f);
    memcpy(f->bytes + info.nlist_offset + index * sizeof(entry), &entry, sizeof(entry));
}

static CacheFixture cache_fixture(bool wide, uint64_t delta) {
    CacheFixture f = {.offsets = {0x1000, wide ? 0x100001000ULL : 0x101000},
                      .delta = delta, .wide = wide};
    unsigned count = sizeof(keystore_symbols) / sizeof(*keystore_symbols);
    unsigned entry_size = wide ? 16 : 12;
    CacheSymbolsInfo info = {.entries_offset = sizeof(info), .entries_count = 2,
        .nlist_offset = sizeof(info) + 2 * entry_size, .nlist_count = count};
    info.strings_offset = info.nlist_offset + count * sizeof(struct nlist_64);
    unsigned starts[] = {0, 14}, counts[] = {14, 4};
    for (unsigned i = 0; i < 2; i++) {
        unsigned char *entry = f.bytes + info.entries_offset + i * entry_size;
        memcpy(entry, &f.offsets[i], wide ? 8 : 4);
        memcpy(entry + entry_size - 8, &starts[i], 4);
        memcpy(entry + entry_size - 4, &counts[i], 4);
    }
    info.strings_size = 1;
    for (unsigned i = 0; i < count; i++) {
        const MappedSymbol *s = &keystore_symbols[i];
        struct nlist_64 entry = {.n_type = N_SECT, .n_sect = 1,
            .n_value = 0x100000 + f.offsets[s->image] + s->offset + delta};
        entry.n_un.n_strx = info.strings_size;
        int size = snprintf((char *)f.bytes + info.strings_offset + info.strings_size,
                            sizeof(f.bytes) - info.strings_offset - info.strings_size, "_%s", s->name);
        CHECK(size > 0 && (size_t)size < sizeof(f.bytes) - info.strings_offset - info.strings_size);
        info.strings_size += (unsigned)size + 1;
        memcpy(f.bytes + info.nlist_offset + i * sizeof(entry), &entry, sizeof(entry));
    }
    f.length = info.strings_offset + info.strings_size;
    cache_put_info(&f, info);
    return f;
}

static Fixture cache_image(CacheFixture *cache, unsigned image) {
    Fixture f = fixture(image);
    f.header.filetype = MH_DYLIB; f.header.flags = MH_DYLIB_IN_CACHE;
    f.uuid.uuid[0] ^= 0xa5; // These images intentionally do not match the fixed map.
    f.segment.vmaddr = 0x100000 + cache->offsets[image];
    f.section.addr = f.segment.vmaddr + 0x1000;
    return f;
}

static CacheFixture *api_cache;
static CacheSymbols api_symbols;
static unsigned api_fallback_calls;
static void *cache_api_fallback(const char *name) {
    api_fallback_calls++;
    const MappedSymbol *s = find_symbol(name);
    if (!s) return NULL;
    Fixture image = cache_image(api_cache, s->image);
    CacheSymbolResult result;
    return cache_image_symbol(&api_symbols, api_cache->offsets[s->image], &image,
                              sizeof(image), 0x100000, name, &result);
}

static void *cache_api_export(void *library, const char *name) {
    (void)library;
    return !strcmp(name, "aks_create_bag") ? (void *)0x44444000 : NULL;
}

static void test_cache_tables(void) {
    for (unsigned wide = 0; wide < 2; wide++) {
        CacheFixture original = cache_fixture(wide, wide ? 0x1000 : 4);
        CacheSymbols table;
        CHECK(cache_symbols(original.bytes, original.length, wide, &table));
        for (size_t i = 0; i < sizeof(keystore_symbols) / sizeof(*keystore_symbols); i++) {
            const MappedSymbol *s = &keystore_symbols[i];
            CacheSymbol value; CacheSymbolResult result;
            CHECK(cache_find_symbol(&table, original.offsets[s->image], s->name, &value) == CACHE_SYMBOL_FOUND);
            CHECK(value.value == 0x100000 + original.offsets[s->image] + s->offset + original.delta);
            Fixture image = cache_image(&original, s->image);
            CHECK(!image_symbol(&image, sizeof(image), image.segment.vmaddr + 0x100000,
                                 0x100000, s));
            CHECK(cache_image_symbol(&table, original.offsets[s->image], &image, sizeof(image),
                                      0x100000, s->name, &result) == (void *)(uintptr_t)(value.value + 0x100000));
            image.header.cpusubtype = CPU_SUBTYPE_ARM64E;
            CHECK(cache_image_symbol(&table, original.offsets[s->image], &image, sizeof(image),
                                      0x100000, s->name, &result) != NULL);
            image.header.flags = 0;
            CHECK(!cache_image_symbol(&table, original.offsets[s->image], &image, sizeof(image),
                                       0x100000, s->name, &result));
        }
        api_cache = &original; api_symbols = table; api_fallback_calls = 0;
        KeyStore keys = {0};
        CHECK(load_keystore(&keys, NULL, dlsym, cache_api_fallback).count == 0);
        CHECK(api_fallback_calls == 18 && keys.create_bag && keys.params_create && keys.remote_session);
        api_fallback_calls = 0;
        CHECK(load_keystore(&keys, (void *)1, cache_api_export, cache_api_fallback).count == 0);
        CHECK(api_fallback_calls == 17 && (void *)keys.create_bag == (void *)0x44444000);
        CacheSymbol value;
        CHECK(cache_find_symbol(&table, original.offsets[0], "aks_create_bag_extra", &value) == CACHE_SYMBOL_MISSING);
        CHECK(cache_find_symbol(&table, original.offsets[0] + 4, "aks_create_bag", &value) == CACHE_SYMBOL_MISSING);
        for (size_t length = 0; length < original.length; length++)
            CHECK(!cache_symbols(original.bytes, length, wide, &table));
        CacheFixture bad = original;
        CacheSymbolsInfo info = cache_info(&bad);
#define BAD_TABLE(change) do { bad = original; info = cache_info(&bad); change; cache_put_info(&bad, info); \
    CHECK(!cache_symbols(bad.bytes, bad.length, wide, &table)); } while (0)
        BAD_TABLE(info.nlist_count = UINT32_MAX);
        BAD_TABLE(info.entries_count = UINT32_MAX);
        BAD_TABLE(info.nlist_offset = UINT32_MAX);
        BAD_TABLE(info.strings_size = UINT32_MAX);
        BAD_TABLE(info.strings_offset = 0);
        BAD_TABLE(info.entries_offset = info.nlist_offset);
#undef BAD_TABLE
        for (unsigned invalid = 0; invalid < 5; invalid++) {
            bad = original;
            struct nlist_64 entry = cache_nlist(&bad, 0);
            if (invalid == 0) entry.n_un.n_strx = UINT32_MAX;
            if (invalid == 1) entry.n_type = N_ABS;
            if (invalid == 2) entry.n_type |= N_STAB;
            if (invalid == 3) entry.n_sect = 0;
            if (invalid == 4) entry.n_value++;
            cache_put_nlist(&bad, 0, entry);
            CHECK(cache_symbols(bad.bytes, bad.length, wide, &table));
            CHECK(cache_find_symbol(&table, bad.offsets[0], "aks_create_bag", &value) == CACHE_SYMBOL_INVALID);
        }
        bad = original;
        cache_put_nlist(&bad, 1, cache_nlist(&bad, 0));
        CHECK(cache_symbols(bad.bytes, bad.length, wide, &table));
        CHECK(cache_find_symbol(&table, bad.offsets[0], "aks_create_bag", &value) == CACHE_SYMBOL_FOUND);
        struct nlist_64 duplicate = cache_nlist(&bad, 1); duplicate.n_value += 4;
        cache_put_nlist(&bad, 1, duplicate);
        CHECK(cache_find_symbol(&table, bad.offsets[0], "aks_create_bag", &value) == CACHE_SYMBOL_INVALID);
        bad = original; info = cache_info(&bad);
        memcpy(bad.bytes + info.entries_offset + (wide ? 16 : 12), &bad.offsets[0], wide ? 8 : 4);
        CHECK(cache_symbols(bad.bytes, bad.length, wide, &table));
        CHECK(cache_find_symbol(&table, bad.offsets[0], "aks_create_bag", &value) == CACHE_SYMBOL_INVALID);
        bad = original;
        CHECK(cache_symbols(bad.bytes, bad.length, wide, &table));
        Fixture image = cache_image(&bad, 0); CacheSymbolResult result;
        struct nlist_64 entry = cache_nlist(&bad, 0); entry.n_sect = 2;
        cache_put_nlist(&bad, 0, entry);
        CHECK(!cache_image_symbol(&table, bad.offsets[0], &image, sizeof(image), 0x100000,
                                   "aks_create_bag", &result));
        entry.n_sect = 1; entry.n_value = image.segment.vmaddr + image.segment.vmsize;
        cache_put_nlist(&bad, 0, entry);
        CHECK(!cache_image_symbol(&table, bad.offsets[0], &image, sizeof(image), 0x100000,
                                   "aks_create_bag", &result));
    }
}

static void cache_header_bytes(unsigned char bytes[CACHE_HEADER_BYTES], bool wide,
                               const unsigned char uuid[16], const unsigned char *symbols_uuid,
                               const CacheFixture *symbols) {
    memset(bytes, 0, CACHE_HEADER_BYTES);
    memcpy(bytes, "dyld_v1   arm64", 16);
    uint32_t mapping = wide ? 456 : 312;
    memcpy(bytes + 16, &mapping, 4); memcpy(bytes + CACHE_UUID_OFFSET, uuid, 16);
    if (symbols) {
        uint64_t offset = 4096 + 32, size = symbols->length;
        memcpy(bytes + 72, &offset, 8); memcpy(bytes + 80, &size, 8);
    }
    if (symbols_uuid) memcpy(bytes + CACHE_SYMBOL_UUID_OFFSET, symbols_uuid, 16);
}

static void write_cache_fixture(const char *path, bool wide, const unsigned char uuid[16],
                                 const unsigned char *symbols_uuid, CacheFixture *symbols) {
    unsigned char header[CACHE_HEADER_BYTES];
    cache_header_bytes(header, wide, uuid, symbols_uuid, symbols);
    int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    CHECK(fd >= 0);
    CHECK(pwrite(fd, header, sizeof(header), 0) == (ssize_t)sizeof(header));
    if (symbols) CHECK(pwrite(fd, symbols->bytes, symbols->length, 4096 + 32) == (ssize_t)symbols->length);
    CHECK(close(fd) == 0);
}

static void test_cache_files(void) {
    unsigned char uuid[16] = {1}, symbols_uuid[16] = {2};
    CacheFixture symbols = cache_fixture(true, 0x1000);
    unsigned char bytes[CACHE_HEADER_BYTES]; CacheHeader header;
    cache_header_bytes(bytes, true, uuid, symbols_uuid, &symbols);
    CHECK(cache_header(bytes, sizeof(bytes), &header) && header.wide_entries);
    for (size_t length = 0; length < sizeof(bytes); length++) CHECK(!cache_header(bytes, length, &header));
    memcpy(bytes, "dyld_v1  arm64e", 16);
    CHECK(cache_header(bytes, sizeof(bytes), &header));
    bytes[0] = 'x'; CHECK(!cache_header(bytes, sizeof(bytes), &header));
    cache_header_bytes(bytes, false, uuid, NULL, &symbols);
    CHECK(cache_header(bytes, CACHE_UUID_OFFSET + 16, &header) && !header.wide_entries);
    memset(bytes + CACHE_UUID_OFFSET, 0, 16); CHECK(!cache_header(bytes, sizeof(bytes), &header));
    char directory[] = "/tmp/mirra-symbols-XXXXXX";
    CHECK(mkdtemp(directory) != NULL);
    char main[PATH_MAX], companion[PATH_MAX], link[PATH_MAX];
    CHECK(snprintf(main, sizeof(main), "%s/cache", directory) > 0);
    CHECK(snprintf(companion, sizeof(companion), "%s/cache.symbols", directory) > 0);
    CHECK(snprintf(link, sizeof(link), "%s/link", directory) > 0);
    write_cache_fixture(main, true, uuid, NULL, &symbols);
    cache_header_bytes(bytes, true, uuid, NULL, &symbols);
    CHECK(cache_header(bytes, sizeof(bytes), &header));
    CacheSymbolsFile file = {0}; const char *error;
    CHECK(open_active_cache_symbols(main, &header, &file, &error) && !error);
    CacheSymbol value;
    CHECK(cache_find_symbol(&file.symbols, symbols.offsets[0], "aks_create_bag", &value) == CACHE_SYMBOL_FOUND);
    close_cache_symbols(&file); CHECK(!file.mapping);
    CHECK(find_cache_symbols(main, &header, &file, &error) && !error);
    close_cache_symbols(&file);
    header.uuid[0] ^= 4;
    CHECK(!open_active_cache_symbols(main, &header, &file, &error));
    CHECK(!strcmp(error, "cache_symbols_uuid_mismatch")); header.uuid[0] ^= 4;
    CHECK(chmod(main, 0660) == 0);
    CHECK(!open_active_cache_symbols(main, &header, &file, &error));
    CHECK(chmod(main, 0600) == 0);
    CHECK(symlink(main, link) == 0);
    CHECK(!open_active_cache_symbols(link, &header, &file, &error));
    CHECK(unlink(link) == 0);
    CHECK(mkfifo(link, 0600) == 0);
    CHECK(!open_active_cache_symbols(link, &header, &file, &error));
    CHECK(unlink(link) == 0);
    CHECK(unlink(main) == 0);
    write_cache_fixture(main, true, uuid, symbols_uuid, NULL);
    write_cache_fixture(companion, true, symbols_uuid, NULL, &symbols);
    cache_header_bytes(bytes, true, uuid, symbols_uuid, NULL);
    CHECK(cache_header(bytes, sizeof(bytes), &header));
    CHECK(open_active_cache_symbols(main, &header, &file, &error)); close_cache_symbols(&file);
    CHECK(unlink(main) == 0);
    CHECK(open_active_cache_symbols(main, &header, &file, &error)); close_cache_symbols(&file);
    header.symbols_uuid[0] ^= 4;
    CHECK(!open_active_cache_symbols(main, &header, &file, &error));
    CHECK(!strcmp(error, "cache_symbols_uuid_mismatch"));
    CHECK(unlink(companion) == 0 && rmdir(directory) == 0);
}

typedef struct { Fixture image; struct segment_command_64 linkedit; struct symtab_command table; } LiveFixture;

static void test_loaded_symbols(void) {
    unsigned char memory[16384] __attribute__((aligned(16))) = {0};
    unsigned char *loaded = memory + 1024;
    intptr_t slide = 0x1000;
    LiveFixture image = {.image = fixture(0)};
    image.image.header.filetype = MH_DYLIB; image.image.header.flags = MH_DYLIB_IN_CACHE;
    image.image.header.ncmds = 4;
    image.image.header.sizeofcmds = sizeof(image) - sizeof(image.image.header);
    image.image.segment.vmaddr = (uintptr_t)loaded - slide; image.image.segment.vmsize = 4096;
    image.image.section.addr = image.image.segment.vmaddr + 512; image.image.section.size = 1024;
    image.linkedit = (struct segment_command_64){.cmd = LC_SEGMENT_64, .cmdsize = sizeof(image.linkedit),
        .vmaddr = image.image.segment.vmaddr + 4096, .vmsize = 4096, .fileoff = 0x50000,
        .filesize = 4096, .initprot = VM_PROT_READ};
    strcpy(image.linkedit.segname, "__LINKEDIT");
    image.table = (struct symtab_command){.cmd = LC_SYMTAB, .cmdsize = sizeof(image.table),
        .symoff = 0x50080, .nsyms = 1, .stroff = 0x50200, .strsize = sizeof("_aks_create_bag")};
    struct nlist_64 symbol = {.n_type = N_SECT, .n_sect = 1,
        .n_value = image.image.segment.vmaddr + 1024};
    memcpy(loaded + 4096 + 128, &symbol, sizeof(symbol));
    memcpy(loaded + 4096 + 512, "_aks_create_bag", sizeof("_aks_create_bag"));
    memcpy(loaded, &image, sizeof(image));
    CacheSymbolResult result;
    CHECK(live_cache_symbol(loaded, sizeof(image), slide, memory, sizeof(memory),
                            "aks_create_bag", &result) == loaded + 1024);
    CHECK(result == CACHE_SYMBOL_FOUND);
    CHECK(!live_cache_symbol(loaded, sizeof(image), slide, memory, sizeof(memory), "aks_unknown", &result));
    CHECK(result == CACHE_SYMBOL_MISSING);
    for (unsigned failure = 0; failure < 8; failure++) {
        LiveFixture bad = image;
        if (failure == 0) bad.table.symoff = 0;
        if (failure == 1) bad.table.stroff = 0x50fff;
        if (failure == 2) bad.table.nsyms = UINT32_MAX;
        if (failure == 3) bad.linkedit.vmsize = sizeof(memory);
        if (failure == 4) bad.linkedit.initprot = 0;
        if (failure == 5) bad.table.cmdsize = 0;
        if (failure == 6) bad.image.header.cputype = CPU_TYPE_X86_64;
        if (failure == 7) bad.image.header.flags = 0;
        memcpy(loaded, &bad, sizeof(bad));
        CHECK(!live_cache_symbol(loaded, sizeof(bad), slide, memory, sizeof(memory), "aks_create_bag", &result));
        CHECK(result == CACHE_SYMBOL_INVALID);
    }
    image.table.nsyms = 0;
    memcpy(loaded, &image, sizeof(image));
    CHECK(!live_cache_symbol(loaded, sizeof(image), slide, memory, sizeof(memory), "aks_create_bag", &result));
    CHECK(result == CACHE_SYMBOL_MISSING);
}

static void test_discovery_platform(void) {
    const char *versions[] = {"15", "15.0", "15.0.1", "15.1", "15.2", "15.3", "15.4", "15.5",
                             "15.6", "15.7", "15.8", "15.8.6", "15.8.8", "15.999.123"};
    for (unsigned i = 0; i < sizeof(versions) / sizeof(*versions); i++) {
        CHECK(cache_discovery_supported(versions[i], "unlisted-build", "arm64"));
        CHECK(cache_discovery_supported(versions[i], "unlisted-build", "arm64e"));
    }
    const char *invalid[] = {"", "1", "14.8", "16.0", "150", "15.", "15.x", "15..1", "15.1beta"};
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(*invalid); i++)
        CHECK(!cache_discovery_supported(invalid[i], "unavailable", "arm64"));
    CHECK(cache_discovery_supported("unavailable", "19A346", "arm64"));
    CHECK(cache_discovery_supported("unavailable", "19H402", "arm64"));
    CHECK(cache_discovery_supported(NULL, "19H422", "arm64e"));
    CHECK(!cache_discovery_supported("16.0", "19H422", "arm64"));
    CHECK(!cache_discovery_supported("unavailable", "19", "arm64"));
    CHECK(!cache_discovery_supported("unavailable", NULL, "arm64"));
    CHECK(!cache_discovery_supported("15.0", "19A346", "x86_64"));
    CHECK(!cache_discovery_supported("15.0", "19A346", NULL));
    CacheRuntime runtime = cache_runtime();
    CHECK(runtime.range && runtime.uuid && runtime.path);
    size_t size = 0; const void *base = runtime.range(&size);
    unsigned char uuid[16];
    CHECK(base && size >= CACHE_UUID_OFFSET + 16 && runtime.uuid(uuid));
    CHECK(!memcmp((const unsigned char *)base + CACHE_UUID_OFFSET, uuid, 16));
}

int main(void) {
    CHECK(symbol_map_supported("19H422", "arm64"));
    CHECK(!symbol_map_supported("19H421", "arm64")); CHECK(!symbol_map_supported("19H422x", "arm64"));
    CHECK(!symbol_map_supported(NULL, "arm64")); CHECK(!find_symbol(NULL));
    CHECK(!find_symbol("aks_unknown"));
    CHECK(!symbol_map_supported("19H422", "arm64e"));
    CHECK(!symbol_map_supported("19H422", "x86_64"));
    CHECK(!symbol_map_supported("19H422", NULL));
    CHECK(!mapped_keystore_symbol("aks_create_bag")); // Host never enables the fallback.
    for (size_t i = 0; i < sizeof(keystore_symbols) / sizeof(*keystore_symbols); i++) {
        const MappedSymbol *s = &keystore_symbols[i];
        Fixture f = fixture(s->image);
        CHECK(find_symbol(s->name) == s);
        CHECK(resolve_fixture(f, s) == (void *)(0x200000 + s->offset));
        CHECK(image_symbol(&f, sizeof(f), 0x80000, -0x80000, s) == (void *)(0x80000 + s->offset));
        f.uuid.uuid[0] ^= 1;
        CHECK(!resolve_fixture(f, s));
    }
    const MappedSymbol *s = find_symbol("aks_create_bag");
    Fixture f = fixture(0);
    for (size_t n = 0; n < sizeof(f); n++)
        CHECK(!image_symbol(&f, n, 0x200000, 0x100000, s));
    CHECK(!image_symbol(NULL, sizeof(f), 0x200000, 0x100000, s));
    CHECK(!image_symbol(&f, sizeof(f), 0x200000, 0x100000, NULL));
    CHECK(!image_symbol(&f, sizeof(f), UINTPTR_MAX - 3, 0, s));
    CHECK(!image_symbol(&f, sizeof(f), 0x200001, 0x100000, s));
#define REJECT(change) do { f = fixture(0); change; CHECK(!resolve_fixture(f, s)); } while (0)
    REJECT(f.header.magic = MH_CIGAM_64);
    REJECT(f.header.cputype = CPU_TYPE_X86_64);
    REJECT(f.header.cpusubtype = CPU_SUBTYPE_ARM64E);
    REJECT(f.header.ncmds = 1);
    REJECT(f.header.ncmds = 3);
    REJECT(f.header.sizeofcmds = UINT32_MAX);
    REJECT(f.uuid.cmdsize = 0);
    REJECT(f.uuid.cmdsize = UINT32_MAX);
    REJECT(f.uuid.cmdsize -= 1);
    REJECT(f.uuid.cmd = LC_CODE_SIGNATURE);
    REJECT(f.segment.cmdsize -= sizeof(f.section));
    REJECT(f.segment.nsects = UINT32_MAX);
    REJECT(f.segment.initprot = VM_PROT_READ);
    REJECT(strcpy(f.segment.segname, "__DATA"));
    REJECT(f.segment.vmaddr = UINT64_MAX - 2);
    REJECT(f.segment.vmsize = 3);
    REJECT(f.section.addr = 0x100000 + s->offset + 4);
    REJECT(f.section.size = 3);
    REJECT(f.section.addr = 0x100000; f.section.size = s->offset + 3);
    REJECT(f.section.addr = UINT64_MAX - 2);
    REJECT(f.section.flags = 0);
    REJECT(strcpy(f.section.sectname, "__cstring"));
    REJECT(strcpy(f.section.segname, "__DATA"));
    uintptr_t address;
    CHECK(!slid_address(0, -1, &address));
    CHECK(!slid_address(UINT64_MAX, 1, &address));
    CHECK(!slid_address(0, INTPTR_MIN, &address));
    CHECK(slid_address(0x100000, -0x80000, &address) && address == 0x80000);
    test_discovery_platform();
    test_cache_tables();
    test_cache_files();
    test_loaded_symbols();
    printf("PASS: %u keystore symbol-map guard checks (no private functions executed)\n", checks);
    return 0;
}
