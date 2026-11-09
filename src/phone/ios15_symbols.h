// ponytail: experimental iOS 15.8.8/19H422 arm64 only; other builds need new verified maps.
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <uuid/uuid.h>

static void *ios15_symbol(const char *name) {
#if TARGET_OS_IPHONE && defined(__arm64__) && !defined(__arm64e__)
    if (![system_value("kern.osversion") isEqualToString:@"19H422"]) return NULL;
    static const struct { const char *name; unsigned image; uintptr_t offset; } symbols[] = {
    {"aks_create_bag", 0, 0x22a00},
    {"aks_unload_bag", 0, 0x22de8},
    {"aks_create_signing_key", 0, 0x24fac},
    {"aks_create_signing_key_with_params", 0, 0x250f4},
    {"aks_sign_signing_key", 0, 0x253d8},
    {"aks_remote_session", 0, 0x25588},
    {"aks_remote_session_step", 0, 0x2587c},
    {"aks_remote_session_reset", 0, 0x25f08},
    {"aks_remote_session_token", 0, 0x258dc},
    {"aks_remote_peer_confirm", 0, 0x258c4},
    {"aks_remote_peer_setup", 0, 0x25894},
    {"aks_validate_local_key", 0, 0x256a8},
    {"aks_remote_peer_get_state", 0, 0x25f54},
    {"aks_remote_peer_drop", 0, 0x26134},
    {"aks_params_create", 1, 0x3b8d4},
    {"aks_params_set_data", 1, 0x3bb34},
    {"aks_params_set_number", 1, 0x3bac0},
    {"aks_params_get_der", 1, 0x3bc2c},
    };
    static const char *paths[] = {
        "/System/Library/PrivateFrameworks/MobileKeyBag.framework/MobileKeyBag",
        "/System/Library/Frameworks/CryptoTokenKit.framework/CryptoTokenKit"
    };
    static const char *uuids[] = {
        "693C0317-A820-3D3F-B47C-8AB6555E1371",
        "8F3F79E7-9261-3F8E-99DB-060F61009B79"
    };
    for (size_t s = 0; s < sizeof(symbols)/sizeof(symbols[0]); s++) {
        if (strcmp(name, symbols[s].name)) continue;
        unsigned image = symbols[s].image;
        // Keep handles open: returned addresses must remain mapped.
        static void *handles[2];
        if (!handles[image]) handles[image] = dlopen(paths[image], RTLD_LAZY | RTLD_LOCAL);
        if (!handles[image]) return NULL;
        for (uint32_t i = 0; i < _dyld_image_count(); i++) {
            if (strcmp(_dyld_get_image_name(i), paths[image])) continue;
            const struct mach_header_64 *h = (const void *)_dyld_get_image_header(i);
            if (h->magic != MH_MAGIC_64) return NULL;
            const uint8_t *p = (const void *)(h + 1), *end = p + h->sizeofcmds;
            BOOL uuid_ok = NO, text_ok = NO;
            uintptr_t address = (uintptr_t)h + symbols[s].offset;
            for (uint32_t n = 0; n < h->ncmds; n++) {
                if ((size_t)(end - p) < sizeof(struct load_command)) return NULL;
                const struct load_command *lc = (const void *)p;
                if (lc->cmdsize < sizeof(*lc) || lc->cmdsize > (size_t)(end-p)) return NULL;
                if (lc->cmd == LC_UUID && lc->cmdsize >= sizeof(struct uuid_command)) {
                    uuid_string_t actual;
                    uuid_unparse_upper(((const struct uuid_command *)p)->uuid, actual);
                    uuid_ok = !strcmp(actual, uuids[image]);
                }
                if (lc->cmd == LC_SEGMENT_64 && lc->cmdsize >= sizeof(struct segment_command_64)) {
                    const struct segment_command_64 *seg = (const void *)p;
                    uintptr_t start = seg->vmaddr + _dyld_get_image_vmaddr_slide(i);
                    if (!strncmp(seg->segname, "__TEXT", 16) && (seg->initprot & 4) &&
                        address >= start && address - start < seg->vmsize && !(address & 3)) text_ok = YES;
                }
                p += lc->cmdsize;
            }
            return uuid_ok && text_ok ? (void *)address : NULL;
        }
        return NULL;
    }
#else
    (void)name;
#endif
    return NULL;
}
