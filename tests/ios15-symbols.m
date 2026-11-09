// Device-only self-check. Build with the same flags as endpoint-ios15.
#ifdef NDEBUG
#error "ios15-symbols requires assertions; do not compile with NDEBUG"
#endif
#define MIRRA_EXPERIMENTAL_IOS15 1
#define main endpoint_main
#include "../src/phone/endpoint.m"
#undef main
#include <assert.h>

int main(void) {
    @autoreleasepool {
        assert(!ios15_symbol("not_an_aks_symbol"));
        CreateBag create = (CreateBag)ios15_symbol("aks_create_bag");
        UnloadBag unload = (UnloadBag)ios15_symbol("aks_unload_bag");
        CreateKey key = (CreateKey)ios15_symbol("aks_create_signing_key");
        ParamsCreate params = (ParamsCreate)ios15_symbol("aks_params_create");
        ParamsNumber number = (ParamsNumber)ios15_symbol("aks_params_set_number");
        ParamsData data = (ParamsData)ios15_symbol("aks_params_set_data");
        ParamsDER der = (ParamsDER)ios15_symbol("aks_params_get_der");
        assert(create && unload && key && params && number && data && der);
        // Unsaved bag only: never access the device's system keybag.
        uint8_t password[32];
        assert(SecRandomCopyBytes(kSecRandomDefault, sizeof(password), password) == 0);
        int bag = -1;
        int created = create(password, sizeof(password), 0, &bag);
        memset(password, 0, sizeof(password));
        printf("create_bag=%d\n", created);
        assert(created == 0 && bag >= 0);
        void *blob = NULL;
        size_t size = 0;
        int signed_key = key(bag, 9, &blob, &size);
        printf("create_signing_key=%d bytes=%zu\n", signed_key, size);
        clear_blob(blob, size);
        int unloaded = unload(bag);
        printf("unload_bag=%d\n", unloaded);
        assert(unloaded == 0);
        // ponytail: one params allocation; process exit reclaims it.
        void *p = params(NULL, 0);
        assert(p);
        int64_t flag = 4;
        const void *encoded = NULL;
        size_t length = 0;
        assert(number(p, 20, &flag) == 0);
        const unsigned char sample[] = {1, 2, 3};
        assert(data(p, 21, sample, sizeof(sample)) == 0);
        assert(der(p, &encoded, &length) == 0 && encoded && length);
        printf("params_roundtrip=ok bytes=%zu\n", length);
        assert(signed_key == 0 && size > 0);
        puts("PASS");
    }
    return 0;
}
