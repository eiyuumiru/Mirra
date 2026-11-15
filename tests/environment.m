#import "../src/tools/environment.m"
#include <stdio.h>
#include <stdlib.h>

static unsigned checks;
static void require(BOOL condition, const char *message) {
    checks++;
    if (!condition) { fprintf(stderr, "%s\n", message); exit(1); }
}

int main(void) {
    @autoreleasepool {
        uint8_t picture[] = {0, 0, 0, 2, 0x65, 0x80};
        NSData *unit = [NSData dataWithBytes:picture length:sizeof(picture)];
        require(valid_access_unit(unit), "valid IDR rejected");
        require(!valid_access_unit(nil), "missing sample accepted");
        for (size_t size = 0; size < sizeof(picture); size++)
            require(!valid_access_unit([unit subdataWithRange:NSMakeRange(0, size)]), "truncated sample accepted");
        uint8_t empty[] = {0, 0, 0, 0};
        require(!valid_access_unit([NSData dataWithBytes:empty length:sizeof(empty)]), "empty NAL accepted");
        picture[0] = 0x80;
        require(!valid_access_unit([NSData dataWithBytes:picture length:sizeof(picture)]), "oversized NAL accepted");
        picture[0] = 0; picture[4] = 0xe5;
        require(!valid_access_unit([NSData dataWithBytes:picture length:sizeof(picture)]), "forbidden bit accepted");
        picture[4] = 0x06;
        require(!valid_access_unit([NSData dataWithBytes:picture length:sizeof(picture)]), "non-picture sample accepted");
        NSDictionary *report = MirraHostEnvironmentReport();
        require([report[@"probe"] isEqual:@"host-environment"], "probe identity changed");
        require(report[@"native_mirroring_verified"] == NSNull.null, "probe claims Mirroring verification");
        for (NSString *name in @[@"default", @"hardware_required"]) {
            NSDictionary *decoder = report[@"h264"][name];
            require([decoder[@"fixture_valid"] boolValue], "embedded frame is invalid");
            require([decoder[@"format_status"] intValue] == 0, "SPS/PPS format invalid");
            require(CFGetTypeID((__bridge CFTypeRef)decoder[@"frame_decoded"]) == CFBooleanGetTypeID(),
                    "frame result is not a JSON boolean");
            if (decoder[@"gpu_query_status"]) {
                require([decoder[@"gpu_query_status"] isKindOfClass:NSNumber.class], "GPU query status is invalid");
                require(decoder[@"gpu_name"] == NSNull.null ||
                        ([decoder[@"gpu_query_status"] intValue] == 0 && [decoder[@"gpu_name"] isKindOfClass:NSString.class]),
                        "GPU name lacks a successful property query");
            }
            require(!decoder[@"registry_id"], "probe exports a registry ID");
        }
        // Driver availability is an observation, not a fixture pass criterion.
        printf("%u host observation fixture checks passed\n", checks);
        return 0;
    }
}
