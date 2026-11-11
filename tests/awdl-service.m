// Only fixture classes in this process are modified. No Apple app is launched.
#include "../src/mirroring/awdl-service.m"
#include <stdio.h>

static unsigned checks, releases, calls;
#define CHECK(value) do { checks++; if (!(value)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #value); exit(1); } } while (0)

@interface ReservationFixture : NSObject
@property(copy) NSString *service;
- (instancetype)initForService:(NSString *)service;
@end
@implementation ReservationFixture
- (instancetype)initForService:(NSString *)service {
    self = [super init];
    if (self) { calls++; self.service = service; }
    return self;
}
- (void)dealloc { releases++; }
@end

// Use the production class and export names so the public lookup is tested.
@interface WiFiP2PTrafficRegistrationReservation : ReservationFixture @end
@implementation WiFiP2PTrafficRegistrationReservation @end

@interface BadReservationFixture : NSObject
- (int)initForService:(int)service;
@end
@implementation BadReservationFixture
- (int)initForService:(int)service { return service; }
@end

__attribute__((naked, noinline, used)) void AWDLTrafficRegistrationServiceRemoteScreen(void) {
    __asm__(".byte 0x55,0x48,0x89,0xe5,0x31,0xc0,0x5d,0xc3");
}
__attribute__((naked, noinline, used)) static void other_stub(void) {
    __asm__(".byte 0x55,0x48,0x89,0xe5,0x31,0xc9,0x5d,0xc3");
}

int main(void) {
    @autoreleasepool {
        Class parent = [ReservationFixture class], target = [WiFiP2PTrafficRegistrationReservation class];
        SEL selector = @selector(initForService:);
        IMP before = class_getMethodImplementation(parent, selector);
        NSString *stock = @"RemoteScreen";
        const unsigned char data_stub[] = {0x55,0x48,0x89,0xe5,0x31,0xc0,0x5d,0xc3};
        CHECK(known_stub(AWDLTrafficRegistrationServiceRemoteScreen));
        CHECK(!known_stub(other_stub)); CHECK(!known_stub(NULL));
        CHECK(!known_stub(&stock)); CHECK(!known_stub(data_stub));
        CHECK(!install_repair(Nil, AWDLTrafficRegistrationServiceRemoteScreen));
        CHECK(!install_repair([NSObject class], AWDLTrafficRegistrationServiceRemoteScreen));
        CHECK(!install_repair([BadReservationFixture class], AWDLTrafficRegistrationServiceRemoteScreen));
        CHECK(!install_repair(target, &stock));
        CHECK(!install_repair(target, other_stub));
        CHECK(class_getMethodImplementation(target, selector) == before);
        CHECK(MirraRepairAWDLService());
        CHECK(MirraRepairAWDLService()); // Idempotent; no recursive IMP.
        CHECK(class_getMethodImplementation(parent, selector) == before);
        CHECK(!install_repair(parent, AWDLTrafficRegistrationServiceRemoteScreen));
        // Preserve init ownership even for a value that would crash on retain.
        uintptr_t poison = 0;
        memcpy(&poison, AWDLTrafficRegistrationServiceRemoteScreen, sizeof(poison));
        __unsafe_unretained id invalid = (__bridge id)(void *)poison;
        ReservationInit init = (ReservationInit)class_getMethodImplementation(target, selector);
        __weak ReservationFixture *weak = nil;
        @autoreleasepool {
            ReservationFixture *object = init([target alloc], selector, invalid);
            weak = object;
            CHECK([object.service isEqualToString:@"RemoteScreen"]);
            CHECK(calls == 1);
        }
        CHECK(!weak); CHECK(releases == 1);
        @autoreleasepool {
            NSMutableString *ordinary = [NSMutableString stringWithString:@"AirPlay"];
            ReservationFixture *object = [[WiFiP2PTrafficRegistrationReservation alloc] initForService:ordinary];
            [ordinary appendString:@" changed"];
            CHECK([object.service isEqualToString:@"AirPlay"]);
            ReservationFixture *empty = [[WiFiP2PTrafficRegistrationReservation alloc] initForService:nil];
            CHECK(empty.service == nil);
            ReservationFixture *stockObject = [[WiFiP2PTrafficRegistrationReservation alloc] initForService:stock];
            CHECK([stockObject.service isEqualToString:stock]);
            CHECK(calls == 4);
        }
        CHECK(releases == 4);
    }
    printf("PASS: %u AWDL repair checks (fixture classes only)\n", checks);
    return 0;
}
