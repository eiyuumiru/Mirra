// Settings → Mirra Bridge on the bridge iPhone (a PreferenceLoader bundle).
//
// Shows the pairing token (with a Copy button), the service status and the
// Macs whose keys the bridge service keeps, and removes a saved Mac. The
// service publishes these values in the com.mirra.bridge preferences domain;
// a removal is requested through the same domain and a Darwin notification.
//
// Preferences.framework and UIKit are private/unavailable to this build, so
// the controller class is created at run time as a PSListController subclass
// and UIKit is reached through the Objective-C runtime only.
#import <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>
#include <objc/message.h>
#include <objc/runtime.h>

// Methods of Preferences.framework classes, reached through the runtime.
@interface NSObject (MirraPreferences)
- (void)reloadSpecifiers;
@end

static CFStringRef const MirraDomain = CFSTR("com.mirra.bridge");
static NSString *const MirraControllerName = @"MirraBridgeListController";
static Class list_controller;
static __weak id visible_controller;

enum { CellGroup = 0, CellTitleValue = 4, CellButton = 13 };
enum { AlertStyleAlert = 1, ActionStyleDefault = 0, ActionStyleCancel = 1, ActionStyleDestructive = 2 };

static void set_property(id row, id value, NSString *key) {
    ((void (*)(id, SEL, id, NSString *))objc_msgSend)(row, @selector(setProperty:forKey:), value, key);
}

static id get_property(id row, NSString *key) {
    return ((id (*)(id, SEL, NSString *))objc_msgSend)(row, @selector(propertyForKey:), key);
}

static id preference(NSString *key) {
    CFPreferencesSynchronize(MirraDomain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    return CFBridgingRelease(CFPreferencesCopyValue((__bridge CFStringRef)key, MirraDomain,
                                                    kCFPreferencesCurrentUser, kCFPreferencesAnyHost));
}

static NSString *text_preference(NSString *key, NSString *fallback) {
    id value = preference(key);
    return [value isKindOfClass:NSString.class] && [value length] ? value : fallback;
}

static id specifier(NSString *name, id target, SEL getter, NSInteger cell) {
    Class type = NSClassFromString(@"PSSpecifier");
    SEL create = @selector(preferenceSpecifierNamed:target:set:get:detail:cell:edit:);
    return ((id (*)(Class, SEL, NSString *, id, SEL, SEL, Class, NSInteger, Class))objc_msgSend)(
        type, create, name, target, NULL, getter, Nil, cell, Nil);
}

static id group(NSString *name, NSString *footer) {
    id value = ((id (*)(Class, SEL, NSString *))objc_msgSend)(NSClassFromString(@"PSSpecifier"),
                                                             @selector(groupSpecifierWithName:), name);
    if (footer) set_property(value, footer, @"footerText");
    return value;
}

static id value_row(NSString *name, NSString *value, id target, BOOL copyable) {
    id row = specifier(name, target, @selector(mirraValue:), CellTitleValue);
    set_property(row, value ?: @"", @"mirraValue");
    if (copyable) set_property(row, @YES, @"isCopyable");
    return row;
}

static id button_row(NSString *name, id target, SEL action) {
    id row = specifier(name, target, NULL, CellButton);
    if ([row respondsToSelector:@selector(setButtonAction:)]) {
        ((void (*)(id, SEL, SEL))objc_msgSend)(row, @selector(setButtonAction:), action);
    } else {
        Ivar ivar = class_getInstanceVariable(object_getClass(row), "action");
        if (ivar) *(SEL *)((uint8_t *)(__bridge void *)row + ivar_getOffset(ivar)) = action;
    }
    return row;
}

static NSArray *build_specifiers(id controller) {
    NSMutableArray *rows = [NSMutableArray array];
    [rows addObject:group(@"Pairing", @"Mirra on a Mac uses this token to open an encrypted connection to this "
                                      "phone. Setup over SSH saves it automatically; copy it only to pair another Mac.")];
    NSString *token = text_preference(@"token", @"—");
    [rows addObject:value_row(@"Token", token, controller, YES)];
    [rows addObject:button_row(@"Copy Token", controller, @selector(mirraCopyToken:))];

    [rows addObject:group(@"Service", nil)];
    [rows addObject:value_row(@"Status", text_preference(@"status", @"Not running"), controller, NO)];
    [rows addObject:value_row(@"Wi-Fi Address", text_preference(@"address", @"—"), controller, YES)];
    [rows addObject:value_row(@"Port", text_preference(@"port", @"—"), controller, NO)];

    id persistence = preference(@"persistence");
    BOOL saving = ![persistence isKindOfClass:NSNumber.class] || [persistence boolValue];
    NSArray *clients = preference(@"clients");
    if (![clients isKindOfClass:NSArray.class]) clients = [NSArray array];
    NSString *footer = saving
        ? @"Each Mac keeps its iPhone Mirroring keys on this phone, so restarting Mirra does not pair again. "
          "Removing a Mac deletes its keys; that Mac then sets up iPhone Mirroring again."
        : @"This iOS version cannot save keys, so each Mac pairs iPhone Mirroring again after Mirra restarts.";
    [rows addObject:group(@"Saved Macs", clients.count ? nil : footer)];
    if (!clients.count) [rows addObject:value_row(@"No saved Macs", @"", controller, NO)];
    for (NSUInteger index = 0; index < clients.count; index++) {
        NSDictionary *client = clients[index];
        if (![client isKindOfClass:NSDictionary.class] || ![client[@"id"] isKindOfClass:NSString.class]) continue;
        NSString *name = [client[@"name"] isKindOfClass:NSString.class] ? client[@"name"] : @"Mac";
        BOOL active = [client[@"active"] isKindOfClass:NSNumber.class] && [client[@"active"] boolValue];
        [rows addObject:group(name, index + 1 == clients.count ? footer : nil)];
        [rows addObject:value_row(@"Hardware UUID", client[@"id"], controller, YES)];
        NSString *seen = [client[@"last_seen"] isKindOfClass:NSString.class] ? client[@"last_seen"] : @"";
        [rows addObject:value_row(@"Last Used", active ? @"Connected now" : (seen.length ? seen : @"—"), controller, NO)];
        id remove = button_row(@"Remove This Mac", controller, @selector(mirraForget:));
        set_property(remove, client[@"id"], @"mirraClient");
        set_property(remove, name, @"mirraName");
        [rows addObject:remove];
    }
    return rows;
}

static Ivar specifiers_ivar(void) {
    return class_getInstanceVariable(NSClassFromString(@"PSListController"), "_specifiers");
}

static void reload(id controller) {
    Ivar ivar = specifiers_ivar();
    if (ivar) object_setIvar(controller, ivar, nil);
    if ([controller respondsToSelector:@selector(reloadSpecifiers)])
        ((void (*)(id, SEL))objc_msgSend)(controller, @selector(reloadSpecifiers));
}

static void changed(CFNotificationCenterRef center, void *observer, CFNotificationName name,
                    const void *object, CFDictionaryRef info) {
    (void)center; (void)observer; (void)name; (void)object; (void)info;
    dispatch_async(dispatch_get_main_queue(), ^{
        id controller = visible_controller;
        if (controller) reload(controller);
    });
}

static id alert_action(NSString *title, NSInteger style, void (^handler)(id)) {
    return ((id (*)(Class, SEL, NSString *, NSInteger, id))objc_msgSend)(
        NSClassFromString(@"UIAlertAction"), @selector(actionWithTitle:style:handler:), title, style, handler);
}

static void present(id controller, NSString *title, NSString *message, NSArray *actions) {
    id alert = ((id (*)(Class, SEL, NSString *, NSString *, NSInteger))objc_msgSend)(
        NSClassFromString(@"UIAlertController"), @selector(alertControllerWithTitle:message:preferredStyle:),
        title, message, AlertStyleAlert);
    for (id action in actions) ((void (*)(id, SEL, id))objc_msgSend)(alert, @selector(addAction:), action);
    ((void (*)(id, SEL, id, BOOL, id))objc_msgSend)(controller, @selector(presentViewController:animated:completion:),
                                                    alert, YES, nil);
}

static void request_forget(NSString *client) {
    NSMutableArray *requests = [preference(@"forget_clients") isKindOfClass:NSArray.class]
        ? [preference(@"forget_clients") mutableCopy] : [NSMutableArray array];
    if (![requests containsObject:client]) [requests addObject:client];
    CFPreferencesSetValue(CFSTR("forget_clients"), (__bridge CFArrayRef)requests, MirraDomain,
                          kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    CFPreferencesSynchronize(MirraDomain, kCFPreferencesCurrentUser, kCFPreferencesAnyHost);
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                         CFSTR("com.mirra.bridge.forget"), NULL, NULL, true);
}

__attribute__((constructor)) static void install(void) {
    Class parent = NSClassFromString(@"PSListController");
    if (!parent || NSClassFromString(MirraControllerName)) return;
    list_controller = objc_allocateClassPair(parent, MirraControllerName.UTF8String, 0);
    if (!list_controller) return;

    class_addMethod(list_controller, @selector(specifiers), imp_implementationWithBlock(^id(id self) {
        Ivar ivar = specifiers_ivar();
        id current = ivar ? object_getIvar(self, ivar) : nil;
        if (!current) {
            current = [build_specifiers(self) mutableCopy];
            if (ivar) object_setIvar(self, ivar, current);
        }
        return current;
    }), "@@:");

    class_addMethod(list_controller, @selector(mirraValue:), imp_implementationWithBlock(^id(id self, id row) {
        (void)self;
        return get_property(row, @"mirraValue");
    }), "@@:@");

    class_addMethod(list_controller, @selector(viewWillAppear:), imp_implementationWithBlock(^(id self, BOOL animated) {
        struct objc_super parent_call = {self, parent};
        ((void (*)(struct objc_super *, SEL, BOOL))objc_msgSendSuper)(&parent_call, @selector(viewWillAppear:), animated);
        visible_controller = self;
        reload(self);
    }), "v@:B");

    class_addMethod(list_controller, @selector(mirraCopyToken:), imp_implementationWithBlock(^(id self, id row) {
        (void)row;
        NSString *token = text_preference(@"token", nil);
        if (!token) return;
        id board = ((id (*)(Class, SEL))objc_msgSend)(NSClassFromString(@"UIPasteboard"), @selector(generalPasteboard));
        ((void (*)(id, SEL, NSString *))objc_msgSend)(board, @selector(setString:), token);
        present(self, @"Token Copied", nil, @[alert_action(@"OK", ActionStyleDefault, nil)]);
    }), "v@:@");

    class_addMethod(list_controller, @selector(mirraForget:), imp_implementationWithBlock(^(id self, id row) {
        NSString *client = get_property(row, @"mirraClient");
        NSString *name = get_property(row, @"mirraName") ?: @"this Mac";
        if (![client isKindOfClass:NSString.class]) return;
        __weak id weak = self;
        id remove = alert_action(@"Remove", ActionStyleDestructive, ^(id action) {
            (void)action;
            request_forget(client);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                id controller = weak;
                if (controller) reload(controller);
            });
        });
        NSString *message = [NSString stringWithFormat:@"The keys “%@” saved on this phone are deleted. "
                             "That Mac then sets up iPhone Mirroring again.", name];
        present(self, [NSString stringWithFormat:@"Remove %@?", name], message,
                @[alert_action(@"Cancel", ActionStyleCancel, nil), remove]);
    }), "v@:@");

    objc_registerClassPair(list_controller);
    // The service posts this after it publishes new values.
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL, changed,
                                    CFSTR("com.mirra.bridge.changed"), NULL,
                                    CFNotificationSuspensionBehaviorDeliverImmediately);
}
