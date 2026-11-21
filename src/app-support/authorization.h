#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
// Credentials stay between the native UI and OpenSSH; Python receives no password.
@interface Authorization : NSObject
@property(readonly) NSDictionary<NSString *, NSString *> *environment;
- (nullable instancetype)initWithPrompt:(void (^)(NSString *, void (^)(NSString * _Nullable)))prompt;
- (void)invalidate;
@end
NS_ASSUME_NONNULL_END
