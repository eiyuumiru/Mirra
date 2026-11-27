#import <AppKit/AppKit.h>
#import "channel.h"

static BOOL write_all_fd(int fd, const void *bytes, size_t count) {
    const uint8_t *cursor = bytes;
    while (count) {
        ssize_t written = write(fd, cursor, count);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return NO;
        cursor += written;
        count -= (size_t)written;
    }
    return YES;
}

static NSString *safe_prompt(int argc, const char *argv[]) {
    NSString *prompt = argc > 1 ? [NSString stringWithUTF8String:argv[1]] : nil;
    if (!prompt.length) prompt = @"SSH password";
    if (prompt.length > 300) {
        NSRange range = [prompt rangeOfComposedCharacterSequenceAtIndex:300];
        prompt = [prompt substringToIndex:range.location];
    }
    return prompt;
}

int main(int argc, const char *argv[]) {
    // AppKit/driver diagnostics must never become part of the SSH response.
    int response = dup(STDOUT_FILENO);
    dup2(STDERR_FILENO, STDOUT_FILENO);
    @autoreleasepool {
        NSDictionary *environment = NSProcessInfo.processInfo.environment;
        NSString *path = environment[@"MIRRA_ASKPASS_SOCKET"];
        if (path) {
            int peer = socket(AF_UNIX, SOCK_STREAM, 0);
            if (peer < 0) { close(response); return 1; }
            MirraSocketOptions(peer, 115);
            struct sockaddr_un address = {0}; address.sun_family = AF_UNIX;
            const char *fs_path = path.fileSystemRepresentation;
            if (!fs_path || strlen(fs_path) >= sizeof(address.sun_path)) { close(peer); close(response); return 1; }
            strlcpy(address.sun_path, fs_path, sizeof(address.sun_path));
            uid_t uid; gid_t gid;
            if (connect(peer, (struct sockaddr *)&address, sizeof(address)) || getpeereid(peer, &uid, &gid) || uid != getuid()) { close(peer); close(response); return 1; }
            NSString *prompt = safe_prompt(argc, argv);
            NSDictionary *reply = MirraSend(peer, @{@"token": environment[@"MIRRA_ASKPASS_TOKEN"] ?: @"", @"prompt": prompt}) ? MirraReceive(peer) : nil;
            close(peer);
            if (![reply[@"password"] isKindOfClass:NSString.class]) { close(response); return 1; }
            NSMutableData *data = [[reply[@"password"] dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
            BOOL ok = (!data.length || write_all_fd(response, data.bytes, data.length)) && write_all_fd(response, "\n", 1);
            [data resetBytesInRange:NSMakeRange(0, data.length)]; close(response); return ok ? 0 : 1;
        }
        NSApplication *app = NSApplication.sharedApplication;
        [app setActivationPolicy:NSApplicationActivationPolicyAccessory];
        [app activateIgnoringOtherApps:YES];
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = @"Authorize SSH access to your phone";
        NSString *prompt = safe_prompt(argc, argv);
        alert.informativeText = [NSString stringWithFormat:@"%@\n\nThe password goes directly to SSH and is not saved by Mirra.", prompt];
        NSSecureTextField *field = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 360, 26)];
        field.placeholderString = @"Phone SSH password";
        alert.accessoryView = field;
        [alert addButtonWithTitle:@"Connect"]; [alert addButtonWithTitle:@"Cancel"];
        [alert.window setInitialFirstResponder:field];
        NSModalResponse selected = [alert runModal];
        if (selected != NSAlertFirstButtonReturn) { close(response); return 1; }
        NSMutableData *password = [[field.stringValue dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
        BOOL ok = (!password.length || write_all_fd(response, password.bytes, password.length)) && write_all_fd(response, "\n", 1);
        [password resetBytesInRange:NSMakeRange(0, password.length)];
        field.stringValue = @""; close(response); return ok ? 0 : 1;
    }
    return 0;
}
