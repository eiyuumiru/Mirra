#import "../mirroring/profile.h"
#import "environment.h"
#include <stdio.h>
#include <string.h>

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        BOOL environment = argc == 2 && !strcmp(argv[1], "--environment");
        if (argc != 1 && !environment) return 2;
        NSDictionary *report = environment ? MirraHostEnvironmentReport() : MirroringHostCompatibilityReport();
        NSData *json = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:NULL];
        if (!json) return 2;
        fwrite(json.bytes, 1, json.length, stdout);
        fputc('\n', stdout);
        return environment || [report[@"compatible"] boolValue] ? 0 : 1;
    }
}
