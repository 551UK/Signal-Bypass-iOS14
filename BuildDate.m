#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <unistd.h>
#import <stdio.h>
#import <string.h>

// Installer helper: change only the build-date fields in the installed app.
// Keep an adjacent backup of BuildDetails; never touch Signal's data container.
static BOOL save(NSDictionary *value, NSString *path) {
    NSError *error = nil;
    NSData *bytes = [NSPropertyListSerialization dataWithPropertyList:value
        format:NSPropertyListBinaryFormat_v1_0 options:0 error:&error];
    struct stat previous;
    BOOL exists = stat(path.fileSystemRepresentation, &previous) == 0;
    if (!bytes || ![bytes writeToFile:path options:NSDataWritingAtomic error:&error]) {
        fprintf(stderr, "SignalBypass14: unable to save plist: %s\n", error.description.UTF8String);
        return NO;
    }
    if (exists && (chown(path.fileSystemRepresentation, previous.st_uid, previous.st_gid) != 0 ||
                   chmod(path.fileSystemRepresentation, previous.st_mode & 07777) != 0)) {
        perror("SignalBypass14: restore plist permissions");
        return NO;
    }
    return YES;
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 2 || (strcmp(argv[1], "apply") && strcmp(argv[1], "restore"))) return 2;
        BOOL restore = !strcmp(argv[1], "restore");
        NSFileManager *fm = NSFileManager.defaultManager;
        NSString *root = @"/var/containers/Bundle/Application";
        NSUInteger found = 0;
        for (NSString *container in [fm contentsOfDirectoryAtPath:root error:nil]) {
            NSString *directory = [root stringByAppendingPathComponent:container];
            for (NSString *entry in [fm contentsOfDirectoryAtPath:directory error:nil]) {
                if (![entry.pathExtension isEqualToString:@"app"]) continue;
                NSString *app = [directory stringByAppendingPathComponent:entry];
                NSString *path = [app stringByAppendingPathComponent:@"Info.plist"];
                NSMutableDictionary *info = [[NSDictionary dictionaryWithContentsOfFile:path] mutableCopy];
                if (![info[@"CFBundleIdentifier"] isEqual:@"org.whispersystems.signal"] ||
                    ![info[@"CFBundleShortVersionString"] isEqual:@"7.19.1"] ||
                    ![info[@"CFBundleVersion"] isEqual:@"208"]) continue;
                NSString *backup = [app stringByAppendingPathComponent:@"SignalBypass14-OriginalBuildDetails.plist"];
                NSMutableDictionary *details = [info[@"BuildDetails"] mutableCopy];
                if (![details isKindOfClass:NSDictionary.class]) continue;
                found++;
                if (restore) {
                    NSDictionary *original = [NSDictionary dictionaryWithContentsOfFile:backup];
                    if (!original) continue;
                    // Do not overwrite a subsequent manual build-date change.
                    if ([details[@"Timestamp"] doubleValue] != 4070908800.0 ||
                        ![details[@"DateTime"] isEqual:@"Thu Jan 01 00:00:00 UTC 2099"]) continue;
                    for (NSString *key in @[@"Timestamp", @"DateTime"]) {
                        if (original[key]) details[key] = original[key];
                        else [details removeObjectForKey:key];
                    }
                    info[@"BuildDetails"] = details;
                    if (!save(info, path)) return 1;
                    if (![fm removeItemAtPath:backup error:nil]) return 1;
                    puts("SignalBypass14: original build dates restored.");
                } else {
                    // Preserve the first backup through reinstalls/upgrades.
                    if (![fm fileExistsAtPath:backup] && !save(details, backup)) return 1;
                    if (![NSDictionary dictionaryWithContentsOfFile:backup]) return 1;
                    details[@"Timestamp"] = @4070908800.0;
                    details[@"DateTime"] = @"Thu Jan 01 00:00:00 UTC 2099";
                    info[@"BuildDetails"] = details;
                    if (!save(info, path)) return 1;
                    NSDictionary *check = [NSDictionary dictionaryWithContentsOfFile:path][@"BuildDetails"];
                    if ([check[@"Timestamp"] doubleValue] != 4070908800.0 ||
                        ![check[@"DateTime"] isEqual:details[@"DateTime"]]) return 1;
                    puts("SignalBypass14: Info.plist build dates set to 1 January 2099.");
                }
            }
        }
        if (!found && !restore) {
            fputs("SignalBypass14: Signal 7.19.1 (208) not found. Install it, then reinstall this tweak.\n", stderr);
            return 1;
        }
        return 0;
    }
}
