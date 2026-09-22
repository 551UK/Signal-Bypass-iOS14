#import <Foundation/Foundation.h>
#import <sys/stat.h>
#import <unistd.h>
#import <stdio.h>
#import <string.h>

// v1.3.0 uses a new local AppVersion identity so an AppExpiry record cached
// under the previous 8.29.0.1867 identity cannot be restored on first launch.
// Runtime code no longer intercepts networking; this helper only persists the
// local bundle identity before Signal starts.

static NSString *const spoofShortVersion = @"8.29";
static NSString *const spoofBuildVersion = @"1868";
static NSString *const originalShortVersion = @"7.19.1";
static NSString *const originalBuildVersion = @"208";

static BOOL isKnownSpoofBuild(NSString *build) {
    return [@[@"1866", @"1867", @"1868"] containsObject:build ?: @""];
}

static NSDictionary *spoofBuildDetails(void) {
    return @{
        @"XCodeVersion": @"2600.2660",
        @"Timestamp": @1790096400,
        @"DateTime": @"Tue Sep 22 17:00:00 UTC 2026",
        @"SignalCommit": @"3188f61b17c4b4caa837ab52a0babab5b9fd6423 Feature flags for .production."
    };
}

static BOOL savePlist(NSDictionary *value, NSString *path) {
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

static NSDictionary *makeBackup(NSDictionary *info) {
    return @{
        @"SB14BackupVersion": @2,
        @"CFBundleShortVersionString": info[@"CFBundleShortVersionString"] ?: originalShortVersion,
        @"CFBundleVersion": info[@"CFBundleVersion"] ?: originalBuildVersion,
        @"BuildDetails": info[@"BuildDetails"] ?: @{}
    };
}

static NSDictionary *loadBackup(NSString *path) {
    NSDictionary *stored = [NSDictionary dictionaryWithContentsOfFile:path];
    if (!stored) return nil;

    if (!stored[@"SB14BackupVersion"]) {
        return @{
            @"SB14BackupVersion": @2,
            @"CFBundleShortVersionString": originalShortVersion,
            @"CFBundleVersion": originalBuildVersion,
            @"BuildDetails": stored
        };
    }
    return stored;
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

                if (![info[@"CFBundleIdentifier"] isEqual:@"org.whispersystems.signal"]) continue;

                NSString *currentVersion = info[@"CFBundleShortVersionString"];
                NSString *currentBuild = info[@"CFBundleVersion"];
                BOOL original = [currentVersion isEqual:originalShortVersion] &&
                                [currentBuild isEqual:originalBuildVersion];
                BOOL spoofed = [currentVersion isEqual:spoofShortVersion] &&
                               isKnownSpoofBuild(currentBuild);

                if (!original && !spoofed) continue;
                found++;

                NSString *backupPath = [app stringByAppendingPathComponent:@"SignalBypass14-OriginalMetadata.plist"];
                NSString *legacyBackupPath = [app stringByAppendingPathComponent:@"SignalBypass14-OriginalBuildDetails.plist"];

                if (restore) {
                    NSDictionary *backup = loadBackup(backupPath);
                    if (!backup) backup = loadBackup(legacyBackupPath);
                    if (!backup) continue;

                    if (spoofed) {
                        info[@"CFBundleShortVersionString"] = backup[@"CFBundleShortVersionString"] ?: originalShortVersion;
                        info[@"CFBundleVersion"] = backup[@"CFBundleVersion"] ?: originalBuildVersion;
                        info[@"BuildDetails"] = backup[@"BuildDetails"] ?: @{};
                        if (!savePlist(info, path)) return 1;
                        puts("SignalBypass14: original Signal metadata restored.");
                    }

                    (void)[fm removeItemAtPath:backupPath error:nil];
                    (void)[fm removeItemAtPath:legacyBackupPath error:nil];
                } else {
                    NSDictionary *backup = loadBackup(backupPath);
                    if (!backup) {
                        backup = loadBackup(legacyBackupPath);
                        if (!backup) backup = makeBackup(info);
                        if (!savePlist(backup, backupPath)) return 1;
                    }

                    info[@"CFBundleShortVersionString"] = spoofShortVersion;
                    info[@"CFBundleVersion"] = spoofBuildVersion;
                    info[@"BuildDetails"] = spoofBuildDetails();
                    if (!savePlist(info, path)) return 1;

                    NSDictionary *check = [NSDictionary dictionaryWithContentsOfFile:path];
                    if (![check[@"CFBundleShortVersionString"] isEqual:spoofShortVersion] ||
                        ![check[@"CFBundleVersion"] isEqual:spoofBuildVersion] ||
                        [check[@"BuildDetails"][@"Timestamp"] doubleValue] != 1790096400.0) {
                        fputs("SignalBypass14: metadata verification failed.\n", stderr);
                        return 1;
                    }

                    puts("SignalBypass14: persisted fresh local Signal identity 8.29.0.1868.");
                }
            }
        }

        if (!found && !restore) {
            fputs("SignalBypass14: compatible Signal app not found. Expected 7.19.1 (208) or an existing 8.29 spoofed metadata state.\n", stderr);
            return 1;
        }
        return 0;
    }
}
