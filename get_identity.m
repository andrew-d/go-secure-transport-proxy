#import <Foundation/Foundation.h>
#import <Security/Security.h>

#include <stdint.h>
#include <string.h>


#define DEBUG


#ifdef DEBUG
#   define DLog(fmt, ...) NSLog((@"%s [Line %d] " fmt), __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#   define DLog(...)
#endif


int GetIdentityPrivateKey(const char *identityName,  uint8_t **out, int *len) {
    int ret = 0;
    OSStatus status;
    CFStringRef identityStr = NULL;
    NSMutableDictionary *query = NULL;
    SecKeychainItemRef identityRef = NULL;
    SecKeyRef keyRef = NULL;
    CFStringRef dummyPassphrase = CFSTR("dummy");
    CFDataRef keyDataRef = NULL;

    // Default to empty.
    *out = NULL;
    *len = 0;

    identityStr = CFStringCreateWithCString(kCFAllocatorDefault, identityName, kCFStringEncodingUTF8);
    if (identityStr == NULL) {
        DLog(@"Could not create identity string");
	ret = 1;
	goto cleanup;
    }

    query = [NSMutableDictionary dictionary];
    [query setObject:(id)kSecClassIdentity forKey:(id)kSecClass];
    [query setObject:(id)kCFBooleanTrue    forKey:(id)kSecReturnRef];
    [query setObject:(id)kSecMatchLimitOne forKey:(id)kSecMatchLimit];
    [query setObject:(id)identityStr       forKey:(id)kSecAttrLabel];

    DLog(@"The query is: %@", query);

    // Run the query
    identityRef = NULL;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&identityRef);
    if (status != errSecSuccess) {
        CFStringRef errorRef = SecCopyErrorMessageString(status, NULL);
	DLog(@"Error copying matching items: %@", (__bridge NSString *)errorRef);
	ret = 1;
	goto cleanup;
    }

    DLog(@"Identity ref is: %@", identityRef);

    // Extract private key.
    status = SecIdentityCopyPrivateKey(identityRef, &keyRef);
    if (status != errSecSuccess) {
        CFStringRef errorRef = SecCopyErrorMessageString(status, NULL);
	DLog(@"Error copying private key: %@", (__bridge NSString *)errorRef);
	ret = 1;
	goto cleanup;
    }

    DLog(@"Key ref is: %@", keyRef);

    // Export as PEM
    SecItemImportExportKeyParameters params;

    params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    params.flags = 0;
    params.passphrase = dummyPassphrase;
    params.alertTitle = NULL;
    params.alertPrompt = NULL;
    params.accessRef = NULL;
    params.keyUsage = NULL;
    params.keyAttributes = NULL;

    status = SecItemExport(
	keyRef,
	kSecFormatWrappedPKCS8,
	kSecItemPemArmour,
	&params,
	&keyDataRef
    );
    if (status != errSecSuccess) {
        CFStringRef errorRef = SecCopyErrorMessageString(status, NULL);
	DLog(@"Error exporting private key: %@", (__bridge NSString *)errorRef);
	ret = 1;
	goto cleanup;
    }

    // All good!  Allocate and copy a buffer.
    int returnLen = CFDataGetLength(keyDataRef);
    uint8_t* returnBuff = calloc(returnLen, 1);

    CFDataGetBytes(keyDataRef, CFRangeMake(0, returnLen), returnBuff);

    *out = returnBuff;
    *len = returnLen;

cleanup:
    if (keyDataRef != NULL)  CFRelease(keyDataRef);
    if (keyRef != NULL)      CFRelease(keyRef);
    if (identityRef != NULL) CFRelease(identityRef);
    if (query != NULL)       CFRelease(query);
    if (identityStr != NULL) CFRelease(identityStr);

    return ret;
}
