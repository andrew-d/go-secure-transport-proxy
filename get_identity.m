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


/**
 * Helper function to export an item with some params, and copy into a buffer.
 */
int exportItemIntoBuffer(
    SecKeychainItemRef item,
    SecExternalFormat format,
    SecItemImportExportKeyParameters *params,
    uint8_t **out,
    int *len
) {
    int ret = 0;
    OSStatus status;
    CFDataRef itemDataRef = NULL;

    status = SecItemExport(
        item,
        format,
        kSecItemPemArmour,
        params,
        &itemDataRef
    );
    if (status != errSecSuccess) {
        CFStringRef errorRef = SecCopyErrorMessageString(status, NULL);
        DLog(@"Error exporting item: %@", (__bridge NSString *)errorRef);
        ret = 1;
        goto cleanup;
    }

    // All good!  Allocate and copy a buffer.
    int returnLen = CFDataGetLength(itemDataRef);
    uint8_t* returnBuff = calloc(returnLen, 1);

    CFDataGetBytes(itemDataRef, CFRangeMake(0, returnLen), returnBuff);

    *out = returnBuff;
    *len = returnLen;

cleanup:
    if (itemDataRef != NULL) CFRelease(itemDataRef);

    return ret;
}
/**
 * Export the private key from an identity using the given password.
 */
int exportIdentityPrivateKey(SecIdentityRef identity, const char* password, uint8_t **out, int *len) {
    int ret = 0;
    OSStatus status;
    SecKeyRef keyRef = NULL;
    CFDataRef passphraseRef = NULL;

    // Extract private key.
    status = SecIdentityCopyPrivateKey(identity, &keyRef);
    if (status != errSecSuccess) {
        CFStringRef errorRef = SecCopyErrorMessageString(status, NULL);
        DLog(@"Error copying private key: %@", (__bridge NSString *)errorRef);
        ret = 1;
        goto cleanup;
    }

    DLog(@"Key ref is: %@", keyRef);

    // Need a CFDataRef for our passphrase.
    passphraseRef = CFDataCreate(
        NULL,
        (unsigned char*)password,
        strlen(password)
    );

    // Export as PEM with our passphrase
    SecItemImportExportKeyParameters params;

    params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    params.flags = 0;
    params.passphrase = passphraseRef;
    params.alertTitle = NULL;
    params.alertPrompt = NULL;
    params.accessRef = NULL;
    params.keyUsage = NULL;
    params.keyAttributes = NULL;

    // Note: from the Apple documentation:
    //   You can export only the following types of keychain items:
    //   SecCertificateRef, SecKeyRef, and SecIdentityRef. If you are exporting
    //   exactly one item, you can specify a SecKeychainItemRef object
    ret = exportItemIntoBuffer((SecKeychainItemRef)keyRef, kSecFormatWrappedPKCS8, &params, out, len);

cleanup:
    if (passphraseRef != NULL) CFRelease(passphraseRef);
    if (keyRef != NULL)        CFRelease(keyRef);

    return ret;
}

/**
 * Export the certificate from an identity.
 */
int exportIdentityCertificate(SecIdentityRef identity, uint8_t **out, int *len) {
    int ret = 0;
    OSStatus status;
    SecCertificateRef certRef = NULL;

    // Extract
    status = SecIdentityCopyCertificate(identity, &certRef);
    if (status != errSecSuccess) {
        CFStringRef errorRef = SecCopyErrorMessageString(status, NULL);
        DLog(@"Error copying certificate: %@", (__bridge NSString *)errorRef);
        ret = 1;
        goto cleanup;
    }

    // Export as PEM
    SecItemImportExportKeyParameters params;

    params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    params.flags = 0;
    params.passphrase = NULL;
    params.alertTitle = NULL;
    params.alertPrompt = NULL;
    params.accessRef = NULL;
    params.keyUsage = NULL;
    params.keyAttributes = NULL;

    // Note: from the Apple documentation:
    //   You can export only the following types of keychain items:
    //   SecCertificateRef, SecKeyRef, and SecIdentityRef. If you are exporting
    //   exactly one item, you can specify a SecKeychainItemRef object
    ret = exportItemIntoBuffer((SecKeychainItemRef)certRef, kSecFormatPEMSequence, &params, out, len);

cleanup:
    if (certRef != NULL) CFRelease(certRef);

    return ret;
}


int ExportIdentity(
    const char *identityName, const char* password,
    uint8_t **certificateOut, int *certificateLen,
    uint8_t **privateKeyOut, int *privateKeyLen
) {
    int ret = 0;
    OSStatus status;
    CFStringRef identityStr = NULL;
    NSMutableDictionary *query = NULL;
    SecKeychainItemRef identityRef = NULL;

    // Clear output variables by default.
    *certificateOut = NULL;
    *certificateLen = 0;
    *privateKeyOut = NULL;
    *privateKeyLen = 0;

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

    ret = exportIdentityPrivateKey((SecIdentityRef)identityRef, password, privateKeyOut, privateKeyLen);
    if (ret != 0) {
        goto cleanup;
    }

    ret = exportIdentityCertificate((SecIdentityRef)identityRef, certificateOut, certificateLen);
    if (ret != 0) {
        goto cleanup;
    }

cleanup:
    if (identityRef != NULL)   CFRelease(identityRef);
    if (query != NULL)         CFRelease(query);
    if (identityStr != NULL)   CFRelease(identityStr);

    return ret;
}
