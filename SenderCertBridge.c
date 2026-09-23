// Signal 7.19.1 sender-certificate compatibility bridge for iOS 14.
// Linked against a source-patched libsignal 0.52 so the opaque SenderCertificate
// layout remains the same as the app's bundled libsignal.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct SignalFfiError SignalFfiError;
typedef struct SignalSenderCertificate SignalSenderCertificate;
typedef struct SignalPublicKey SignalPublicKey;

typedef struct {
    const unsigned char *base;
    size_t length;
} SignalBorrowedBuffer;

extern SignalFfiError *signal_sender_certificate_deserialize(
    SignalSenderCertificate **out,
    SignalBorrowedBuffer data);
extern SignalFfiError *signal_sender_certificate_destroy(SignalSenderCertificate *p);
extern SignalFfiError *signal_sender_certificate_validate(
    bool *out,
    const SignalSenderCertificate *cert,
    const SignalPublicKey *key,
    uint64_t time);

extern SignalFfiError *signal_publickey_deserialize(
    SignalPublicKey **out,
    SignalBorrowedBuffer data);
extern SignalFfiError *signal_publickey_destroy(SignalPublicKey *p);

extern void signal_free_string(const char *buf);
extern uint32_t signal_error_get_type(const SignalFfiError *err);
extern SignalFfiError *signal_error_get_message(const SignalFfiError *err, const char **out);
extern void signal_error_free(SignalFfiError *err);

// Signal 7.19.1 production Sealed Sender trust root.
static const unsigned char kLegacyProdTrustRoot[33] = {
    0x05,0x7b,0xba,0x40,0x82,0x95,0xcf,0x93,0x00,0xf2,0x0b,
    0x2d,0xcd,0xf3,0xa0,0x45,0x01,0xaa,0xc8,0xba,0x8e,0xc0,
    0xd2,0x87,0x2f,0xa2,0x0d,0x92,0xfd,0xc8,0x1d,0x63,0x05
};

// Current production Sealed Sender trust root used by server certificate id 3.
static const unsigned char kCurrentProdTrustRoot[33] = {
    0x05,0x49,0x18,0xd0,0x8f,0xbd,0xfa,0x83,0xe0,0x0c,0x29,
    0xf8,0xf8,0x07,0x3a,0x22,0xef,0x35,0xdf,0x2b,0xea,0x90,
    0x3a,0xff,0x81,0xaf,0x03,0xcc,0xbc,0x45,0xc6,0xe9,0x3a
};

SignalFfiError *sb52_sender_certificate_deserialize(
    SignalSenderCertificate **out,
    SignalBorrowedBuffer data) {
    return signal_sender_certificate_deserialize(out, data);
}

SignalFfiError *sb52_sender_certificate_destroy(SignalSenderCertificate *p) {
    return signal_sender_certificate_destroy(p);
}

static SignalFfiError *validate_with_root(
    bool *out,
    const SignalSenderCertificate *cert,
    uint64_t time,
    const unsigned char root[33]) {

    SignalPublicKey *key = NULL;
    SignalBorrowedBuffer rootBuffer = { root, 33 };
    SignalFfiError *error = signal_publickey_deserialize(&key, rootBuffer);
    if (error) return error;

    error = signal_sender_certificate_validate(out, cert, key, time);

    SignalFfiError *destroyError = signal_publickey_destroy(key);
    if (!error && destroyError) return destroyError;
    if (destroyError) signal_error_free(destroyError);

    return error;
}

SignalFfiError *sb52_sender_certificate_validate_known_roots(
    bool *out,
    const SignalSenderCertificate *cert,
    uint64_t time) {

    if (out) *out = false;

    bool valid = false;
    SignalFfiError *error = validate_with_root(
        &valid, cert, time, kCurrentProdTrustRoot);
    if (error) return error;

    if (valid) {
        if (out) *out = true;
        return NULL;
    }

    error = validate_with_root(
        &valid, cert, time, kLegacyProdTrustRoot);
    if (error) return error;

    if (out) *out = valid;
    return NULL;
}

void sb52_free_string(const char *buf) {
    signal_free_string(buf);
}

uint32_t sb52_error_get_type(const SignalFfiError *err) {
    return signal_error_get_type(err);
}

SignalFfiError *sb52_error_get_message(const SignalFfiError *err, const char **out) {
    return signal_error_get_message(err, out);
}

void sb52_error_free(SignalFfiError *err) {
    signal_error_free(err);
}
