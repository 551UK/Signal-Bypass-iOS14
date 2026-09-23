// Signal CDSI post-quantum bridge for iOS 14.
// Links libsignal 0.71.0's official iOS static FFI build behind private sb71_* exports.
// The main tweak adapts Signal 7.19.1's older opaque-pointer ABI to these wrappers.

#include <stddef.h>
#include <stdint.h>

typedef struct SignalFfiError SignalFfiError;
typedef struct SignalSgxClientState SignalSgxClientState;

typedef struct {
    const unsigned char *base;
    size_t length;
} SignalBorrowedBuffer;

typedef struct {
    unsigned char *base;
    size_t length;
} SignalOwnedBuffer;

typedef struct {
    SignalSgxClientState *raw;
} SignalMutPointerSgxClientState;

typedef struct {
    const SignalSgxClientState *raw;
} SignalConstPointerSgxClientState;

extern SignalFfiError *signal_cds2_client_state_new(
    SignalMutPointerSgxClientState *out,
    SignalBorrowedBuffer mrenclave,
    SignalBorrowedBuffer attestation_msg,
    uint64_t current_timestamp);

extern SignalFfiError *signal_sgx_client_state_destroy(SignalMutPointerSgxClientState p);
extern SignalFfiError *signal_sgx_client_state_initial_request(
    SignalOwnedBuffer *out,
    SignalConstPointerSgxClientState obj);
extern SignalFfiError *signal_sgx_client_state_complete_handshake(
    SignalMutPointerSgxClientState cli,
    SignalBorrowedBuffer handshake_received);
extern SignalFfiError *signal_sgx_client_state_established_send(
    SignalOwnedBuffer *out,
    SignalMutPointerSgxClientState cli,
    SignalBorrowedBuffer plaintext_to_send);
extern SignalFfiError *signal_sgx_client_state_established_recv(
    SignalOwnedBuffer *out,
    SignalMutPointerSgxClientState cli,
    SignalBorrowedBuffer received_ciphertext);

extern void signal_free_buffer(const unsigned char *buf, size_t buf_len);
extern void signal_free_string(const char *buf);
extern uint32_t signal_error_get_type(const SignalFfiError *err);
extern SignalFfiError *signal_error_get_message(const SignalFfiError *err, const char **out);
extern void signal_error_free(SignalFfiError *err);

SignalFfiError *sb71_cds2_client_state_new(
    SignalSgxClientState **out,
    SignalBorrowedBuffer mrenclave,
    SignalBorrowedBuffer attestation_msg,
    uint64_t current_timestamp) {
    SignalMutPointerSgxClientState wrapped = {0};
    SignalFfiError *error = signal_cds2_client_state_new(
        &wrapped, mrenclave, attestation_msg, current_timestamp);
    if (out) *out = wrapped.raw;
    return error;
}

SignalFfiError *sb71_sgx_client_state_destroy(SignalSgxClientState *p) {
    SignalMutPointerSgxClientState wrapped = {p};
    return signal_sgx_client_state_destroy(wrapped);
}

SignalFfiError *sb71_sgx_client_state_initial_request(
    SignalOwnedBuffer *out,
    const SignalSgxClientState *obj) {
    SignalConstPointerSgxClientState wrapped = {obj};
    return signal_sgx_client_state_initial_request(out, wrapped);
}

SignalFfiError *sb71_sgx_client_state_complete_handshake(
    SignalSgxClientState *cli,
    SignalBorrowedBuffer handshake_received) {
    SignalMutPointerSgxClientState wrapped = {cli};
    return signal_sgx_client_state_complete_handshake(wrapped, handshake_received);
}

SignalFfiError *sb71_sgx_client_state_established_send(
    SignalOwnedBuffer *out,
    SignalSgxClientState *cli,
    SignalBorrowedBuffer plaintext_to_send) {
    SignalMutPointerSgxClientState wrapped = {cli};
    return signal_sgx_client_state_established_send(out, wrapped, plaintext_to_send);
}

SignalFfiError *sb71_sgx_client_state_established_recv(
    SignalOwnedBuffer *out,
    SignalSgxClientState *cli,
    SignalBorrowedBuffer received_ciphertext) {
    SignalMutPointerSgxClientState wrapped = {cli};
    return signal_sgx_client_state_established_recv(out, wrapped, received_ciphertext);
}

void sb71_free_buffer(const unsigned char *buf, size_t buf_len) {
    signal_free_buffer(buf, buf_len);
}

void sb71_free_string(const char *buf) {
    signal_free_string(buf);
}

uint32_t sb71_error_get_type(const SignalFfiError *err) {
    return signal_error_get_type(err);
}

SignalFfiError *sb71_error_get_message(const SignalFfiError *err, const char **out) {
    return signal_error_get_message(err, out);
}

void sb71_error_free(SignalFfiError *err) {
    signal_error_free(err);
}
