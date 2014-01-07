#ifndef MAIN

#define MAIN

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/aes.h"
#include "openssl/rand.h"
#include "openssl/dh.h"
#include "openssl/pem.h"

typedef struct {
    size_t max;
    size_t len;
    const char **all;
    const char* current;
    size_t current_i;
} main_enum;

void main_enum_init(main_enum *a, const char **all);

typedef struct {
    size_t filename_length;
    FILE *in;
    FILE *out;
    size_t size_max;
    size_t debug;
    size_t password_length;
    size_t pbkdf2_iterations;
    size_t pipe_buffer_size;
    size_t message_id_length;
    size_t user_id_length;
    size_t key_salt_length;
    size_t iv_length;
    size_t tag_length;
    const char *size_t_format;
    size_t dh_generator_length;
    const unsigned char* dh_generator;
    size_t dh_prime_length;
    const unsigned char* dh_prime;
    const char **key_types;
    size_t key_type_dh;
    size_t key_type_rsa;
    size_t key_type_password;
} main_params;

int main_derive_key_dh(const char *private_key_filename,
        const char *public_key_filename, unsigned char *key, size_t key_length);

int main_generate_keys(main_params *params);

int main_write_dh_key(main_params *params, const char *filename,
        EVP_PKEY *dh_params, int private);

int main_read_filename(main_params *params, const char *message,
        char *filename);

size_t main_max(size_t a, size_t b);

int main_read_key_type(main_params *params, main_enum *key_type);

int main_read_enum(main_params *params, main_enum *a);

int main_fill_dh_params(main_params *params, EVP_PKEY **dh_params);

int main_generate_dh_key(main_params *params, EVP_PKEY *dh_params,
        EVP_PKEY **key);

void main_digits(size_t n, size_t *d);

int main_write_size_t(main_params *params, size_t size);

int main_string_to_integer(main_params *params, char *string, size_t *integer);

int main_encrypt_pipe(main_params *params, EVP_CIPHER_CTX *ctx, FILE *in,
        FILE *out);

int main_decrypt_pipe(main_params *params, EVP_CIPHER_CTX *ctx, FILE *in,
        FILE *out);

int main_decrypt(main_params *params, const char *ciphertext_filename,
        const char *plaintext_filename);

int main_encrypt(main_params *params, const char *plaintext_filename,
        const char* encrypted_filename);

int main_read_text(main_params *params, char *text, size_t text_length);

int main_aes(const unsigned char *in, unsigned char *out,
        const unsigned char *key);

int main_read_integer(main_params *params, size_t *integer);

int main_read_yesno(main_params *params, const char *positive_response,
        int *yesno);

int main_error(main_params *params, int type, const char *message);

int main_write_bytes_hex(main_params *params, unsigned char *bytes,
        size_t length);

#endif

