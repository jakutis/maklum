#ifndef MAIN

#define MAIN

#ifndef SIZE_MAX
#define SIZE_MAX ((size_t) - 1)
#endif

typedef struct {
    FILE *in;
    FILE *out;
    size_t password_length;
    size_t pbkdf2_iterations;
    size_t pipe_buffer_size;
    size_t message_id_length;
    size_t user_id_length;
    size_t key_salt_length;
} main_params;

size_t main_digits(size_t n);

int main_string_to_integer(char *string, size_t *integer);

int main_encrypt_pipe(main_params *params, EVP_CIPHER_CTX *ctx, FILE *in,
        FILE *out, size_t *out_length);

int main_decrypt_pipe(main_params *params, EVP_CIPHER_CTX *ctx, FILE *in,
        FILE *out, size_t out_length);

int main_decrypt(main_params *params, const char *ciphertext_filename,
        const char *plaintext_filename);

int main_encrypt(main_params *params, const char *plaintext_filename,
        const char* encrypted_filename);

void main_read_text(main_params *params, char *text, size_t text_length);

int main_set_iv(unsigned char *iv, unsigned char *key, char *user_id,
        char *message_id);

int main_aes(const unsigned char *in, unsigned char *out,
        const unsigned char *key);

int main_read_integer(main_params *params, size_t *integer);

int main_read_yesno(main_params *params, const char *positive_response);

int main_error(main_params *params, int type, const char *message);

#endif
