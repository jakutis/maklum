#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/rand.h"

#include "main.h"

int main(int argc, const char **argv) {
    main_params params;
    params.in = stdin;
    params.out = stdout;
    params.password_length = 50;
    params.pbkdf2_iterations = 100;
    params.pipe_buffer_size = 100000;

    if(argc < 2) {
        return main_error(&params, 0, "nepateiktas operacijos pavadinimas");
    }
    if(strcmp(argv[1], "uzsifruoti") == 0) {
        if(argc == 2) {
            return main_error(&params, 0, "nepateiktas šifruojamo failo vardas");
        }
        if(argc == 3) {
            return main_error(&params, 0, "nepateiktas užšifruoto failo vardas");
        }
        return main_encrypt(&params, argv[2], argv[3]);
    } else if(strcmp(argv[1], "issifruoti") == 0) {
        return main_error(&params, 1, "operacija dar neįgyvendinta");
    } else {
        return main_error(&params, 0, "neatpažintas operacijos pavadinimas (turi būti vienas iš: \"uzsifruoti\", \"issifruoti\")");
    }
}

void main_read_text(main_params *params, char *text, size_t text_length) {
    size_t i;
    int c;

    for(i = 0; i < text_length; i += 1) {
        c = fgetc(params->in);
        if(!isgraph(c)) {
            break;
        }
        text[i] = (char)c;
    }
    text[i + 1] = 0;
    fprintf(params->out, "\n");
}

int main_read_yesno(main_params *params, const char *positive_response) {
    int result;
    size_t n;
    char *response;

    n = strlen(positive_response);
    response = malloc((n + 1) * sizeof(char));

    main_read_text(params, response, n);
    result = strcmp(response, positive_response) == 0;

    free(response);

    return result;
}

int main_error(main_params *params, int type, const char *message) {
    fprintf(params->out, "%s klaida: %s.\n", type == 0 ? "Vartotojo" : "Sisteminė", message);
    return EXIT_FAILURE;
}

int main_string_to_integer(char *string, size_t *integer) {
    if(sscanf(string, "%zu", integer) == 1) {
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}

int main_read_integer(main_params *params, size_t *integer) {
    int result;
    char *string;
    size_t n;

    n = main_digits(SIZE_MAX);
    string = malloc((n + 1) * sizeof(char));
    main_read_text(params, string, n);
    result = main_string_to_integer(string, integer);

    free(string);
    return result;
}

int main_aes(const unsigned char *in, unsigned char *out, const unsigned char *key) {
    AES_KEY aes_key;

    if(AES_set_encrypt_key(key, 256, &aes_key) != 0) {
        return EXIT_FAILURE;
    }
    AES_encrypt(in, out, &aes_key);

    return EXIT_SUCCESS;
}

int main_set_iv(unsigned char *iv, unsigned char *key, char *user_id, char *message_id) {
    int result = EXIT_SUCCESS;
    unsigned char *nonce;

    nonce = malloc(16 * sizeof(char));
    memcpy(user_id, nonce, 8);
    memcpy(message_id, nonce, 8);

    if(main_aes(nonce, iv, key) != EXIT_SUCCESS) {
        result = EXIT_FAILURE;
    }

    free(nonce);
    return result;
}

size_t main_digits(size_t n) {
    size_t d;

    for(d = 1; n > 9; d += 1) {
        n /= 10;
    }

    return d;
}

int main_encrypt_pipe(main_params *params, EVP_CIPHER_CTX *ctx, FILE *in, FILE *out) {
    int result = EXIT_SUCCESS;
    size_t plaintext_available;
    int ciphertext_available = 0;
    unsigned char *plaintext = malloc(params->pipe_buffer_size * sizeof(char));
    unsigned char *ciphertext = malloc(params->pipe_buffer_size * sizeof(char));

    while(!feof(in)) {
        plaintext_available = fread(plaintext, sizeof(char), params->pipe_buffer_size, in);
        fprintf(params->out, "Nuskaityta tekstogramos baitų: %zu\n", plaintext_available);
        if(ferror(in) ||
                EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_available, plaintext, (int)plaintext_available) != 1 ||
                fwrite(ciphertext, sizeof(char), (size_t)ciphertext_available, out) < (size_t)ciphertext_available) {
            result = EXIT_FAILURE;
            break;
        }
        fprintf(params->out, "Įrašyta šifrogramos baitų: %d\n", ciphertext_available);
    }
    if(result == EXIT_SUCCESS && EVP_EncryptFinal_ex(ctx, ciphertext, &ciphertext_available) != 1) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS && fwrite(ciphertext, sizeof(char), (size_t)ciphertext_available, out) < (size_t)ciphertext_available) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS) {
        fprintf(params->out, "Įrašytą paskutinių šifrogramos baitų: %d\n", ciphertext_available);
    }

    free(plaintext);
    free(ciphertext);

    return result;
}

int main_encrypt(main_params *params, const char *plaintext_filename,
        const char *ciphertext_filename) {
    int result = EXIT_SUCCESS;

    size_t message_id_length = 8;
    char *message_id = malloc((message_id_length + 1) * sizeof(char));
    size_t user_id_length = 8;
    char *user_id = malloc((user_id_length + 1) * sizeof(char));

    unsigned char *iv = malloc(16 * sizeof(char));
    size_t key_salt_length = 32;
    unsigned char *key_salt = malloc(key_salt_length * sizeof(char));
    size_t key_length = 32;
    unsigned char *key = malloc(key_length * sizeof(char));
    char *password = malloc((params->password_length + 1) * sizeof(char));
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    FILE *plaintext_file = NULL;
    FILE *ciphertext_file = NULL;

    if(result == EXIT_SUCCESS) {
        plaintext_file = fopen(plaintext_filename, "rb");
    }
    if(plaintext_file == NULL) {
        result = main_error(params, 0, "nepavyko atidaryti šifruojamo failo");
    }
    if(result == EXIT_SUCCESS) {
        ciphertext_file = fopen(ciphertext_filename, "wb");
    }
    if(ciphertext_file == NULL) {
        result = main_error(params, 0, "nepavyko atidaryti failo užšfiravimui");
    }
    if(result == EXIT_SUCCESS) {
        fprintf(params->out, "Suveskite vartotojo identifikatorių (maksimalus ilgis yra %zu): ", user_id_length);
        main_read_text(params, user_id, user_id_length);
        fprintf(params->out, "Suveskite šio vartotojo vardu atliekamos užšifravimo operacijos vienkartinį identifikatorių (maksimalus ilgis yra %zu): ", message_id_length);
        main_read_text(params, message_id, message_id_length);
    }
    if(result == EXIT_SUCCESS) {
        fprintf(params->out, "Suveskite užšifravimo slaptažodį (maksimalus ilgis yra %zu): ", params->password_length);
        main_read_text(params, password, params->password_length);
        fprintf(params->out, "Ačiū! Sistema pasiruošusi šifravimo operacijai su tokiais parametrais:\n");
        fprintf(params->out, "Šifruojamas failas: %s\n", plaintext_filename);
        fprintf(params->out, "Užšifruotas failas: %s\n", ciphertext_filename);
        fprintf(params->out, "Vartotojo identifikatorius: %s\n", user_id);
        fprintf(params->out, "Operacijos identifikatorius: %s\n", message_id);
        fprintf(params->out, "Slaptažodis: %s\n", password);
        fprintf(params->out, "Ar pradėti operaciją (taip/ne)? ");
        if(main_read_yesno(params, "taip")) {
            fprintf(params->out, "Operacija vykdoma, prašome palaukti\n");

            if(RAND_bytes(key_salt, (int)key_salt_length) != 1) {
                result = main_error(params, 1, "RAND_bytes");
            }
            if(result == EXIT_SUCCESS && PKCS5_PBKDF2_HMAC_SHA1(password, (int)strlen(password), key_salt, (int)key_salt_length, (int)params->pbkdf2_iterations, (int)key_length, key) != 1) {
                result = main_error(params, 1, "PKCS5_PBKDF2_HMAC_SHA1");
            }
            /*
             * 2010 - Niels Ferguson, Bruce Schneier, Tadayoshi Kohno - Cryptography Engineering - Design Principles and Practical Applications:
             * As with OFB mode, you must make absolutely sure never to reuse a singlekey / nonce combination.
             *
             * Instead of a random IV (RAND_bytes) we derive IV from user_id and message_id to rule out IV collision, which is more probable when more and more encryption operations are done.
             */
            if(result == EXIT_SUCCESS && main_set_iv(iv, key, user_id, message_id) != EXIT_SUCCESS) {
                result = main_error(params, 1, "main_set_iv");
            }
            if(result == EXIT_SUCCESS && EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1) {
                result = main_error(params, 1, "EVP_EncryptInit_ex");
            }
            /* TODO add metadata to ciphertext_file
             *
             * key_salt, user_id, message_id
             */
            if(result == EXIT_SUCCESS && main_encrypt_pipe(params, ctx, plaintext_file, ciphertext_file) != EXIT_SUCCESS) {
                result = main_error(params, 1, "main_encrypt_pipe");
            }
            if(result == EXIT_SUCCESS) {
                fprintf(params->out, "Šifravimo operacija baigta vykdyti sėkmingai\n");
            }
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    free(password);
    free(iv);
    free(key);
    free(key_salt);
    free(user_id);
    free(message_id);
    return result;
}
