#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "openssl/evp.h"
#include "openssl/aes.h"
#include "openssl/rand.h"

#include "main.h"

int main(int argc, const char **argv) {
    size_t size_t_bytes = sizeof(size_t);
    main_params params;

    params.debug = 0;
    params.in = stdin;
    params.out = stdout;
    params.password_length = 50;
    params.pbkdf2_iterations = 16384;
    params.pipe_buffer_size = 100000;
    params.iv_length = 16;
    params.key_salt_length = 32;
    params.size_t_format = NULL;

    if(sizeof(short int) == size_t_bytes) {
        params.size_t_format = "%hu";
    } else if(sizeof(int) == size_t_bytes) {
        params.size_t_format = "%u";
    } else if(sizeof(long int) == size_t_bytes) {
        params.size_t_format = "%lu";
    }

    if(argc < 2) {
        return main_error(&params, 0, "nepateiktas operacijos pavadinimas");
    }
    if(strcmp(argv[1], "uzsifruoti") == 0) {
        if(argc == 2) {
            return main_error(&params, 0,
                    "nepateiktas tekstogramos failo vardas");
        }
        if(argc == 3) {
            return main_error(&params, 0,
                    "nepateiktas šifrogramos failo vardas");
        }
        return main_encrypt(&params, argv[2], argv[3]);
    } else if(strcmp(argv[1], "issifruoti") == 0) {
        if(argc == 2) {
            return main_error(&params, 0,
                    "nepateiktas šifrogramos failo vardas");
        }
        if(argc == 3) {
            return main_error(&params, 0,
                    "nepateiktas tekstogramos failo vardas");
        }
        return main_decrypt(&params, argv[2], argv[3]);
    } else {
        return main_error(&params, 0, "neatpažintas operacijos pavadinimas"
                " (turi būti vienas iš: \"uzsifruoti\", \"issifruoti\")");
    }
}

void main_read_text(main_params *params, char *text, size_t text_length) {
    size_t i;
    int c;

    c = 0;
    for(i = 0; !isgraph(c); i += 1) {
        c = fgetc(params->in);
    }
    text[0] = (char)c;

    for(i = 1; i < text_length; i += 1) {
        c = fgetc(params->in);
        if(!isgraph(c)) {
            break;
        }
        text[i] = (char)c;
    }
    text[i] = 0;

    OPENSSL_cleanse(&i, sizeof(size_t));
    OPENSSL_cleanse(&c, sizeof(int));

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

    OPENSSL_cleanse(&n, sizeof(size_t));
    OPENSSL_cleanse(response, (n + 1) * sizeof(char));

    free(response);

    return result;
}

int main_error(main_params *params, int type, const char *message) {
    fprintf(params->out, "%s klaida: %s.\n", type == 0 ? "Vartotojo" :
            "Sisteminė", message);
    return EXIT_FAILURE;
}

int main_string_to_integer(main_params *params, char *string, size_t *integer) {
    if(sscanf(string, params->size_t_format, integer) == 1) {
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}

int main_read_integer(main_params *params, size_t *integer) {
    int result;
    char *string;
    size_t n;

    main_digits(SIZE_MAX, &n);
    string = malloc((n + 1) * sizeof(char));
    main_read_text(params, string, n);
    result = main_string_to_integer(params, string, integer);

    OPENSSL_cleanse(string, (n + 1) * sizeof(char));

    free(string);
    return result;
}

int main_aes(const unsigned char *in, unsigned char *out,
        const unsigned char *key) {
    AES_KEY aes_key;

    if(AES_set_encrypt_key(key, 256, &aes_key) != 0) {
        return EXIT_FAILURE;
    }
    AES_encrypt(in, out, &aes_key);

    OPENSSL_cleanse(&aes_key, sizeof(AES_KEY));

    return EXIT_SUCCESS;
}

void main_digits(size_t n, size_t *d) {
    for(*d = 1; n > 9; *d += 1) {
        n /= 10;
    }
}

int main_encrypt_pipe(main_params *params, EVP_CIPHER_CTX *ctx, FILE *in,
        FILE *out) {
    int result = EXIT_SUCCESS;
    size_t plaintext_available;
    int ciphertext_available = 0;
    unsigned char *plaintext = malloc(params->pipe_buffer_size * sizeof(char));
    unsigned char *ciphertext = malloc(params->pipe_buffer_size * sizeof(char));

    while(!feof(in)) {
        plaintext_available = fread(plaintext, sizeof(char),
                params->pipe_buffer_size, in);
        fprintf(params->out, "Nuskaityta tekstogramos baitų: ");
        main_write_size_t(params, plaintext_available);
        fprintf(params->out, "\n");
        if(ferror(in) ||
                EVP_EncryptUpdate(ctx, ciphertext,
                    &ciphertext_available, plaintext,
                    (int)plaintext_available) != 1 ||
                fwrite(ciphertext, sizeof(char), (size_t)ciphertext_available,
                    out) < (size_t)ciphertext_available) {
            result = EXIT_FAILURE;
            break;
        }
        fprintf(params->out, "Įrašyta šifrogramos baitų: %d\n",
                ciphertext_available);
    }
    if(result == EXIT_SUCCESS && EVP_EncryptFinal_ex(ctx, ciphertext,
                &ciphertext_available) != 1) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS && fwrite(ciphertext, sizeof(char),
                (size_t)ciphertext_available, out) <
                (size_t)ciphertext_available) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS) {
        fprintf(params->out, "Įrašyta paskutinių šifrogramos baitų: %d\n",
                ciphertext_available);
    }

    OPENSSL_cleanse(plaintext, params->pipe_buffer_size *
            sizeof(char));
    OPENSSL_cleanse(ciphertext, params->pipe_buffer_size *
            sizeof(char));
    OPENSSL_cleanse(&plaintext_available, sizeof(size_t));
    OPENSSL_cleanse(&ciphertext_available, sizeof(int));

    free(plaintext);
    free(ciphertext);

    return result;
}

int main_encrypt(main_params *params, const char *plaintext_filename,
        const char *ciphertext_filename) {
    int result = EXIT_SUCCESS;

    unsigned char *iv = malloc(16 * sizeof(char));
    unsigned char *key_salt = malloc(params->key_salt_length * sizeof(char));
    size_t key_length = 32;
    unsigned char *key = malloc(key_length * sizeof(char));
    char *password = malloc((params->password_length + 1) * sizeof(char));
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    FILE *plaintext_file = NULL;
    FILE *ciphertext_file = NULL;

    if(result == EXIT_SUCCESS) {
        plaintext_file = fopen(plaintext_filename, "rb");
        if(plaintext_file == NULL) {
            result = main_error(params, 0, "nepavyko atidaryti tekstogramos"
                    " failo");
        }
    }
    if(result == EXIT_SUCCESS) {
        ciphertext_file = fopen(ciphertext_filename, "wb");
        if(ciphertext_file == NULL) {
            result = main_error(params, 0, "nepavyko atidaryti šifrogramos"
                    " failo");
        }
    }
    if(result == EXIT_SUCCESS) {
        fprintf(params->out, "Suveskite užšifravimo slaptažodį (maksimalus"
                " ilgis yra ");
        main_write_size_t(params, params->password_length);
        fprintf(params->out, "): ");
        main_read_text(params, password, params->password_length);
        fprintf(params->out, "Ačiū! Sistema pasiruošusi šifravimo operacijai"
                " su tokiais parametrais:\n");
        fprintf(params->out, "Tekstogramos failas: %s\n", plaintext_filename);
        fprintf(params->out, "Šifrogramos failas: %s\n", ciphertext_filename);
        fprintf(params->out, "Slaptažodis: %s\n", password);
        fprintf(params->out, "Ar pradėti operaciją (taip/ne)? ");
        if(main_read_yesno(params, "taip")) {
            fprintf(params->out, "Operacija vykdoma, prašome palaukti\n");

            if(RAND_bytes(key_salt, (int)params->key_salt_length) != 1) {
                result = main_error(params, 1, "RAND_bytes (key_salt)");
            }
            if(result == EXIT_SUCCESS && PKCS5_PBKDF2_HMAC_SHA1(password,
                        (int)strlen(password), key_salt,
                        (int)params->key_salt_length,
                        (int)params->pbkdf2_iterations,
                        (int)key_length, key) != 1) {
                result = main_error(params, 1, "PKCS5_PBKDF2_HMAC_SHA1");
            }
            /*
             * 2010 - Niels Ferguson, Bruce Schneier, Tadayoshi Kohno -
             * Cryptography Engineering - Design Principles and Practical
             * Applications:
             * As with OFB mode, you must make absolutely sure never to reuse
             * a singlekey / nonce combination.
             *
             * In the previous versions of this system, instead of a random IV
             * (RAND_bytes) we derived IV from user_id and message_id to rule
             * out IV collision, which is more probable when more and more
             * encryption operations are done.
             *
             * But now, we go back to just generating a random IV. The
             * probability of collision is probably lower than a probability of
             * user entering the same user id and message id pair.
             */
            if(result == EXIT_SUCCESS && RAND_bytes(iv, (int)params->iv_length) != 1) {
                result = main_error(params, 1, "RAND_bytes (iv)");
            }
            if(result == EXIT_SUCCESS && params->debug) {
                fprintf(params->out, "Pradedamas užšifravimas, IV=");
                main_write_bytes_hex(params, iv, params->iv_length);
                fprintf(params->out, ", KEY=");
                main_write_bytes_hex(params, key, key_length);
                fprintf(params->out, ".\n");
            }
            if(result == EXIT_SUCCESS && EVP_EncryptInit(ctx,
                        EVP_aes_256_ctr(), key, iv) != 1) {
                result = main_error(params, 1, "EVP_EncryptInit");
            }
            if(result == EXIT_SUCCESS && fwrite(key_salt, sizeof(char),
                        params->key_salt_length, ciphertext_file) <
                    params->key_salt_length) {
                result = main_error(params, 1, "fwrite (key_salt)");
            }
            if(result == EXIT_SUCCESS && fwrite(iv, sizeof(char),
                        params->iv_length, ciphertext_file) <
                    params->iv_length) {
                result = main_error(params, 1, "fwrite (iv)");
            }
            if(result == EXIT_SUCCESS && main_encrypt_pipe(params, ctx,
                        plaintext_file, ciphertext_file) != EXIT_SUCCESS) {
                result = main_error(params, 1, "main_encrypt_pipe");
            }
        }
    }
    if(ciphertext_file != NULL) {
        if(fclose(ciphertext_file) == EOF) {
            result = main_error(params, 1, "nepavyko uždaryti šifrogramos"
                    " failo");
        }
    }
    if(plaintext_file != NULL) {
        if(fclose(plaintext_file) == EOF) {
            result = main_error(params, 1, "nepavyko uždaryti tekstogramos"
                    " failo");
        }
    }
    OPENSSL_cleanse(password, (params->password_length + 1) * sizeof(char));
    OPENSSL_cleanse(key, key_length * sizeof(char));
    OPENSSL_cleanse(iv, 16 * sizeof(char));
    OPENSSL_cleanse(key_salt, params->key_salt_length * sizeof(char));
    EVP_CIPHER_CTX_free(ctx);
    free(password);
    free(iv);
    free(key);
    free(key_salt);

    if(result == EXIT_SUCCESS) {
        fprintf(params->out, "Užšifravimo operacija baigta vykdyti"
                " sėkmingai\n");
    }
    return result;
}

int main_write_size_t(main_params *params, size_t size) {
    if(params->size_t_format != NULL && fprintf(params->out,
                params->size_t_format, size) >= 0) {
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}

int main_decrypt_pipe(main_params *params, EVP_CIPHER_CTX *ctx, FILE *in,
        FILE *out) {
    int result = EXIT_SUCCESS;
    size_t ciphertext_available;
    int plaintext_available = 0;
    unsigned char *plaintext = malloc(params->pipe_buffer_size * sizeof(char));
    unsigned char *ciphertext = malloc(params->pipe_buffer_size * sizeof(char));

    while(!feof(in)) {
        ciphertext_available = fread(ciphertext, sizeof(char),
                params->pipe_buffer_size, in);
        fprintf(params->out, "Nuskaityta šifrogramos baitų: ");
        main_write_size_t(params, ciphertext_available);
        fprintf(params->out, "\n");
        if(ferror(in) ||
                EVP_DecryptUpdate(ctx, plaintext, &plaintext_available,
                    ciphertext, (int)ciphertext_available) != 1 ||
                fwrite(plaintext, sizeof(char), (size_t)plaintext_available,
                    out) < (size_t)plaintext_available) {
            result = EXIT_FAILURE;
            break;
        }
        fprintf(params->out, "Įrašyta tekstogramos baitų: %d\n",
                plaintext_available);
    }
    if(result == EXIT_SUCCESS && EVP_DecryptFinal_ex(ctx, plaintext,
                &plaintext_available) != 1) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS && fwrite(plaintext, sizeof(char),
                (size_t)plaintext_available, out) <
            (size_t)plaintext_available) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS) {
        fprintf(params->out, "Įrašyta paskutinių tekstogramos baitų: %d\n",
                plaintext_available);
    }

    OPENSSL_cleanse(ciphertext, params->pipe_buffer_size * sizeof(char));
    OPENSSL_cleanse(plaintext, params->pipe_buffer_size * sizeof(char));
    OPENSSL_cleanse(&ciphertext_available, sizeof(size_t));
    OPENSSL_cleanse(&plaintext_available, sizeof(int));

    free(plaintext);
    free(ciphertext);

    return result;
}

int main_decrypt(main_params *params, const char *ciphertext_filename,
        const char *plaintext_filename) {
    int result = EXIT_SUCCESS;

    FILE *plaintext_file = NULL;
    FILE *ciphertext_file = NULL;
    unsigned char size_t_size = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    unsigned char *iv = malloc(params->iv_length * sizeof(char));
    unsigned char *key_salt = malloc(params->key_salt_length * sizeof(char));
    size_t key_length = 32;
    unsigned char *key = malloc(key_length * sizeof(char));
    char *password = malloc((params->password_length + 1) * sizeof(char));

    if(result == EXIT_SUCCESS) {
        ciphertext_file = fopen(ciphertext_filename, "rb");
        if(ciphertext_file == NULL) {
            result = main_error(params, 0, "nepavyko atidaryti šifrogramos"
                    " failo");
        }
    }
    if(result == EXIT_SUCCESS) {
        plaintext_file = fopen(plaintext_filename, "wb");
        if(plaintext_file == NULL) {
            result = main_error(params, 0, "nepavyko atidaryti tekstogramos"
                    " failo");
        }
    }
    if(result == EXIT_SUCCESS) {
        fread(key_salt, sizeof(char), params->key_salt_length,
                ciphertext_file);
        if(ferror(ciphertext_file)) {
            result = main_error(params, 1, "nepavyko nuskaityti salt duomenų");
        }
    }
    if(result == EXIT_SUCCESS) {
        fread(iv, sizeof(char), params->iv_length,
                ciphertext_file);
        if(ferror(ciphertext_file)) {
            result = main_error(params, 1,
                    "nepavyko nuskaityti inicializacijos vektoriaus");
        }
    }
    if(result == EXIT_SUCCESS) {
        fprintf(params->out, "Suveskite iššifravimo slaptažodį (maksimalus"
                " ilgis yra ");
        main_write_size_t(params, params->password_length);
        fprintf(params->out, "): ");
        main_read_text(params, password, params->password_length);
    }
    if(result == EXIT_SUCCESS && PKCS5_PBKDF2_HMAC_SHA1(password,
                (int)strlen(password), key_salt, (int)params->key_salt_length,
                (int)params->pbkdf2_iterations, (int)key_length, key) != 1) {
        result = main_error(params, 1, "PKCS5_PBKDF2_HMAC_SHA1");
    }
    if(result == EXIT_SUCCESS && params->debug) {
        fprintf(params->out, "Pradedamas iššifravimas, IV=");
        main_write_bytes_hex(params, iv, params->iv_length);
        fprintf(params->out, ", KEY=");
        main_write_bytes_hex(params, key, key_length);
        fprintf(params->out, ".\n");
    }
    if(result == EXIT_SUCCESS && EVP_DecryptInit(ctx, EVP_aes_256_ctr(),
                key, iv) != 1) {
        result = main_error(params, 1, "EVP_DecryptInit");
    }
    if(result == EXIT_SUCCESS && main_decrypt_pipe(params, ctx,
                ciphertext_file, plaintext_file) != EXIT_SUCCESS) {
        result = main_error(params, 1, "main_decrypt_pipe");
    }
    if(ciphertext_file != NULL) {
        if(fclose(ciphertext_file) == EOF) {
            result = main_error(params, 1, "nepavyko uždaryti šifrogramos"
                    " failo");
        }
    }
    if(plaintext_file != NULL) {
        if(fclose(plaintext_file) == EOF) {
            result = main_error(params, 1, "nepavyko uždaryti tekstogramos"
                    " failo");
        }
    }
    OPENSSL_cleanse(password, (params->password_length + 1) * sizeof(char));
    OPENSSL_cleanse(key, key_length * sizeof(char));
    OPENSSL_cleanse(iv, params->iv_length * sizeof(char));
    OPENSSL_cleanse(key_salt, params->key_salt_length * sizeof(char));
    OPENSSL_cleanse(&size_t_size, sizeof(char));
    EVP_CIPHER_CTX_free(ctx);
    free(password);
    free(iv);
    free(key);
    free(key_salt);


    if(result == EXIT_SUCCESS) {
        fprintf(params->out, "Iššifravimo operacija baigta vykdyti"
                " sėkmingai\n");
    }
    return result;
}

int main_write_bytes_hex(main_params *params, unsigned char *bytes,
        size_t length) {
    size_t i;

    for(i = 0; i < length; i += 1) {
        if(fprintf(params->out, "%x", bytes[i]) < 0) {
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
