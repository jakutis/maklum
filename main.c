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

    params.in = stdin;
    params.out = stdout;
    params.password_length = 50;
    params.pbkdf2_iterations = 100;
    params.pipe_buffer_size = 100000;
    params.iv_length = 16;
    params.key_salt_length = 32;
    params.message_id_length = 8;
    params.user_id_length = 8;
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

    for(i = 0; i < text_length; i += 1) {
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

int main_set_iv(main_params *params, unsigned char *iv, unsigned char *key,
        char *user_id, char *message_id) {
    int result = EXIT_SUCCESS;
    unsigned char *nonce;

    nonce = malloc(params->iv_length * sizeof(char));
    memcpy(nonce, user_id, params->user_id_length);
    memcpy(nonce + params->user_id_length, message_id,
            params->message_id_length);

    if(main_aes(nonce, iv, key) != EXIT_SUCCESS) {
        result = EXIT_FAILURE;
    }

    OPENSSL_cleanse(nonce, params->iv_length * sizeof(char));

    free(nonce);
    return result;
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

    char *message_id = malloc((params->message_id_length + 1) * sizeof(char));
    char *user_id = malloc((params->user_id_length + 1) * sizeof(char));

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
        fprintf(params->out, "Suveskite vartotojo identifikatorių (maksimalus"
                " ilgis yra ");
        main_write_size_t(params, params->user_id_length);
        fprintf(params->out, "): ");
        main_read_text(params, user_id, params->user_id_length);
        fprintf(params->out, "Suveskite šio vartotojo vardu atliekamos"
                " užšifravimo operacijos vienkartinį identifikatorių"
                " (maksimalus ilgis yra ");
        main_write_size_t(params, params->message_id_length);
        fprintf(params->out, "): ");
        main_read_text(params, message_id, params->message_id_length);
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
        fprintf(params->out, "Vartotojo identifikatorius: %s\n", user_id);
        fprintf(params->out, "Operacijos identifikatorius: %s\n", message_id);
        fprintf(params->out, "Slaptažodis: %s\n", password);
        fprintf(params->out, "Ar pradėti operaciją (taip/ne)? ");
        if(main_read_yesno(params, "taip")) {
            fprintf(params->out, "Operacija vykdoma, prašome palaukti\n");

            if(RAND_bytes(key_salt, (int)params->key_salt_length) != 1) {
                result = main_error(params, 1, "RAND_bytes");
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
             * Instead of a random IV (RAND_bytes) we derive IV from user_id
             * and message_id to rule out IV collision, which is more probable
             * when more and more encryption operations are done.
             */
            if(result == EXIT_SUCCESS && main_set_iv(params, iv, key, user_id,
                        message_id) != EXIT_SUCCESS) {
                result = main_error(params, 1, "main_set_iv");
            }
            if(result == EXIT_SUCCESS) {
                fprintf(params->out, "Pradedamas užšifravimas, IV=");
                main_write_bytes_hex(params, iv, params->iv_length);
                fprintf(params->out, ", KEY=");
                main_write_bytes_hex(params, key, key_length);
                fprintf(params->out, ".\n");
            }
            if(result == EXIT_SUCCESS && EVP_EncryptInit_ex(ctx,
                        EVP_aes_256_ctr(), NULL, key, iv) != 1) {
                result = main_error(params, 1, "EVP_EncryptInit_ex");
            }
            if(result == EXIT_SUCCESS && fwrite(key_salt, sizeof(char),
                        params->key_salt_length, ciphertext_file) <
                    params->key_salt_length) {
                result = main_error(params, 1, "fwrite (key_salt)");
            }
            if(result == EXIT_SUCCESS && fwrite(user_id, sizeof(char),
                        params->user_id_length, ciphertext_file) <
                    params->user_id_length) {
                result = main_error(params, 1, "fwrite (user_id)");
            }
            if(result == EXIT_SUCCESS && fwrite(message_id, sizeof(char),
                        params->message_id_length, ciphertext_file) <
                    params->message_id_length) {
                result = main_error(params, 1, "fwrite (message_id)");
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
    OPENSSL_cleanse(user_id, (params->user_id_length + 1) * sizeof(char));
    OPENSSL_cleanse(message_id, (params->message_id_length + 1) * sizeof(char));
    EVP_CIPHER_CTX_free(ctx);
    free(password);
    free(iv);
    free(key);
    free(key_salt);
    free(user_id);
    free(message_id);

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

    char *message_id = malloc((params->message_id_length + 1) * sizeof(char));
    char *user_id = malloc((params->user_id_length + 1) * sizeof(char));

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
        fread(user_id, sizeof(char), params->user_id_length,
                ciphertext_file);
        if(ferror(ciphertext_file)) {
            result = main_error(params, 1,
                    "nepavyko nuskaityti vartotojo identifikatoriaus");
        } else {
            user_id[params->user_id_length] = 0;
        }
    }
    if(result == EXIT_SUCCESS) {
        fread(message_id, sizeof(char), params->message_id_length,
                ciphertext_file);
        if(ferror(ciphertext_file)) {
            result = main_error(params, 1,
                    "nepavyko nuskaityti operacijos identifikatoriaus");
        } else {
            message_id[params->message_id_length] = 0;
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
    if(result == EXIT_SUCCESS && main_set_iv(params, iv, key, user_id,
                message_id) != EXIT_SUCCESS) {
        result = main_error(params, 1, "main_set_iv");
    }
    if(result == EXIT_SUCCESS) {
        fprintf(params->out, "Pradedamas iššifravimas, IV=");
        main_write_bytes_hex(params, iv, params->iv_length);
        fprintf(params->out, ", KEY=");
        main_write_bytes_hex(params, key, key_length);
        fprintf(params->out, ".\n");
    }
    if(result == EXIT_SUCCESS && EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(),
                NULL, key, iv) != 1) {
        result = main_error(params, 1, "EVP_EncryptInit_ex");
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
    OPENSSL_cleanse(message_id, (params->message_id_length + 1) * sizeof(char));
    OPENSSL_cleanse(user_id, (params->user_id_length + 1) * sizeof(char));
    OPENSSL_cleanse(&size_t_size, sizeof(char));
    EVP_CIPHER_CTX_free(ctx);
    free(password);
    free(iv);
    free(key);
    free(key_salt);
    free(user_id);
    free(message_id);


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
