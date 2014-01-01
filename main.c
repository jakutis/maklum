#include "main.h"

int main(int argc, const char **argv) {
    size_t size_t_bytes = sizeof(size_t);
    main_params params;

    /* These two arrays are taken from RFC 5114. */
    unsigned char p[] = {
0x87, 0xA8, 0xE6, 0x1D, 0xB4, 0xB6, 0x66, 0x3C, 0xFF, 0xBB, 0xD1, 0x9C,
0x65, 0x19, 0x59, 0x99, 0x8C, 0xEE, 0xF6, 0x08, 0x66, 0x0D, 0xD0, 0xF2,
0x5D, 0x2C, 0xEE, 0xD4, 0x43, 0x5E, 0x3B, 0x00, 0xE0, 0x0D, 0xF8, 0xF1,
0xD6, 0x19, 0x57, 0xD4, 0xFA, 0xF7, 0xDF, 0x45, 0x61, 0xB2, 0xAA, 0x30,
0x16, 0xC3, 0xD9, 0x11, 0x34, 0x09, 0x6F, 0xAA, 0x3B, 0xF4, 0x29, 0x6D,
0x83, 0x0E, 0x9A, 0x7C, 0x20, 0x9E, 0x0C, 0x64, 0x97, 0x51, 0x7A, 0xBD,
0x5A, 0x8A, 0x9D, 0x30, 0x6B, 0xCF, 0x67, 0xED, 0x91, 0xF9, 0xE6, 0x72,
0x5B, 0x47, 0x58, 0xC0, 0x22, 0xE0, 0xB1, 0xEF, 0x42, 0x75, 0xBF, 0x7B,
0x6C, 0x5B, 0xFC, 0x11, 0xD4, 0x5F, 0x90, 0x88, 0xB9, 0x41, 0xF5, 0x4E,
0xB1, 0xE5, 0x9B, 0xB8, 0xBC, 0x39, 0xA0, 0xBF, 0x12, 0x30, 0x7F, 0x5C,
0x4F, 0xDB, 0x70, 0xC5, 0x81, 0xB2, 0x3F, 0x76, 0xB6, 0x3A, 0xCA, 0xE1,
0xCA, 0xA6, 0xB7, 0x90, 0x2D, 0x52, 0x52, 0x67, 0x35, 0x48, 0x8A, 0x0E,
0xF1, 0x3C, 0x6D, 0x9A, 0x51, 0xBF, 0xA4, 0xAB, 0x3A, 0xD8, 0x34, 0x77,
0x96, 0x52, 0x4D, 0x8E, 0xF6, 0xA1, 0x67, 0xB5, 0xA4, 0x18, 0x25, 0xD9,
0x67, 0xE1, 0x44, 0xE5, 0x14, 0x05, 0x64, 0x25, 0x1C, 0xCA, 0xCB, 0x83,
0xE6, 0xB4, 0x86, 0xF6, 0xB3, 0xCA, 0x3F, 0x79, 0x71, 0x50, 0x60, 0x26,
0xC0, 0xB8, 0x57, 0xF6, 0x89, 0x96, 0x28, 0x56, 0xDE, 0xD4, 0x01, 0x0A,
0xBD, 0x0B, 0xE6, 0x21, 0xC3, 0xA3, 0x96, 0x0A, 0x54, 0xE7, 0x10, 0xC3,
0x75, 0xF2, 0x63, 0x75, 0xD7, 0x01, 0x41, 0x03, 0xA4, 0xB5, 0x43, 0x30,
0xC1, 0x98, 0xAF, 0x12, 0x61, 0x16, 0xD2, 0x27, 0x6E, 0x11, 0x71, 0x5F,
0x69, 0x38, 0x77, 0xFA, 0xD7, 0xEF, 0x09, 0xCA, 0xDB, 0x09, 0x4A, 0xE9,
0x1E, 0x1A, 0x15, 0x97,
};
    unsigned char g[] = {
0x3F, 0xB3, 0x2C, 0x9B, 0x73, 0x13, 0x4D, 0x0B, 0x2E, 0x77, 0x50, 0x66,
0x60, 0xED, 0xBD, 0x48, 0x4C, 0xA7, 0xB1, 0x8F, 0x21, 0xEF, 0x20, 0x54,
0x07, 0xF4, 0x79, 0x3A, 0x1A, 0x0B, 0xA1, 0x25, 0x10, 0xDB, 0xC1, 0x50,
0x77, 0xBE, 0x46, 0x3F, 0xFF, 0x4F, 0xED, 0x4A, 0xAC, 0x0B, 0xB5, 0x55,
0xBE, 0x3A, 0x6C, 0x1B, 0x0C, 0x6B, 0x47, 0xB1, 0xBC, 0x37, 0x73, 0xBF,
0x7E, 0x8C, 0x6F, 0x62, 0x90, 0x12, 0x28, 0xF8, 0xC2, 0x8C, 0xBB, 0x18,
0xA5, 0x5A, 0xE3, 0x13, 0x41, 0x00, 0x0A, 0x65, 0x01, 0x96, 0xF9, 0x31,
0xC7, 0x7A, 0x57, 0xF2, 0xDD, 0xF4, 0x63, 0xE5, 0xE9, 0xEC, 0x14, 0x4B,
0x77, 0x7D, 0xE6, 0x2A, 0xAA, 0xB8, 0xA8, 0x62, 0x8A, 0xC3, 0x76, 0xD2,
0x82, 0xD6, 0xED, 0x38, 0x64, 0xE6, 0x79, 0x82, 0x42, 0x8E, 0xBC, 0x83,
0x1D, 0x14, 0x34, 0x8F, 0x6F, 0x2F, 0x91, 0x93, 0xB5, 0x04, 0x5A, 0xF2,
0x76, 0x71, 0x64, 0xE1, 0xDF, 0xC9, 0x67, 0xC1, 0xFB, 0x3F, 0x2E, 0x55,
0xA4, 0xBD, 0x1B, 0xFF, 0xE8, 0x3B, 0x9C, 0x80, 0xD0, 0x52, 0xB9, 0x85,
0xD1, 0x82, 0xEA, 0x0A, 0xDB, 0x2A, 0x3B, 0x73, 0x13, 0xD3, 0xFE, 0x14,
0xC8, 0x48, 0x4B, 0x1E, 0x05, 0x25, 0x88, 0xB9, 0xB7, 0xD2, 0xBB, 0xD2,
0xDF, 0x01, 0x61, 0x99, 0xEC, 0xD0, 0x6E, 0x15, 0x57, 0xCD, 0x09, 0x15,
0xB3, 0x35, 0x3B, 0xBB, 0x64, 0xE0, 0xEC, 0x37, 0x7F, 0xD0, 0x28, 0x37,
0x0D, 0xF9, 0x2B, 0x52, 0xC7, 0x89, 0x14, 0x28, 0xCD, 0xC6, 0x7E, 0xB6,
0x18, 0x4B, 0x52, 0x3D, 0x1D, 0xB2, 0x46, 0xC3, 0x2F, 0x63, 0x07, 0x84,
0x90, 0xF0, 0x0E, 0xF8, 0xD6, 0x47, 0xD1, 0x48, 0xD4, 0x79, 0x54, 0x51,
0x5E, 0x23, 0x27, 0xCF, 0xEF, 0x98, 0xC5, 0x82, 0x66, 0x4B, 0x4C, 0x0F,
0x6C, 0xC4, 0x16, 0x59,
};

    params.debug = 1;
    params.tag_length = 16;
    params.in = stdin;
    params.out = stdout;
    params.password_length = 50;
    params.pbkdf2_iterations = 16384;
    params.pipe_buffer_size = 100000;
    params.iv_length = 16;
    params.key_salt_length = 32;
    params.size_t_format = NULL;
    params.dh_prime_length = 2048;
    params.dh_generator_length = 2048;
    params.dh_generator = g;
    params.dh_prime = p;

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
    } else if(strcmp(argv[1], "sukurtiparametrus") == 0) {
        return main_a(&params);
    } else {
        return main_error(&params, 0, "neatpažintas operacijos pavadinimas"
                " (turi būti vienas iš: \"uzsifruoti\", \"issifruoti\", \"sukurtiparametrus\")");
    }
}

int main_a(main_params *params) {
    int result = EXIT_SUCCESS;

    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *dh_params = NULL;

    if(result == EXIT_SUCCESS && (ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL)) == NULL) {
        result = main_error(params, 0, "EVP_PKEY_CTX_new_id");
    }
    if(result == EXIT_SUCCESS && EVP_PKEY_paramgen_init(ctx) != 1) {
        result = main_error(params, 0, "EVP_PKEY_paramgen_init");
    }
    if(result == EXIT_SUCCESS && EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, (int)params->dh_prime_length) != 1) {
        result = main_error(params, 0, "EVP_PKEY_CTX_set_dh_paramgen_prime_len");
    }
    if(result == EXIT_SUCCESS && params->debug) {
        fprintf(params->out, "Pradedamas vykdyti parametrų generavimas.\n");
    }
    if(result == EXIT_SUCCESS && EVP_PKEY_paramgen(ctx, &dh_params)) {
        result = main_error(params, 0, "EVP_PKEY_paramgen");
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(dh_params);

    return result;
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

    unsigned char *tag = malloc(params->tag_length * sizeof(char));
    unsigned char *iv = malloc(params->iv_length * sizeof(char));
    unsigned char *key_salt = malloc(params->key_salt_length * sizeof(char));
    size_t key_length = 32;
    unsigned char *key = malloc(key_length * sizeof(char));
    char *password = malloc((params->password_length + 1) * sizeof(char));
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    fpos_t *tag_pos = malloc(sizeof(fpos_t));

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
            /*
             * 2011 - David McGrew - Galois Counter Mode:
             *
             * Another criticism is that security degrades with the length of
             * messages that are processed. These demerits are due to the
             * choice of hash function used in GCM, which also bring low
             * computational cost and low latency.
             */
            /*
             * Since this cryptosystem is designed to for the exchange of
             * manually typed messages by two persons, it is not expected
             * that the vulnerability related to message length is of any
             * concern.
             */
            if(result == EXIT_SUCCESS && EVP_EncryptInit_ex(ctx,
                        EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
                result = main_error(params, 1, "EVP_EncryptInit_ex (mode)");
            }
            if(result == EXIT_SUCCESS && EVP_CIPHER_CTX_ctrl(ctx,
                        EVP_CTRL_GCM_SET_IVLEN, (int)params->iv_length, NULL) != 1) {
                result = main_error(params, 1, "EVP_CIPHER_CTX_ctrl");
;
            }
            if(result == EXIT_SUCCESS && EVP_EncryptInit_ex(ctx,
                        NULL, NULL, key, iv) != 1) {
                result = main_error(params, 1, "EVP_EncryptInit_ex (key, iv)");
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
            if(result == EXIT_SUCCESS && fgetpos(ciphertext_file, tag_pos)) {
                result = main_error(params, 1, "fgetpos");
            }
            if(result == EXIT_SUCCESS && fwrite(tag, sizeof(char),
                        params->tag_length, ciphertext_file) <
                    params->tag_length) {
                result = main_error(params, 1, "fwrite (spacing tag)");
            }
            if(result == EXIT_SUCCESS && main_encrypt_pipe(params, ctx,
                        plaintext_file, ciphertext_file) != EXIT_SUCCESS) {
                result = main_error(params, 1, "main_encrypt_pipe");
            }
            if(result == EXIT_SUCCESS && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                        (int)params->tag_length, tag) != 1) {
                result = main_error(params, 1, "EVP_CIPHER_CTX_ctrl");
            }
            if(result == EXIT_SUCCESS && fsetpos(ciphertext_file, tag_pos)) {
                result = main_error(params, 1, "fsetpos");
            }
            if(result == EXIT_SUCCESS && fwrite(tag, sizeof(char),
                        params->tag_length, ciphertext_file) <
                    params->tag_length) {
                result = main_error(params, 1, "fwrite (actual tag)");
            }
            if(result == EXIT_SUCCESS && params->debug) {
                fprintf(params->out, "Baigtas užšifravimas, TAG=");
                main_write_bytes_hex(params, tag, params->tag_length);
                fprintf(params->out, ".\n");
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
    OPENSSL_cleanse(tag_pos, sizeof(fpos_t));
    OPENSSL_cleanse(tag, params->tag_length * sizeof(char));
    OPENSSL_cleanse(password, (params->password_length + 1) * sizeof(char));
    OPENSSL_cleanse(key, key_length * sizeof(char));
    OPENSSL_cleanse(iv, 16 * sizeof(char));
    OPENSSL_cleanse(key_salt, params->key_salt_length * sizeof(char));
    EVP_CIPHER_CTX_free(ctx);
    free(tag_pos);
    free(tag);
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

    unsigned char *tag = malloc(params->tag_length * sizeof(char));
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
        fread(iv, sizeof(char), params->iv_length, ciphertext_file);
        if(ferror(ciphertext_file)) {
            result = main_error(params, 1,
                    "nepavyko nuskaityti inicializacijos vektoriaus");
        }
    }
    if(result == EXIT_SUCCESS) {
        fread(tag, sizeof(char), params->tag_length, ciphertext_file);
        if(ferror(ciphertext_file)) {
            result = main_error(params, 1, "fread (tag)");
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
        fprintf(params->out, ", TAG=");
        main_write_bytes_hex(params, tag, params->tag_length);
        fprintf(params->out, ", KEY=");
        main_write_bytes_hex(params, key, key_length);
        fprintf(params->out, ".\n");
    }
    if(result == EXIT_SUCCESS && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(),
                NULL, NULL, NULL) != 1) {
        result = main_error(params, 1, "EVP_EncryptInit_ex (mode)");
    }
    if(result == EXIT_SUCCESS && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                (int)params->tag_length, tag) != 1) {
        result = main_error(params, 1, "EVP_CIPHER_CTX_ctrl (TAG)");
    }
    if(result == EXIT_SUCCESS && EVP_CIPHER_CTX_ctrl(ctx,
                EVP_CTRL_GCM_SET_IVLEN, (int)params->iv_length, NULL) != 1) {
        result = main_error(params, 1, "EVP_CIPHER_CTX_ctrl (IVLEN)");
    }
    if(result == EXIT_SUCCESS && EVP_DecryptInit_ex(ctx, NULL,
                NULL, key, iv) != 1) {
        result = main_error(params, 1, "EVP_EncryptInit_ex (key, iv)");
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
    OPENSSL_cleanse(tag, params->tag_length * sizeof(char));
    OPENSSL_cleanse(password, (params->password_length + 1) * sizeof(char));
    OPENSSL_cleanse(key, key_length * sizeof(char));
    OPENSSL_cleanse(iv, params->iv_length * sizeof(char));
    OPENSSL_cleanse(key_salt, params->key_salt_length * sizeof(char));
    OPENSSL_cleanse(&size_t_size, sizeof(char));
    EVP_CIPHER_CTX_free(ctx);
    free(tag);
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

