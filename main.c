#include "main.h"

int main(int argc, const char **argv) {
    size_t size_t_bytes = sizeof (size_t);
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
0x1E, 0x1A, 0x15, 0x97
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
0x6C, 0xC4, 0x16, 0x59
    };

    params.debug = 1;
    params.filename_length = 255;
    params.tag_length = 16;
    params.in = stdin;
    params.out = stdout;
    params.password_length = 50;
    params.pbkdf2_iterations = 16384;
    params.pipe_buffer_size = 100000;
    params.iv_length = 16;
    params.key_salt_length = 32;
    params.size_t_format = NULL;
    params.dh_prime_length = 256;
    params.dh_generator_length = 256;
    params.dh_generator = g;
    params.dh_prime = p;
    params.size_max = (size_t) - 1;

    if(sizeof (short int) == size_t_bytes) {
        params.size_t_format = "%hu";
    } else if(sizeof (int) == size_t_bytes) {
        params.size_t_format = "%u";
    } else if(sizeof (long int) == size_t_bytes) {
        params.size_t_format = "%lu";
    }

    if(argc < 2) {
        return main_error(&params, 0,
                "main: nepateiktas operacijos pavadinimas");
    }
    if(strcmp(argv[1], "uzsifruoti") == 0) {
        if(argc == 2) {
            return main_error(&params, 0,
                    "main: nepateiktas tekstogramos failo vardas");
        }
        if(argc == 3) {
            return main_error(&params, 0,
                    "main: nepateiktas šifrogramos failo vardas");
        }
        return main_encrypt(&params, argv[2], argv[3]);
    } else if(strcmp(argv[1], "issifruoti") == 0) {
        if(argc == 2) {
            return main_error(&params, 0,
                    "main: nepateiktas šifrogramos failo vardas");
        }
        if(argc == 3) {
            return main_error(&params, 0,
                    "main: nepateiktas tekstogramos failo vardas");
        }
        return main_decrypt(&params, argv[2], argv[3]);
    } else if(strcmp(argv[1], "sukurtiraktus") == 0) {
        return main_generate_keys(&params);
    } else {
        return main_error(&params, 0, "main: neatpažintas operacijos"
                " pavadinimas (turi būti vienas iš: \"uzsifruoti\","
                " \"issifruoti\", \"sukurtiraktus\")");
    }
}

int main_read_filename(main_params *params, const char *message,
        char *filename) {
    int result = EXIT_SUCCESS;

    fprintf(params->out, "%s (maksimalus ilgis yra ", message);
    main_write_size_t(params, params->filename_length);
    fprintf(params->out, "): ");
    main_read_text(params, filename, params->filename_length);

    return result;
}

int main_generate_and_write_dh_key(main_params *params, const char *filename,
        EVP_PKEY *dh_params, int private) {
    int result = EXIT_SUCCESS;
    EVP_PKEY *key = NULL;
    BIO *bio = NULL;

    if(result == EXIT_SUCCESS && main_generate_dh_key(params, dh_params, &key)
            != EXIT_SUCCESS) {
        result = main_error(params, 1,
                "main_generate_and_write_dh_key: main_generate_dh_key");
    }
    if(result == EXIT_SUCCESS && params->debug) {
        fprintf(params->out, "private key generated.\n");
    }
    if(result == EXIT_SUCCESS && (bio = BIO_new_file(filename, "wb")) == NULL) {
        result = main_error(params, 1, "main_generate_and_write_dh_key: BIO_new_file");
    }
    if(result == EXIT_SUCCESS && (
                private ?
                PEM_write_bio_PKCS8PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL) :
                PEM_write_bio_PUBKEY(bio, key)
                ) != 1) {
        result = main_error(params, 1,
                "main_generate_and_write_dh_key: PEM_write_bio_...");
    }
    BIO_free_all(bio);
    EVP_PKEY_free(key);

    return result;
}

int main_generate_keys(main_params *params) {
    int result = EXIT_SUCCESS;
    char *private_key_filename = NULL, *public_key_filename = NULL;
    EVP_PKEY *dh_params = NULL;

    if(result == EXIT_SUCCESS && (private_key_filename =
                malloc(params->filename_length + 1)) == NULL) {
        result = main_error(params, 1, "main_generate_keys: malloc"
                " (private_key_filename)");
    }
    if(result == EXIT_SUCCESS && (public_key_filename =
                malloc(params->filename_length + 1)) == NULL) {
        result = main_error(params, 1, "main_generate_keys: malloc"
                " (public_key_filename)");
    }

    if(result == EXIT_SUCCESS && main_read_filename(params,
                "Suveskite failo kelią kuriame norite išsaugoti savo privatųjį"
                " raktą", private_key_filename) != EXIT_SUCCESS) {
        result = main_error(params, 1,
                "main_generate_keys: main_read_filename (private)");
    }
    if(result == EXIT_SUCCESS && main_read_filename(params,
                "Suveskite failo kelią kuriame norite išsaugoti savo viešąjį"
                " raktą", public_key_filename) != EXIT_SUCCESS) {
        result = main_error(params, 1,
                "main_generate_keys: main_read_filename (public)");
    }

    if(result == EXIT_SUCCESS && params->debug) {
        fprintf(params->out, "public = %s, private = %s\n", public_key_filename,
                private_key_filename);
    }

    if(result == EXIT_SUCCESS &&
            main_fill_dh_params(params, &dh_params) != EXIT_SUCCESS) {
        result = main_error(params, 1,
                "main_generate_keys: main_fill_dh_params");
    }

    if(result == EXIT_SUCCESS && params->debug) {
        fprintf(params->out, "main_generate_keys: DH params read.\n");
        fprintf(params->out, "main_generate_keys: missing parameters: %d\n", EVP_PKEY_missing_parameters(dh_params));
    }

    if(result == EXIT_SUCCESS && main_generate_and_write_dh_key(params,
                private_key_filename, dh_params, 1) != EXIT_SUCCESS) {
        result = main_error(params, 1,
                "main_generate_keys: main_generate_and_write_dh_key (private)");
    }
    if(private_key_filename != NULL) {
        OPENSSL_cleanse(private_key_filename, params->filename_length + 1);
        free(private_key_filename);
    }

    if(result == EXIT_SUCCESS && params->debug) {
        fprintf(params->out, "private key written.\n");
    }

    if(result == EXIT_SUCCESS && main_generate_and_write_dh_key(params,
                public_key_filename, dh_params, 0) != EXIT_SUCCESS) {
        result = main_error(params, 1,
                "main_generate_keys: main_generate_and_write_dh_key (public)");
    }
    if(public_key_filename != NULL) {
        OPENSSL_cleanse(public_key_filename, params->filename_length + 1);
        free(public_key_filename);
    }

    if(result == EXIT_SUCCESS && params->debug) {
        fprintf(params->out, "public key written.\n");
    }

    EVP_PKEY_free(dh_params);

    return result;
}

void main_enum_init(main_enum *a, const char **all, size_t len) {
    size_t i;

    a->all = all;
    a->len = len;
    a->max = 0;
    for(i = 0; i < len; i += 1) {
        a->max = main_max(strlen(all[i]), a->max);
    }
    a->current = NULL;
    a->current_i = 0;
}

int main_generate_dh_key(main_params *params, EVP_PKEY *dh_params,
        EVP_PKEY **key) {
    int result = EXIT_SUCCESS;
    int status = 0;
    EVP_PKEY_CTX *ctx = NULL;

    if(result == EXIT_SUCCESS && params->debug) {
        fprintf(params->out, "main_generate_dh_key: entry.\n");
    }
    if(result == EXIT_SUCCESS &&
            (ctx = EVP_PKEY_CTX_new(dh_params, NULL)) == NULL) {
        result = main_error(params, 1,
                "main_generate_dh_key: EVP_PKEY_CTX_new");
    }
    if(result == EXIT_SUCCESS && params->debug) {
        fprintf(params->out, "main_generate_dh_key: context created.\n");
    }
    if(result == EXIT_SUCCESS && EVP_PKEY_keygen_init(ctx) != 1) {
        result = main_error(params, 1,
                "main_generate_dh_key: EVP_PKEY_keygen_init");
    }
    if(result == EXIT_SUCCESS && params->debug) {
        fprintf(params->out, "main_generate_dh_key: keygen initialized.\n");
    }
    if(result == EXIT_SUCCESS && (status = EVP_PKEY_keygen(ctx, key)) != 1) {
        ERR_print_errors_fp(params->out);
        fprintf(params->out, "main_generate_dh_key: EVP_PKEY_keygen returned status %d\n", status);
        result = main_error(params, 1,
                "main_generate_dh_key: EVP_PKEY_keygen");
    }
    if(result == EXIT_SUCCESS && params->debug) {
        fprintf(params->out, "main_generate_dh_key: keygen finished.\n");
    }

    EVP_PKEY_CTX_free(ctx);
    return result;
}


int main_fill_dh_params(main_params *params, EVP_PKEY **dh_params) {
    int result = EXIT_SUCCESS;
    DH *dh = NULL;

    if(result == EXIT_SUCCESS && (dh = DH_new()) == NULL) {
        result = main_error(params, 1,"main_fill_dh_params: DH_new");
    }
    if(result == EXIT_SUCCESS &&
            (dh->p = BN_bin2bn(params->dh_prime,
                               (int)params->dh_prime_length,
                               NULL)) == NULL) {
        result = main_error(params, 1,
                "main_fill_dh_params: BN_bin2bn (prime)");
    }
    if(result == EXIT_SUCCESS &&
            (dh->g = BN_bin2bn(params->dh_generator,
                               (int)params->dh_generator_length,
                               NULL)) == NULL) {
        result = main_error(params, 1,
                "main_fill_dh_params: BN_bin2bn (generator)");
    }
    if(result == EXIT_SUCCESS && (*dh_params = EVP_PKEY_new()) == NULL) {
        result = main_error(params, 1, "main_fill_dh_params: EVP_PKEY_new");
    }
		if(result == EXIT_SUCCESS && EVP_PKEY_set1_DH(*dh_params, dh) != 1) {
        result = main_error(params, 1,
                "main_fill_dh_params: EVP_PKEY_set1_DH");
    }
    DH_free(dh);

    return result;
}

int main_read_text(main_params *params, char *text, size_t text_length) {
    int result = EXIT_SUCCESS;
    size_t i;
    int c;

    c = 0;
    for(i = 0; !isgraph(c); i += 1) {
        c = fgetc(params->in);
        if(ferror(params->in)) {
            result = EXIT_FAILURE;
            break;
        }
    }

    if(result == EXIT_SUCCESS) {
        text[0] = (char)c;

        for(i = 1; i < text_length; i += 1) {
            c = fgetc(params->in);
            if(ferror(params->in)) {
                result = EXIT_FAILURE;
                break;
            }
            if(!isgraph(c)) {
                break;
            }
            text[i] = (char)c;
        }
    }

    if(result == EXIT_SUCCESS) {
        text[i] = 0;
        fprintf(params->out, "\n");
    }

    OPENSSL_cleanse(&i, sizeof i);
    OPENSSL_cleanse(&c, sizeof c);

    return result;
}

int main_read_yesno(main_params *params, const char *positive_response,
        int *yesno) {
    int result = EXIT_SUCCESS;
    size_t n;
    char *response = NULL;

    n = strlen(positive_response);
    if(result == EXIT_SUCCESS && (response = malloc(n + 1)) == NULL) {
        result = EXIT_FAILURE;
    }

    if(result == EXIT_SUCCESS && main_read_text(params, response, n) !=
            EXIT_SUCCESS) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS) {
        *yesno = strcmp(response, positive_response) == 0;
    }

    if(response != NULL) {
        OPENSSL_cleanse(response, n + 1);
        free(response);
    }
    OPENSSL_cleanse(&n, sizeof n);

    return result;
}

size_t main_max(size_t a, size_t b) {
    return a > b ? a : b;
}

int main_read_enum(main_params *params, main_enum *a) {
    int result = EXIT_SUCCESS;
    char *response = NULL;
    size_t i;

    if(result == EXIT_SUCCESS && (response = malloc(a->max + 1)) == NULL) {
        result = EXIT_FAILURE;
    }

    if(result == EXIT_SUCCESS &&
            main_read_text(params, response, a->max) != EXIT_SUCCESS) {
        result = EXIT_FAILURE;
    }

    if(result == EXIT_SUCCESS) {
        a->current = NULL;
        for(i = 0; i < a->len; i += 1) {
            if(!strcmp(a->all[i], response)) {
                a->current = a->all[i];
                a->current_i = i;
            }
        }
    }

    if(response != NULL) {
        OPENSSL_cleanse(response, a->max + 1);
        free(response);
    }
    OPENSSL_cleanse(&i, sizeof i);

    return result;
}

int main_error(main_params *params, int type, const char *message) {
    fprintf(params->out, "%s klaida: %s.\n", type ? "Sisteminė" : "Vartotojo",
            message);
    return EXIT_FAILURE;
}

int main_string_to_integer(main_params *params, char *string, size_t *integer) {
    if(sscanf(string, params->size_t_format, integer) == 1) {
        return EXIT_SUCCESS;
    }
    return EXIT_FAILURE;
}

int main_read_integer(main_params *params, size_t *integer) {
    int result = EXIT_SUCCESS;
    char *string = NULL;
    size_t n;

    main_digits(params->size_max, &n);
    if(result == EXIT_SUCCESS && (string = malloc(n + 1)) == NULL) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS &&
            main_read_text(params, string, n) != EXIT_SUCCESS) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS &&
            main_string_to_integer(params, string, integer) != EXIT_SUCCESS) {
        result = EXIT_FAILURE;
    }

    if(string != NULL) {
        OPENSSL_cleanse(string, n + 1);
        free(string);
    }
    return result;
}

int main_aes(const unsigned char *in, unsigned char *out,
        const unsigned char *key) {
    AES_KEY aes_key;

    if(AES_set_encrypt_key(key, 256, &aes_key) != 0) {
        return EXIT_FAILURE;
    }
    AES_encrypt(in, out, &aes_key);

    OPENSSL_cleanse(&aes_key, sizeof aes_key);

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
    unsigned char *plaintext = malloc(params->pipe_buffer_size);
    unsigned char *ciphertext = malloc(params->pipe_buffer_size);

    if(plaintext == NULL) {
        result = EXIT_FAILURE;
    }
    if(ciphertext == NULL) {
        result = EXIT_FAILURE;
    }

    if(result == EXIT_SUCCESS) {
        while(!feof(in)) {
            plaintext_available = fread(plaintext, 1, params->pipe_buffer_size, in);
            fprintf(params->out, "Nuskaityta tekstogramos baitų: ");
            main_write_size_t(params, plaintext_available);
            fprintf(params->out, "\n");
            if(ferror(in) ||
                    EVP_EncryptUpdate(ctx, ciphertext,
                        &ciphertext_available, plaintext,
                        (int)plaintext_available) != 1 ||
                    fwrite(ciphertext, 1, (size_t)ciphertext_available, out) <
                        (size_t)ciphertext_available) {
                result = EXIT_FAILURE;
                break;
            }
            fprintf(params->out, "Įrašyta šifrogramos baitų: %d\n",
                    ciphertext_available);
        }
    }
    if(result == EXIT_SUCCESS && EVP_EncryptFinal_ex(ctx, ciphertext,
                &ciphertext_available) != 1) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS && fwrite(ciphertext, 1,
                (size_t)ciphertext_available, out) <
                (size_t)ciphertext_available) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS) {
        fprintf(params->out, "Įrašyta paskutinių šifrogramos baitų: %d\n",
                ciphertext_available);
    }

    if(plaintext != NULL) {
        OPENSSL_cleanse(plaintext, params->pipe_buffer_size);
        free(plaintext);
    }
    if(ciphertext != NULL) {
        OPENSSL_cleanse(ciphertext, params->pipe_buffer_size);
        free(ciphertext);
    }
    OPENSSL_cleanse(&plaintext_available, sizeof plaintext_available);
    OPENSSL_cleanse(&ciphertext_available, sizeof ciphertext_available);

    return result;
}

int main_derive_key_dh(const char *private_key_filename,
        const char *public_key_filename, unsigned char *key,
        size_t key_length) {
    int result = EXIT_SUCCESS;
    unsigned char *skey = NULL;
    size_t skeylen = 0;
    EVP_MD_CTX mdctx;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL, *peerkey = NULL;
    BIO *bio = NULL;

    if(key_length != 32) {
        result = EXIT_FAILURE;
    }

    if(result == EXIT_SUCCESS &&
            (bio = BIO_new_file(private_key_filename, "rb")) == NULL) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS &&
            (pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)) == NULL) {
        result = EXIT_FAILURE;
    }
    BIO_free_all(bio);

    if(result == EXIT_SUCCESS &&
            (bio = BIO_new_file(public_key_filename, "rb")) == NULL) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS &&
            (peerkey =
             PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)) == NULL) {
        result = EXIT_FAILURE;
    }
    BIO_free_all(bio);

    if(result == EXIT_SUCCESS) {
    }
    if(result == EXIT_SUCCESS && (ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS && EVP_PKEY_derive_init(ctx) != 1) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS && EVP_PKEY_derive_set_peer(ctx, peerkey) != 1) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS && EVP_PKEY_derive(ctx, NULL, &skeylen) != 1) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS && (skey = malloc(skeylen)) == NULL) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS && EVP_PKEY_derive(ctx, skey, &skeylen) != 1) {
        result = EXIT_FAILURE;
    }
		EVP_PKEY_CTX_free(ctx);

    EVP_MD_CTX_init(&mdctx);
    if(result == EXIT_SUCCESS &&
            EVP_DigestInit_ex(&mdctx, EVP_sha256(), NULL) != 1) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS && EVP_DigestUpdate(&mdctx, skey, skeylen) != 1) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS && EVP_DigestFinal_ex(&mdctx, key, NULL) != 1) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS && EVP_MD_CTX_cleanup(&mdctx) != 1) {
        result = EXIT_FAILURE;
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peerkey);
    if(skey != NULL) {
        OPENSSL_cleanse(skey, skeylen);
        free(skey);
    }
    OPENSSL_cleanse(&skeylen, sizeof skeylen);

    return result;
}

int main_encrypt(main_params *params, const char *plaintext_filename,
        const char *ciphertext_filename) {
    int result = EXIT_SUCCESS;

    char *public_key_filename = malloc(params->filename_length + 1);
    char *private_key_filename = malloc(params->filename_length + 1);
    unsigned char *tag = malloc(params->tag_length);
    unsigned char *iv = malloc(params->iv_length);
    unsigned char *key_salt = malloc(params->key_salt_length);
    size_t key_length = 32;
    unsigned char *key = malloc(key_length);
    char *password = malloc(params->password_length + 1);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    fpos_t tag_pos;
    size_t kt_password = 0, kt_dh = 1;
    const char *key_types[] = {"password", "dh"};
    main_enum key_type;
    int confirm = 0;

    FILE *plaintext_file = NULL;
    FILE *ciphertext_file = NULL;

    if(public_key_filename == NULL ||
            private_key_filename == NULL ||
            tag == NULL ||
            iv == NULL ||
            key_salt == NULL ||
            key == NULL ||
            password == NULL) {
        result = EXIT_FAILURE;
    }

    if(result == EXIT_SUCCESS) {
        main_enum_init(&key_type, key_types, 2);
    }

    if(result == EXIT_SUCCESS) {
        plaintext_file = fopen(plaintext_filename, "rb");
        if(plaintext_file == NULL) {
            result = main_error(params, 1, "main_encrypt: nepavyko atidaryti"
                    " tekstogramos failo");
        }
    }
    if(result == EXIT_SUCCESS) {
        ciphertext_file = fopen(ciphertext_filename, "wb");
        if(ciphertext_file == NULL) {
            result = main_error(params, 1, "main_encrypt: nepavyko atidaryti"
                    " šifrogramos failo");
        }
    }
    if(result == EXIT_SUCCESS) {
        result = main_read_key_type(params, &key_type);
    }
    if(result == EXIT_SUCCESS) {
        if(key_type.current_i == kt_dh) {
            fprintf(params->out, "Suveskite kelią iki savo privačiojo rakto"
                    " failo (maksimalus ilgis yra ");
            main_write_size_t(params, params->filename_length);
            fprintf(params->out, "): ");
            main_read_text(params, private_key_filename,
                    params->filename_length);
            fprintf(params->out, "Suveskite kelią iki gavėjo viešojo rakto"
                    " failo (maksimalus ilgis yra ");
            main_write_size_t(params, params->filename_length);
            fprintf(params->out, "): ");
            main_read_text(params, public_key_filename,
                    params->filename_length);
            result = main_derive_key_dh(private_key_filename,
                    public_key_filename, key, key_length);
        }
        if(key_type.current_i == kt_password) {
            fprintf(params->out, "Suveskite užšifravimo slaptažodį (maksimalus"
                    " ilgis yra ");
            main_write_size_t(params, params->password_length);
            fprintf(params->out, "): ");
            main_read_text(params, password, params->password_length);
            fprintf(params->out, "Suvestas slaptažodis: %s\n", password);
            if(RAND_bytes(key_salt, (int)params->key_salt_length) != 1) {
                result = main_error(params, 1,
                        "main_encrypt: RAND_bytes (key_salt)");
            }
            if(result == EXIT_SUCCESS && PKCS5_PBKDF2_HMAC_SHA1(password,
                        (int)strlen(password), key_salt,
                        (int)params->key_salt_length,
                        (int)params->pbkdf2_iterations,
                        (int)key_length, key) != 1) {
                result = main_error(params, 1,
                        "main_encrypt: PKCS4_PBKDF2_HMAC_SHA1");
            }
        }
    }
    if(result == EXIT_SUCCESS) {

        fprintf(params->out, "Ačiū! Sistema pasiruošusi šifravimo operacijai"
                " su tokiais parametrais:\n");
        fprintf(params->out, "Tekstogramos failas: %s\n", plaintext_filename);
        fprintf(params->out, "Šifrogramos failas: %s\n", ciphertext_filename);
        fprintf(params->out, "Ar pradėti operaciją (taip/ne)? ");
        if(main_read_yesno(params, "taip", &confirm) != EXIT_SUCCESS) {
            result = main_error(params, 1, "main_encrypt: main_read_yesno");
        }
    }
    if(result == EXIT_SUCCESS && confirm) {
        fprintf(params->out, "Operacija vykdoma, prašome palaukti\n");

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
        if(result == EXIT_SUCCESS && RAND_bytes(iv,
                    (int)params->iv_length) != 1) {
            result = main_error(params, 1, "main_encrypt: RAND_bytes (iv)");
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
            result = main_error(params, 1,
                    "main_encrypt: EVP_EncryptInit_ex (mode)");
        }
        if(result == EXIT_SUCCESS && EVP_CIPHER_CTX_ctrl(ctx,
                    EVP_CTRL_GCM_SET_IVLEN, (int)params->iv_length,
                    NULL) != 1) {
            result = main_error(params, 1,
                    "main_encrypt: EVP_CIPHER_CTX_ctrl");
;
        }
        if(result == EXIT_SUCCESS && EVP_EncryptInit_ex(ctx,
                    NULL, NULL, key, iv) != 1) {
            result = main_error(params, 1,
                    "main_encrypt: EVP_EncryptInit_ex (key, iv)");
        }
        if(result == EXIT_SUCCESS && fwrite(key_salt, 1,
                    params->key_salt_length, ciphertext_file) <
                params->key_salt_length) {
            result = main_error(params, 1,
                    "main_encrypt: fwrite (key_salt)");
        }
        if(result == EXIT_SUCCESS && fwrite(iv, 1, params->iv_length,
                    ciphertext_file) < params->iv_length) {
            result = main_error(params, 1,
                    "main_encrypt: fwrite (iv)");
        }
        if(result == EXIT_SUCCESS && fgetpos(ciphertext_file, &tag_pos)) {
            result = main_error(params, 1,
                    "main_encrypt: fgetpos");
        }
        if(result == EXIT_SUCCESS && fwrite(tag, 1, params->tag_length,
                    ciphertext_file) < params->tag_length) {
            result = main_error(params, 1,
                    "main_encrypt: fwrite (spacing tag)");
        }
        if(result == EXIT_SUCCESS && main_encrypt_pipe(params, ctx,
                    plaintext_file, ciphertext_file) != EXIT_SUCCESS) {
            result = main_error(params, 1,
                    "main_encrypt: main_encrypt_pipe");
        }
        if(result == EXIT_SUCCESS && EVP_CIPHER_CTX_ctrl(ctx,
                    EVP_CTRL_GCM_GET_TAG,
                    (int)params->tag_length, tag) != 1) {
            result = main_error(params, 1,
                    "main_encrypt: EVP_CIPHER_CTX_ctrl");
        }
        if(result == EXIT_SUCCESS && fsetpos(ciphertext_file, &tag_pos)) {
            result = main_error(params, 1,
                    "main_encrypt: fsetpos");
        }
        if(result == EXIT_SUCCESS && fwrite(tag, 1, params->tag_length,
                    ciphertext_file) < params->tag_length) {
            result = main_error(params, 1,
                    "main_encrypt: fwrite (actual tag)");
        }
        if(result == EXIT_SUCCESS && params->debug) {
            fprintf(params->out, "Baigtas užšifravimas, TAG=");
            main_write_bytes_hex(params, tag, params->tag_length);
            fprintf(params->out, ".\n");
        }
    }
    if(ciphertext_file != NULL) {
        if(fclose(ciphertext_file) == EOF) {
            result = main_error(params, 1,
                    "main_encrypt: fclose (ciphertext_file)");
        }
    }
    if(plaintext_file != NULL) {
        if(fclose(plaintext_file) == EOF) {
            result = main_error(params, 1,
                    "main_encrypt: nepavyko uždaryti tekstogramos failo");
        }
    }
    OPENSSL_cleanse(&tag_pos, sizeof tag_pos);
    if(tag != NULL) {
        OPENSSL_cleanse(tag, params->tag_length);
        free(tag);
    }
    if(password != NULL) {
        OPENSSL_cleanse(password, params->password_length + 1);
        free(password);
    }
    if(key != NULL) {
        OPENSSL_cleanse(key, key_length);
        free(key);
    }
    if(private_key_filename != NULL) {
        OPENSSL_cleanse(private_key_filename, params->password_length + 1);
        free(private_key_filename);
    }
    if(public_key_filename != NULL) {
        OPENSSL_cleanse(public_key_filename, params->password_length + 1);
        free(public_key_filename);
    }
    if(iv != NULL) {
        OPENSSL_cleanse(iv, params->iv_length);
        free(iv);
    }
    if(key_salt != NULL) {
        OPENSSL_cleanse(key_salt, params->key_salt_length);
        free(key_salt);
    }
    EVP_CIPHER_CTX_free(ctx);

    if(result == EXIT_SUCCESS && confirm) {
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
    unsigned char *plaintext = malloc(params->pipe_buffer_size);
    unsigned char *ciphertext = malloc(params->pipe_buffer_size);

    if(plaintext == NULL || ciphertext == NULL) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS) {
        while(!feof(in)) {
            ciphertext_available = fread(ciphertext, 1, params->pipe_buffer_size,
                    in);
            fprintf(params->out, "Nuskaityta šifrogramos baitų: ");
            main_write_size_t(params, ciphertext_available);
            fprintf(params->out, "\n");
            if(ferror(in) ||
                    EVP_DecryptUpdate(ctx, plaintext, &plaintext_available,
                        ciphertext, (int)ciphertext_available) != 1 ||
                    fwrite(plaintext, 1, (size_t)plaintext_available, out)
                        < (size_t)plaintext_available) {
                result = EXIT_FAILURE;
                break;
            }
            fprintf(params->out, "Įrašyta tekstogramos baitų: %d\n",
                    plaintext_available);
        }
    }
    if(result == EXIT_SUCCESS && EVP_DecryptFinal_ex(ctx, plaintext,
                &plaintext_available) != 1) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS && fwrite(plaintext, 1,
                (size_t)plaintext_available, out) <
            (size_t)plaintext_available) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS) {
        fprintf(params->out, "Įrašyta paskutinių tekstogramos baitų: %d\n",
                plaintext_available);
    }

    if(ciphertext != NULL) {
        OPENSSL_cleanse(ciphertext, params->pipe_buffer_size);
        free(ciphertext);
    }
    if(plaintext != NULL) {
        OPENSSL_cleanse(plaintext, params->pipe_buffer_size);
        free(plaintext);
    }
    OPENSSL_cleanse(&ciphertext_available, sizeof ciphertext_available);
    OPENSSL_cleanse(&plaintext_available, sizeof plaintext_available);

    return result;
}

int main_read_key_type(main_params *params, main_enum *key_type) {
    int result = EXIT_SUCCESS;
    size_t i;

    while(1) {
        fprintf(params->out, "Suveskite rakto tipą - ");
        for(i = 0; i < key_type->len; i += 1) {
            if(i) {
                fprintf(params->out, " arba ");
            }
            if(fputs(key_type->all[i], params->out) == EOF) {
                result = main_error(params, 1, "main_read_key: fputs");
                break;
            }
        }
        if(result == EXIT_SUCCESS) {
            fprintf(params->out, ": ");
            result = main_read_enum(params, key_type);
            if(result != EXIT_SUCCESS) {
                main_error(params, 1, "main_read_key: main_read_enum");
            }
        }
        if(result != EXIT_SUCCESS) {
            break;
        }
        if(!key_type->current) {
            fprintf(params->out, "Neatpažintas rakto tipas. Bandykite iš"
                    " naujo\n");
            continue;
        }
        break;
    }

    return result;
}

int main_decrypt(main_params *params, const char *ciphertext_filename,
        const char *plaintext_filename) {
    int result = EXIT_SUCCESS;

    FILE *plaintext_file = NULL;
    FILE *ciphertext_file = NULL;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    unsigned char *tag = malloc(params->tag_length);
    unsigned char *iv = malloc(params->iv_length);
    unsigned char *key_salt = malloc(params->key_salt_length);
    size_t key_length = 32;
    unsigned char *key = malloc(key_length);
    char *password = malloc(params->password_length + 1);
    size_t kt_password = 0, kt_dh = 1;
    const char *key_types[] = {"password", "dh"};
    main_enum key_type;

    if(tag == NULL || iv == NULL || key_salt == NULL || key == NULL ||
            password == NULL) {
        result = EXIT_FAILURE;
    }

    if(result == EXIT_SUCCESS) {
        main_enum_init(&key_type, key_types, 2);
    }

    if(result == EXIT_SUCCESS) {
        ciphertext_file = fopen(ciphertext_filename, "rb");
        if(ciphertext_file == NULL) {
            result = main_error(params, 1,
                    "main_decrypt: nepavyko atidaryti šifrogramos failo");
        }
    }
    if(result == EXIT_SUCCESS) {
        plaintext_file = fopen(plaintext_filename, "wb");
        if(plaintext_file == NULL) {
            result = main_error(params, 1,
                    "main_decrypt: nepavyko atidaryti tekstogramos failo");
        }
    }
    if(result == EXIT_SUCCESS) {
        result = main_read_key_type(params, &key_type);
    }
    if(key_type.current_i == kt_password) {
        if(result == EXIT_SUCCESS) {
            fprintf(params->out, "Suveskite iššifravimo slaptažodį (maksimalus"
                    " ilgis yra ");
            main_write_size_t(params, params->password_length);
            fprintf(params->out, "): ");
            main_read_text(params, password, params->password_length);
        }
        if(result == EXIT_SUCCESS) {
            fread(key_salt, 1, params->key_salt_length, ciphertext_file);
            if(ferror(ciphertext_file)) {
                result = main_error(params, 1,
                        "main_decrypt: nepavyko nuskaityti salt duomenų");
            }
        }
        if(result == EXIT_SUCCESS && PKCS5_PBKDF2_HMAC_SHA1(password,
                    (int)strlen(password), key_salt,
                    (int)params->key_salt_length,
                    (int)params->pbkdf2_iterations,
                    (int)key_length, key) != 1) {
            result = main_error(params, 1,
                    "main_decrypt: PKCS5_PBKDF2_HMAC_SHA1");
        }
    }
    if(key_type.current_i == kt_dh) {
        if(result == EXIT_SUCCESS) {
            result = main_error(params, 1, "main_decrypt: funkcija dar"
                    " neįgyvendinta");
        }
    }
    if(result == EXIT_SUCCESS) {
        fread(iv, 1, params->iv_length, ciphertext_file);
        if(ferror(ciphertext_file)) {
            result = main_error(params, 1,
                    "main_decrypt: nepavyko nuskaityti inicializacijos"
                    " vektoriaus");
        }
    }
    if(result == EXIT_SUCCESS) {
        fread(tag, 1, params->tag_length, ciphertext_file);
        if(ferror(ciphertext_file)) {
            result = main_error(params, 1, "main_decrypt: fread (tag)");
        }
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
        result = main_error(params, 1,
                "main_decrypt: EVP_EncryptInit_ex (mode)");
    }
    if(result == EXIT_SUCCESS && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                (int)params->tag_length, tag) != 1) {
        result = main_error(params, 1,
                "main_decrypt: EVP_CIPHER_CTX_ctrl (TAG)");
    }
    if(result == EXIT_SUCCESS && EVP_CIPHER_CTX_ctrl(ctx,
                EVP_CTRL_GCM_SET_IVLEN, (int)params->iv_length, NULL) != 1) {
        result = main_error(params, 1,
                "main_decrypt: EVP_CIPHER_CTX_ctrl (IVLEN)");
    }
    if(result == EXIT_SUCCESS && EVP_DecryptInit_ex(ctx, NULL,
                NULL, key, iv) != 1) {
        result = main_error(params, 1,
                "main_decrypt: EVP_EncryptInit_ex (key, iv)");
    }
    if(result == EXIT_SUCCESS && main_decrypt_pipe(params, ctx,
                ciphertext_file, plaintext_file) != EXIT_SUCCESS) {
        result = main_error(params, 1, "main_decrypt: main_decrypt_pipe");
    }
    if(ciphertext_file != NULL) {
        if(fclose(ciphertext_file) == EOF) {
            result = main_error(params, 1,
                    "main_decrypt: fclose (ciphertext_file)");
        }
    }
    if(plaintext_file != NULL) {
        if(fclose(plaintext_file) == EOF) {
            result = main_error(params, 1, "main_decrypt: fclose"
                    " (plaintext_file)");
        }
    }
    if(tag != NULL) {
        OPENSSL_cleanse(tag, params->tag_length);
        free(tag);
    }
    if(password != NULL) {
        OPENSSL_cleanse(password, params->password_length + 1);
        free(password);
    }
    if(key != NULL) {
        OPENSSL_cleanse(key, key_length);
        free(key);
    }
    if(iv != NULL) {
        OPENSSL_cleanse(iv, params->iv_length);
        free(iv);
    }
    if(key_salt != NULL) {
        OPENSSL_cleanse(key_salt, params->key_salt_length);
        free(key_salt);
    }
    OPENSSL_cleanse(&key_type, sizeof key_type);
    EVP_CIPHER_CTX_free(ctx);

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

