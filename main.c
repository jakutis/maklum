#include "main.h"

int main(int argc, char **argv) {
    int result = EXIT_SUCCESS;
    int i = 0;
    size_t size_t_bytes = sizeof (size_t);
    main_params params;
    /* These two arrays are taken as recommended for AES-256 from RFC 3526,
     * 8192-bit MODP Group. */
    unsigned char p[] = {
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D,
0x04, 0x50, 0x7A, 0x33, 0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57,
0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0,
0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 0xD8, 0x76, 0x02, 0x73,
0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0,
0xBA, 0xD9, 0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20,
0xA9, 0x21, 0x08, 0x01, 0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7,
0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26, 0x99, 0xC3, 0x27, 0x18,
0x6A, 0xF4, 0xE2, 0x3C, 0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA,
0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8, 0xDB, 0xBB, 0xC2, 0xDB,
0x04, 0xDE, 0x8E, 0xF9, 0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6,
0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D, 0x99, 0xB2, 0x96, 0x4F,
0xA0, 0x90, 0xC3, 0xA2, 0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED,
0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF, 0xB8, 0x1B, 0xDD, 0x76,
0x21, 0x70, 0x48, 0x1C, 0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1, 0x86, 0xFF, 0xB7, 0xDC,
0x90, 0xA6, 0xC0, 0x8F, 0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x02, 0x84, 0x92,
0x36, 0xC3, 0xFA, 0xB4, 0xD2, 0x7C, 0x70, 0x26, 0xC1, 0xD4, 0xDC, 0xB2,
0x60, 0x26, 0x46, 0xDE, 0xC9, 0x75, 0x1E, 0x76, 0x3D, 0xBA, 0x37, 0xBD,
0xF8, 0xFF, 0x94, 0x06, 0xAD, 0x9E, 0x53, 0x0E, 0xE5, 0xDB, 0x38, 0x2F,
0x41, 0x30, 0x01, 0xAE, 0xB0, 0x6A, 0x53, 0xED, 0x90, 0x27, 0xD8, 0x31,
0x17, 0x97, 0x27, 0xB0, 0x86, 0x5A, 0x89, 0x18, 0xDA, 0x3E, 0xDB, 0xEB,
0xCF, 0x9B, 0x14, 0xED, 0x44, 0xCE, 0x6C, 0xBA, 0xCE, 0xD4, 0xBB, 0x1B,
0xDB, 0x7F, 0x14, 0x47, 0xE6, 0xCC, 0x25, 0x4B, 0x33, 0x20, 0x51, 0x51,
0x2B, 0xD7, 0xAF, 0x42, 0x6F, 0xB8, 0xF4, 0x01, 0x37, 0x8C, 0xD2, 0xBF,
0x59, 0x83, 0xCA, 0x01, 0xC6, 0x4B, 0x92, 0xEC, 0xF0, 0x32, 0xEA, 0x15,
0xD1, 0x72, 0x1D, 0x03, 0xF4, 0x82, 0xD7, 0xCE, 0x6E, 0x74, 0xFE, 0xF6,
0xD5, 0x5E, 0x70, 0x2F, 0x46, 0x98, 0x0C, 0x82, 0xB5, 0xA8, 0x40, 0x31,
0x90, 0x0B, 0x1C, 0x9E, 0x59, 0xE7, 0xC9, 0x7F, 0xBE, 0xC7, 0xE8, 0xF3,
0x23, 0xA9, 0x7A, 0x7E, 0x36, 0xCC, 0x88, 0xBE, 0x0F, 0x1D, 0x45, 0xB7,
0xFF, 0x58, 0x5A, 0xC5, 0x4B, 0xD4, 0x07, 0xB2, 0x2B, 0x41, 0x54, 0xAA,
0xCC, 0x8F, 0x6D, 0x7E, 0xBF, 0x48, 0xE1, 0xD8, 0x14, 0xCC, 0x5E, 0xD2,
0x0F, 0x80, 0x37, 0xE0, 0xA7, 0x97, 0x15, 0xEE, 0xF2, 0x9B, 0xE3, 0x28,
0x06, 0xA1, 0xD5, 0x8B, 0xB7, 0xC5, 0xDA, 0x76, 0xF5, 0x50, 0xAA, 0x3D,
0x8A, 0x1F, 0xBF, 0xF0, 0xEB, 0x19, 0xCC, 0xB1, 0xA3, 0x13, 0xD5, 0x5C,
0xDA, 0x56, 0xC9, 0xEC, 0x2E, 0xF2, 0x96, 0x32, 0x38, 0x7F, 0xE8, 0xD7,
0x6E, 0x3C, 0x04, 0x68, 0x04, 0x3E, 0x8F, 0x66, 0x3F, 0x48, 0x60, 0xEE,
0x12, 0xBF, 0x2D, 0x5B, 0x0B, 0x74, 0x74, 0xD6, 0xE6, 0x94, 0xF9, 0x1E,
0x6D, 0xBE, 0x11, 0x59, 0x74, 0xA3, 0x92, 0x6F, 0x12, 0xFE, 0xE5, 0xE4,
0x38, 0x77, 0x7C, 0xB6, 0xA9, 0x32, 0xDF, 0x8C, 0xD8, 0xBE, 0xC4, 0xD0,
0x73, 0xB9, 0x31, 0xBA, 0x3B, 0xC8, 0x32, 0xB6, 0x8D, 0x9D, 0xD3, 0x00,
0x74, 0x1F, 0xA7, 0xBF, 0x8A, 0xFC, 0x47, 0xED, 0x25, 0x76, 0xF6, 0x93,
0x6B, 0xA4, 0x24, 0x66, 0x3A, 0xAB, 0x63, 0x9C, 0x5A, 0xE4, 0xF5, 0x68,
0x34, 0x23, 0xB4, 0x74, 0x2B, 0xF1, 0xC9, 0x78, 0x23, 0x8F, 0x16, 0xCB,
0xE3, 0x9D, 0x65, 0x2D, 0xE3, 0xFD, 0xB8, 0xBE, 0xFC, 0x84, 0x8A, 0xD9,
0x22, 0x22, 0x2E, 0x04, 0xA4, 0x03, 0x7C, 0x07, 0x13, 0xEB, 0x57, 0xA8,
0x1A, 0x23, 0xF0, 0xC7, 0x34, 0x73, 0xFC, 0x64, 0x6C, 0xEA, 0x30, 0x6B,
0x4B, 0xCB, 0xC8, 0x86, 0x2F, 0x83, 0x85, 0xDD, 0xFA, 0x9D, 0x4B, 0x7F,
0xA2, 0xC0, 0x87, 0xE8, 0x79, 0x68, 0x33, 0x03, 0xED, 0x5B, 0xDD, 0x3A,
0x06, 0x2B, 0x3C, 0xF5, 0xB3, 0xA2, 0x78, 0xA6, 0x6D, 0x2A, 0x13, 0xF8,
0x3F, 0x44, 0xF8, 0x2D, 0xDF, 0x31, 0x0E, 0xE0, 0x74, 0xAB, 0x6A, 0x36,
0x45, 0x97, 0xE8, 0x99, 0xA0, 0x25, 0x5D, 0xC1, 0x64, 0xF3, 0x1C, 0xC5,
0x08, 0x46, 0x85, 0x1D, 0xF9, 0xAB, 0x48, 0x19, 0x5D, 0xED, 0x7E, 0xA1,
0xB1, 0xD5, 0x10, 0xBD, 0x7E, 0xE7, 0x4D, 0x73, 0xFA, 0xF3, 0x6B, 0xC3,
0x1E, 0xCF, 0xA2, 0x68, 0x35, 0x90, 0x46, 0xF4, 0xEB, 0x87, 0x9F, 0x92,
0x40, 0x09, 0x43, 0x8B, 0x48, 0x1C, 0x6C, 0xD7, 0x88, 0x9A, 0x00, 0x2E,
0xD5, 0xEE, 0x38, 0x2B, 0xC9, 0x19, 0x0D, 0xA6, 0xFC, 0x02, 0x6E, 0x47,
0x95, 0x58, 0xE4, 0x47, 0x56, 0x77, 0xE9, 0xAA, 0x9E, 0x30, 0x50, 0xE2,
0x76, 0x56, 0x94, 0xDF, 0xC8, 0x1F, 0x56, 0xE8, 0x80, 0xB9, 0x6E, 0x71,
0x60, 0xC9, 0x80, 0xDD, 0x98, 0xED, 0xD3, 0xDF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF
    };
    unsigned char g[] = {2};
    size_t size_max_digits_digits = 0;
    const char *size_t_format_format = NULL;
    size_t key_types_length = 4;

    params.debug = 0;
    params.filename_length = 255;
    params.tag_length = 16;
    params.in = stdin;
    params.out = stdout;
    params.rsa_key_length_bits = 4096;
    params.password_length = 50;
    params.pbkdf2_iterations = 16384;
    params.pipe_buffer_length = 100000;
    params.iv_length = 16;
    params.key_salt_length = 32;
    params.size_t_format = NULL;
    params.dh_prime_length = 256;
    params.dh_generator_length = 256;
    params.dh_generator = g;
    params.dh_prime = p;
    params.key_type_password = 0;
    params.key_type_dh = 1;
    params.key_type_rsa = 2;
    if(result == EXIT_SUCCESS &&
            (params.key_types = malloc(key_types_length * sizeof(char*)))
            == NULL) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS) {
        params.key_types[params.key_type_password] = "password";
        params.key_types[params.key_type_dh] = "dh";
        params.key_types[params.key_type_rsa] = "rsa";
        params.key_types[key_types_length - 1] = NULL;
        main_digits((size_t) - 1, &params.size_max_digits);
        main_digits(params.size_max_digits, &size_max_digits_digits);
        if((params.size_t_format = malloc(1 + size_max_digits_digits + 2 + 1))
                == NULL) {
            result = EXIT_FAILURE;
        }
    }
    if(result == EXIT_SUCCESS) {
        if(sizeof (short int) == size_t_bytes) {
            size_t_format_format = "%%%huhu";
            params.size_t_format_flex = "%hu";
        } else if(sizeof (int) == size_t_bytes) {
            size_t_format_format = "%%%uu";
            params.size_t_format_flex = "%u";
        } else if(sizeof (long int) == size_t_bytes) {
            size_t_format_format = "%%%lulu";
            params.size_t_format_flex = "%lu";
        } else {
            result = EXIT_FAILURE;
        }
    }
    if(result == EXIT_SUCCESS) {
        sprintf(params.size_t_format, size_t_format_format,
                params.size_max_digits);
        if(argc < 2) {
            result = main_error(&params, 0,
                    "main: nepateiktas operacijos pavadinimas");
        } else if(strcmp(argv[1], "uzsifruoti") == 0) {
            if(argc == 2) {
                result = main_error(&params, 0,
                        "main: nepateiktas tekstogramos failo vardas");
            } else if(argc == 3) {
                result = main_error(&params, 0,
                        "main: nepateiktas šifrogramos failo vardas");
            } else {
                result = main_encrypt(&params, argv[2], argv[3]);
            }
        } else if(strcmp(argv[1], "issifruoti") == 0) {
            if(argc == 2) {
                result = main_error(&params, 0,
                        "main: nepateiktas šifrogramos failo vardas");
            } else if(argc == 3) {
                result = main_error(&params, 0,
                        "main: nepateiktas tekstogramos failo vardas");
            } else {
                result = main_decrypt(&params, argv[2], argv[3]);
            }
        } else if(strcmp(argv[1], "sukurtiraktus") == 0) {
            result = main_generate_keys(&params);
        } else {
            result = main_error(&params, 0, "main: neatpažintas operacijos"
                    " pavadinimas (turi būti vienas iš: \"uzsifruoti\","
                    " \"issifruoti\", \"sukurtiraktus\")");
        }
    }

    for(i = 0; i < argc; i += 1) {
        OPENSSL_cleanse(argv[i], strlen(argv[i]) + 1);
    }
    if(params.size_t_format != NULL) {
        OPENSSL_cleanse(params.size_t_format,
                1 + size_max_digits_digits + 2 + 1);
        free(params.size_t_format);
    }
    OPENSSL_cleanse(&i, sizeof i);
    OPENSSL_cleanse(&size_t_format_format, sizeof size_t_format_format);
    OPENSSL_cleanse(&size_max_digits_digits, sizeof size_max_digits_digits);
    OPENSSL_cleanse(argv, (size_t)(argc) * sizeof argv);
    OPENSSL_cleanse(&argv, sizeof argv);
    OPENSSL_cleanse(&argc, sizeof argc);
    OPENSSL_cleanse(&g, sizeof g);
    OPENSSL_cleanse(&p, sizeof p);
    OPENSSL_cleanse(&size_t_bytes, sizeof size_t_bytes);
    OPENSSL_cleanse(&key_types_length, sizeof key_types_length);
    free(params.key_types);
    OPENSSL_cleanse(&params, sizeof params);
    return result;
}

int main_read_filename(main_params *params, const char *message,
        char *filename) {
    int result = EXIT_SUCCESS;

    fprintf(params->out, "%s (maksimalus ilgis yra ", message);
    fprintf(params->out, params->size_t_format_flex, params->filename_length);
    fprintf(params->out, "): ");
    main_read_text(params, filename, params->filename_length);

    OPENSSL_cleanse(&params, sizeof params);
    OPENSSL_cleanse(&message, sizeof message);
    OPENSSL_cleanse(&filename, sizeof filename);
    return result;
}

int main_write_key(main_params *params, const char *filename,
        EVP_PKEY *key, int private) {
    int result = EXIT_SUCCESS;
    BIO *bio = NULL;

    if(result == EXIT_SUCCESS && (bio = BIO_new_file(filename, "wb")) == NULL) {
        result = main_error(params, 1,
                "main_write_key: BIO_new_file");
    }
    if(result == EXIT_SUCCESS && (
                private ?
                PEM_write_bio_PKCS8PrivateKey(bio, key, NULL, NULL, 0, NULL,
                    NULL) :
                PEM_write_bio_PUBKEY(bio, key)
                ) != 1) {
        result = main_error(params, 1,
                "main_write_key: PEM_write_bio_...");
    }

    OPENSSL_cleanse(&params, sizeof params);
    OPENSSL_cleanse(&filename, sizeof filename);
    OPENSSL_cleanse(&key, sizeof key);
    OPENSSL_cleanse(&private, sizeof private);
    BIO_free_all(bio);
    OPENSSL_cleanse(&bio, sizeof bio);
    return result;
}

int main_generate_keys(main_params *params) {
    int result = EXIT_SUCCESS;
    char *private_key_filename = NULL, *public_key_filename = NULL;
    EVP_PKEY *dh_params = NULL;
    EVP_PKEY *key = NULL;
    main_enum key_type;

    if(result == EXIT_SUCCESS) {
        main_enum_init(&key_type, params->key_types);
    }
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
    if(result == EXIT_SUCCESS) {
        result = main_read_key_type(params, &key_type);
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
        fprintf(params->out, "type = %s, public = %s, private = %s\n",
                key_type.current, public_key_filename, private_key_filename);
    }
    if(key_type.current_i == params->key_type_dh) {
        if(result == EXIT_SUCCESS &&
                main_fill_dh_params(params, &dh_params) != EXIT_SUCCESS) {
            result = main_error(params, 1,
                    "main_generate_keys: main_fill_dh_params");
        }

        if(result == EXIT_SUCCESS && params->debug) {
            fprintf(params->out, "main_generate_keys: DH params read.\n");
        }

        if(result == EXIT_SUCCESS &&
                main_generate_dh_key(params, dh_params, &key) != EXIT_SUCCESS) {
            result = main_error(params, 1,
                    "main_generate_keys: main_generate_dh_key");
        }
    } else if(key_type.current_i == params->key_type_rsa) {
        if(result == EXIT_SUCCESS && main_generate_rsa_key(params,
                    params->rsa_key_length_bits, &key) != EXIT_SUCCESS) {
            result = main_error(params, 1,
                    "main_generate_keys: main_generate_rsa_key");
        }
    } else {
        result = main_error(params, 0,
                "\"password\" raktų tipas nereikalauja raktų failų");
    }
    if(result == EXIT_SUCCESS && main_write_key(params,
                private_key_filename, key, 1) != EXIT_SUCCESS) {
        result = main_error(params, 1,
                "main_generate_keys: main_write_key (private)");
    }
    if(result == EXIT_SUCCESS && params->debug) {
        fprintf(params->out, "private key written.\n");
    }
    if(result == EXIT_SUCCESS && main_write_key(params,
                public_key_filename, key, 0) != EXIT_SUCCESS) {
        result = main_error(params, 1,
                "main_generate_keys: main_write_key (public)");
    }
    if(result == EXIT_SUCCESS && params->debug) {
        fprintf(params->out, "public key written.\n");
    }

    if(private_key_filename != NULL) {
        OPENSSL_cleanse(private_key_filename, params->filename_length + 1);
        free(private_key_filename);
    }
    OPENSSL_cleanse(&private_key_filename, sizeof private_key_filename);
    if(public_key_filename != NULL) {
        OPENSSL_cleanse(public_key_filename, params->filename_length + 1);
        free(public_key_filename);
    }
    OPENSSL_cleanse(&public_key_filename, sizeof public_key_filename);
    OPENSSL_cleanse(&params, sizeof params);
    OPENSSL_cleanse(&key_type, sizeof key_type);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(&key, sizeof key);
    EVP_PKEY_free(dh_params);
    OPENSSL_cleanse(&dh_params, sizeof dh_params);
    return result;
}

void main_enum_init(main_enum *a, const char **all) {
    size_t i;

    a->all = all;
    a->len = 0;
    a->max = 0;
    for(i = 0; all[i] != NULL; i += 1) {
        a->max = main_max(strlen(all[i]), a->max);
        a->len += 1;
    }
    a->current = NULL;
    a->current_i = 0;

    OPENSSL_cleanse(&a, sizeof a);
    OPENSSL_cleanse(&all, sizeof all);
    OPENSSL_cleanse(&i, sizeof i);
}

int main_generate_dh_key(main_params *params, EVP_PKEY *dh_params,
        EVP_PKEY **key) {
    int result = EXIT_SUCCESS;
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
    if(result == EXIT_SUCCESS && EVP_PKEY_keygen(ctx, key) != 1) {
        result = main_error(params, 1,
                "main_generate_dh_key: EVP_PKEY_keygen");
    }
    if(result == EXIT_SUCCESS && params->debug) {
        fprintf(params->out, "main_generate_dh_key: keygen finished.\n");
    }

    EVP_PKEY_CTX_free(ctx);
    OPENSSL_cleanse(&ctx, sizeof ctx);
    OPENSSL_cleanse(&params, sizeof params);
    OPENSSL_cleanse(&dh_params, sizeof dh_params);
    OPENSSL_cleanse(&key, sizeof key);
    return result;
}

int main_generate_rsa_key(main_params *params, size_t key_length_bits,
        EVP_PKEY **key) {
    int result = EXIT_SUCCESS;
    EVP_PKEY_CTX *ctx = NULL;

    if(result == EXIT_SUCCESS && params->debug) {
        fprintf(params->out, "main_generate_rsa_key: entry.\n");
    }
    if(result == EXIT_SUCCESS &&
            (ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) == NULL) {
        result = main_error(params, 1,
                "main_generate_rsa_key: EVP_PKEY_CTX_new_id");
    }
    if(result == EXIT_SUCCESS && params->debug) {
        fprintf(params->out, "main_generate_rsa_key: context created.\n");
    }
    if(result == EXIT_SUCCESS && EVP_PKEY_keygen_init(ctx) != 1) {
        result = main_error(params, 1,
                "main_generate_rsa_key: EVP_PKEY_keygen_init");
    }
    if(result == EXIT_SUCCESS && params->debug) {
        fprintf(params->out, "main_generate_rsa_key: keygen initialized.\n");
    }
    if(result == EXIT_SUCCESS &&
            EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int)key_length_bits) != 1) {
        result = main_error(params, 1,
                "main_generate_rsa_key: EVP_PKEY_CTX_set_rsa_keygen_bits");
    }
    if(result == EXIT_SUCCESS && EVP_PKEY_keygen(ctx, key) != 1) {
        result = main_error(params, 1,
                "main_generate_rsa_key: EVP_PKEY_keygen");
    }
    if(result == EXIT_SUCCESS && params->debug) {
        fprintf(params->out, "main_generate_rsa_key: keygen finished.\n");
    }

    EVP_PKEY_CTX_free(ctx);
    OPENSSL_cleanse(&ctx, sizeof ctx);
    OPENSSL_cleanse(&params, sizeof params);
    OPENSSL_cleanse(&key, sizeof key);
    OPENSSL_cleanse(&key_length_bits, sizeof key_length_bits);
    return result;
}


int main_fill_dh_params(main_params *params, EVP_PKEY **dh_params) {
    int result = EXIT_SUCCESS;
    DH *dh = NULL;
    int check = 0;

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
    if(result == EXIT_SUCCESS &&
            (DH_check(dh, &check) != 1)) {
        /*
         * OpenSSL views parameters with p==23 mod 24 (IETF style) as insecure.
         * But they are equally secure, because
         * http://crypto.stackexchange.com/a/12972
         * See also http://wiki.openssl.org/index.php/Diffie-Hellman_parameters
         */
        if(check & DH_NOT_SUITABLE_GENERATOR &&
                BN_is_word(dh->g, DH_GENERATOR_2) &&
                BN_mod_word(dh->p, 24) == 23) {
            check &= ~DH_NOT_SUITABLE_GENERATOR;
        }
        if(check) {
            result = main_error(params, 1, "main_fill_dh_params: DH_check");
        }
    }
    if(result == EXIT_SUCCESS && (*dh_params = EVP_PKEY_new()) == NULL) {
        result = main_error(params, 1, "main_fill_dh_params: EVP_PKEY_new");
    }
		if(result == EXIT_SUCCESS && EVP_PKEY_set1_DH(*dh_params, dh) != 1) {
        result = main_error(params, 1,
                "main_fill_dh_params: EVP_PKEY_set1_DH");
    }

    DH_free(dh);
    OPENSSL_cleanse(&dh, sizeof dh);
    OPENSSL_cleanse(&params, sizeof params);
    OPENSSL_cleanse(&dh_params, sizeof dh_params);
    OPENSSL_cleanse(&check, sizeof check);
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

    OPENSSL_cleanse(&params, sizeof params);
    OPENSSL_cleanse(&text, sizeof text);
    OPENSSL_cleanse(&text_length, sizeof text_length);
    OPENSSL_cleanse(&i, sizeof i);
    OPENSSL_cleanse(&c, sizeof c);
    return result;
}

int main_read_yesno(main_params *params, const char *positive_response,
        unsigned char *yesno) {
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
    OPENSSL_cleanse(&response, sizeof response);
    OPENSSL_cleanse(&n, sizeof n);
    OPENSSL_cleanse(&params, sizeof params);
    OPENSSL_cleanse(&positive_response, sizeof positive_response);
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
    OPENSSL_cleanse(&response, sizeof response);
    OPENSSL_cleanse(&i, sizeof i);
    OPENSSL_cleanse(&a, sizeof a);
    OPENSSL_cleanse(&params, sizeof params);
    return result;
}

int main_error(main_params *params, int type, const char *message) {
    fprintf(params->out, "%s klaida: %s.\n", type ? "Sisteminė" : "Vartotojo",
            message);

    OPENSSL_cleanse(&params, sizeof params);
    OPENSSL_cleanse(&type, sizeof type);
    OPENSSL_cleanse(&message, sizeof message);
    return EXIT_FAILURE;
}

int main_string_to_integer(main_params *params, char *string, size_t *integer) {
    int result = EXIT_SUCCESS;

    if(sscanf(string, params->size_t_format_flex, integer) != 1) {
        result = EXIT_FAILURE;
    }

    OPENSSL_cleanse(&params, sizeof params);
    OPENSSL_cleanse(&string, sizeof string);
    OPENSSL_cleanse(&integer, sizeof integer);
    return result;
}

int main_read_integer(main_params *params, size_t *integer) {
    int result = EXIT_SUCCESS;
    char *string = NULL;

    if(result == EXIT_SUCCESS &&
            (string = malloc(params->size_max_digits + 1)) == NULL) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS &&
            main_read_text(params, string,
                params->size_max_digits) != EXIT_SUCCESS) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS &&
            main_string_to_integer(params, string, integer) != EXIT_SUCCESS) {
        result = EXIT_FAILURE;
    }

    if(string != NULL) {
        OPENSSL_cleanse(string, params->size_max_digits + 1);
        free(string);
    }
    OPENSSL_cleanse(&string, sizeof string);
    OPENSSL_cleanse(&params->size_max_digits, sizeof params->size_max_digits);
    OPENSSL_cleanse(&params, sizeof params);
    OPENSSL_cleanse(&integer, sizeof integer);
    return result;
}

int main_aes(const unsigned char *in, unsigned char *out,
        const unsigned char *key) {
    int result = EXIT_SUCCESS;
    AES_KEY aes_key;

    if(AES_set_encrypt_key(key, 256, &aes_key) != 0) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS) {
        AES_encrypt(in, out, &aes_key);
    }

    OPENSSL_cleanse(&aes_key, sizeof aes_key);
    OPENSSL_cleanse(&in, sizeof in);
    OPENSSL_cleanse(&out, sizeof out);
    OPENSSL_cleanse(&key, sizeof key);
    return result;
}

void main_digits(size_t n, size_t *d) {
    for(*d = 1; n > 9; *d += 1) {
        n /= 10;
    }

    OPENSSL_cleanse(&d, sizeof d);
    OPENSSL_cleanse(&n, sizeof n);
}

int main_read_size_t_bin_buffer(unsigned char *in, size_t *size,
        size_t max_bytes, size_t *bytes_read) {
    int result = EXIT_SUCCESS;
    size_t buffer_length = 0;

    if(result == EXIT_SUCCESS) {
        memcpy(&buffer_length, in, 1);
    }
    if(result == EXIT_SUCCESS && (
                buffer_length > sizeof *size ||
                buffer_length + 1 > max_bytes
                )) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS) {
        memcpy(size, in + 1, buffer_length);
        *bytes_read = 1 + buffer_length;
    }

    OPENSSL_cleanse(&in, sizeof in);
    OPENSSL_cleanse(&size, sizeof size);
    OPENSSL_cleanse(&buffer_length, sizeof buffer_length);
    OPENSSL_cleanse(&max_bytes, sizeof max_bytes);
    OPENSSL_cleanse(&bytes_read, sizeof bytes_read);
    return result;
}

int main_write_size_t_bin_buffer(unsigned char *out, size_t size,
        size_t *length) {
    int result = EXIT_SUCCESS;
    size_t buffer_length = main_size_t_bytes(size);

    if(result == EXIT_SUCCESS && buffer_length > UCHAR_MAX) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS) {
        if(out != NULL) {
            memcpy(out, &buffer_length, 1);
            memcpy(out + 1, &size, buffer_length);
        }
        *length = 1 + buffer_length;
    }

    OPENSSL_cleanse(&out, sizeof out);
    OPENSSL_cleanse(&size, sizeof size);
    OPENSSL_cleanse(&length, sizeof length);
    OPENSSL_cleanse(&buffer_length, sizeof buffer_length);
    return result;
}

int main_write_size_t_bin(FILE *out, size_t size) {
    int result = EXIT_SUCCESS;
    size_t buffer_length = main_size_t_bytes(size);

    if(result == EXIT_SUCCESS && buffer_length > UCHAR_MAX) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS && fwrite(&buffer_length, 1, 1, out) < 1) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS &&
            fwrite(&size, 1, buffer_length, out) < buffer_length) {
        result = EXIT_FAILURE;
    }

    OPENSSL_cleanse(&out, sizeof out);
    OPENSSL_cleanse(&size, sizeof size);
    OPENSSL_cleanse(&buffer_length, sizeof buffer_length);
    return result;
}

int main_read_size_t_bin(FILE *in, size_t *size) {
    int result = EXIT_SUCCESS;
    size_t buffer_length = 0;

    if(result == EXIT_SUCCESS && fread(&buffer_length, 1, 1, in) < 1) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS && buffer_length > sizeof *size) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS &&
            fread(size, 1, buffer_length, in) < buffer_length) {
        result = EXIT_FAILURE;
    }

    OPENSSL_cleanse(&in, sizeof in);
    OPENSSL_cleanse(&size, sizeof size);
    OPENSSL_cleanse(&buffer_length, sizeof buffer_length);
    return result;
}

int main_write_char(FILE *f, char c, size_t n) {
    int result = EXIT_SUCCESS;
    char *str = malloc(n + 1);
    size_t i;

    if(result == EXIT_SUCCESS && str == NULL) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS) {
        memset(str, c, n);
        str[n] = 0;
        if(fprintf(f, "%s", str) < (int)n) {
            result = EXIT_FAILURE;
        }
    }

    if(str != NULL) {
        OPENSSL_cleanse(str, n + 1);
        free(str);
    }
    OPENSSL_cleanse(&str, sizeof str);
    OPENSSL_cleanse(&i, sizeof i);
    OPENSSL_cleanse(&f, sizeof f);
    OPENSSL_cleanse(&c, sizeof c);
    OPENSSL_cleanse(&n, sizeof n);
    return result;
}

int main_encrypt_pipe(main_params *params, EVP_CIPHER_CTX *ctx, FILE *in,
        FILE *out, const char *key_filename) {
    int result = EXIT_SUCCESS;
    size_t metadata_available = 0;
    size_t plaintext_available = 0;
    int ciphertext_available = 0;
    size_t ciphertext_total = 0;
    unsigned char *metadata = malloc(1 + sizeof(size_t));
    unsigned char *plaintext = malloc(params->pipe_buffer_length);
    unsigned char *ciphertext = malloc(params->pipe_buffer_length);
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char *signature = NULL;
    size_t signature_length = 0;
    clock_t last_progress_clock = clock();
    clock_t current_clock = 0;
    size_t clocks_per_progress = CLOCKS_PER_SEC / 25;

    if(result == EXIT_SUCCESS) {
        fprintf(params->out, "Įrašyta šifrogramos baitų: ");
        fprintf(params->out, params->size_t_format, ciphertext_total);
    }
    if(key_filename != NULL) {
        if(result == EXIT_SUCCESS && (mdctx = EVP_MD_CTX_create()) == NULL) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS &&
                main_read_pkey(key_filename, &key, 1) != EXIT_SUCCESS) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS &&
                EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key) != 1) {
            result = EXIT_FAILURE;
        }
    }
    if(result == EXIT_SUCCESS && (plaintext == NULL || ciphertext == NULL)) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS && (
        main_write_size_t_bin_buffer(metadata, params->pipe_buffer_length,
            &metadata_available) != EXIT_SUCCESS ||
        EVP_EncryptUpdate(ctx, ciphertext,
            &ciphertext_available, metadata,
            (int)metadata_available) != 1 ||
        fwrite(ciphertext, 1, (size_t)ciphertext_available, out) <
            (size_t)ciphertext_available)) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS) {
        ciphertext_total += (size_t)ciphertext_available;
        main_write_char(params->out, '\b', params->size_max_digits);
        fprintf(params->out, params->size_t_format, ciphertext_total);
    }
    if(result == EXIT_SUCCESS) {
        while(!feof(in)) {
            plaintext_available = fread(plaintext, 1,
                    params->pipe_buffer_length, in);
            if(ferror(in)) {
                result = EXIT_FAILURE;
                break;
            }
            if(key_filename != NULL &&
                    EVP_DigestSignUpdate(mdctx, plaintext, plaintext_available)
                    != 1) {
                result = EXIT_FAILURE;
                break;
            }
            if(main_write_size_t_bin_buffer(metadata,
                    /* fread returns less than nmemb only on ferror or feof */
                    plaintext_available < params->pipe_buffer_length ?
                    plaintext_available : 0,
                    &metadata_available) != EXIT_SUCCESS ||
                EVP_EncryptUpdate(ctx, ciphertext,
                    &ciphertext_available, metadata,
                    (int)metadata_available) != 1 ||
                fwrite(ciphertext, 1, (size_t)ciphertext_available, out) <
                    (size_t)ciphertext_available) {
                result = EXIT_FAILURE;
                break;
            }
            ciphertext_total += (size_t)ciphertext_available;
            if(EVP_EncryptUpdate(ctx, ciphertext,
                    &ciphertext_available, plaintext,
                    (int)plaintext_available) != 1 ||
                fwrite(ciphertext, 1, (size_t)ciphertext_available, out) <
                    (size_t)ciphertext_available) {
                result = EXIT_FAILURE;
                break;
            }
            ciphertext_total += (size_t)ciphertext_available;
            current_clock = clock();
            if((size_t)(current_clock - last_progress_clock) >
                    clocks_per_progress) {
                last_progress_clock = current_clock;
                main_write_char(params->out, '\b', params->size_max_digits);
                fprintf(params->out, params->size_t_format, ciphertext_total);
            }
        }
    }
    if(key_filename != NULL) {
        if(result == EXIT_SUCCESS &&
                EVP_DigestSignFinal(mdctx, NULL, &signature_length) != 1) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS &&
                (signature = malloc(signature_length)) == NULL) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS && (
                EVP_DigestSignFinal(mdctx, signature, &signature_length) != 1 ||
                EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_available,
                    signature, (int)signature_length) != 1 ||
                fwrite(ciphertext, 1, (size_t)ciphertext_available, out) <
                    (size_t)ciphertext_available)) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS) {
            ciphertext_total += (size_t)ciphertext_available;
            main_write_char(params->out, '\b', params->size_max_digits);
            fprintf(params->out, params->size_t_format, ciphertext_total);
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
        ciphertext_total += (size_t)ciphertext_available;
        main_write_char(params->out, '\b', params->size_max_digits);
        fprintf(params->out, params->size_t_format, ciphertext_total);
        fprintf(params->out, "\n");
    }

    if(plaintext != NULL) {
        OPENSSL_cleanse(plaintext, params->pipe_buffer_length);
        free(plaintext);
    }
    OPENSSL_cleanse(&plaintext, sizeof plaintext);
    if(ciphertext != NULL) {
        OPENSSL_cleanse(ciphertext, params->pipe_buffer_length);
        free(ciphertext);
    }
    OPENSSL_cleanse(&ciphertext, sizeof ciphertext);
    if(metadata != NULL) {
        OPENSSL_cleanse(metadata, 1 + sizeof metadata_available);
        free(metadata);
    }
    EVP_PKEY_free(key);
    OPENSSL_cleanse(&key, sizeof key);
    if(mdctx != NULL) {
        EVP_MD_CTX_destroy(mdctx);
    }
    OPENSSL_cleanse(&mdctx, sizeof mdctx);
    if(signature != NULL) {
        OPENSSL_cleanse(signature, signature_length);
        free(signature);
    }
    OPENSSL_cleanse(&last_progress_clock, sizeof last_progress_clock);
    OPENSSL_cleanse(&current_clock, sizeof current_clock);
    OPENSSL_cleanse(&clocks_per_progress, sizeof clocks_per_progress);
    OPENSSL_cleanse(&signature, sizeof signature);
    OPENSSL_cleanse(&signature_length, sizeof signature_length);
    OPENSSL_cleanse(&key_filename, sizeof key_filename);
    OPENSSL_cleanse(&metadata, sizeof metadata);
    OPENSSL_cleanse(&metadata_available, sizeof metadata_available);
    OPENSSL_cleanse(&plaintext_available, sizeof plaintext_available);
    OPENSSL_cleanse(&ciphertext_available, sizeof ciphertext_available);
    OPENSSL_cleanse(&params, sizeof params);
    OPENSSL_cleanse(&ctx, sizeof ctx);
    OPENSSL_cleanse(&in, sizeof in);
    OPENSSL_cleanse(&out, sizeof out);
    return result;
}

int main_read_pkey(const char *filename, EVP_PKEY **pkey,
        unsigned char private) {
    int result = EXIT_SUCCESS;
    BIO *bio = NULL;

    if(result == EXIT_SUCCESS &&
            (bio = BIO_new_file(filename, "rb")) == NULL) {
        result = EXIT_FAILURE;
    }
    if(private) {
        if(result == EXIT_SUCCESS &&
                (*pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)) ==
                NULL) {
            result = EXIT_FAILURE;
        }
    } else {
        if(result == EXIT_SUCCESS &&
                (*pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL)) == NULL) {
            result = EXIT_FAILURE;
        }
    }

    BIO_free_all(bio);
    OPENSSL_cleanse(&bio, sizeof bio);
    OPENSSL_cleanse(&filename, sizeof filename);
    OPENSSL_cleanse(&pkey, sizeof pkey);
    OPENSSL_cleanse(&private, sizeof private);
    return result;
}

int main_derive_key_rsa(int read, FILE *file, const char *key_filename,
        unsigned char *key, size_t key_length) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int result = EXIT_SUCCESS;
    unsigned char *encrypted_key = NULL;
    size_t encrypted_key_length = 0;
    size_t buffer_length = 0;
    unsigned char *buffer = NULL;

    if(read) {
        if(result == EXIT_SUCCESS &&
                main_read_pkey(key_filename, &pkey, 1) != EXIT_SUCCESS) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS &&
                (ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS && EVP_PKEY_decrypt_init(ctx) != 1) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS &&
                EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)
                != 1) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS && (
            main_read_size_t_bin(file, &encrypted_key_length) == EXIT_FAILURE ||
            (encrypted_key = malloc(encrypted_key_length)) == NULL ||
            fread(encrypted_key, 1, encrypted_key_length, file) <
            encrypted_key_length
        )) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS &&
                EVP_PKEY_decrypt(ctx, NULL, &buffer_length, encrypted_key,
                    encrypted_key_length) != 1) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS && (buffer = malloc(buffer_length)) == NULL) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS && EVP_PKEY_decrypt(ctx, buffer,
                    &buffer_length, encrypted_key, encrypted_key_length) != 1) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS && buffer_length != key_length) {
            result = EXIT_FAILURE;
        }
        memcpy(key, buffer, key_length);
    } else {
        if(result == EXIT_SUCCESS &&
                main_read_pkey(key_filename, &pkey, 0) != EXIT_SUCCESS) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS &&
                (ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS && EVP_PKEY_encrypt_init(ctx) != 1) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS &&
                EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING)
                != 1) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS && RAND_bytes(key, (int)key_length) != 1) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS &&
                EVP_PKEY_encrypt(ctx, NULL, &encrypted_key_length, key,
                    key_length) != 1) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS &&
                (encrypted_key = malloc(encrypted_key_length)) == NULL) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS &&
                EVP_PKEY_encrypt(ctx, encrypted_key, &encrypted_key_length, key,
                    key_length) != 1) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS && (
                main_write_size_t_bin(file, encrypted_key_length) ==
                EXIT_FAILURE ||
                fwrite(encrypted_key, 1, encrypted_key_length, file) <
                encrypted_key_length
            )) {
            result = EXIT_FAILURE;
        }
    }

    EVP_PKEY_free(pkey);
    OPENSSL_cleanse(&pkey, sizeof pkey);
		EVP_PKEY_CTX_free(ctx);
    OPENSSL_cleanse(&ctx, sizeof ctx);
    if(buffer != NULL) {
        OPENSSL_cleanse(buffer, buffer_length);
        free(buffer);
    }
    OPENSSL_cleanse(&buffer, sizeof buffer);
    if(encrypted_key != NULL) {
        OPENSSL_cleanse(encrypted_key, encrypted_key_length);
        free(encrypted_key);
    }
    OPENSSL_cleanse(&encrypted_key, sizeof encrypted_key);
    OPENSSL_cleanse(&read, sizeof read);
    OPENSSL_cleanse(&file, sizeof file);
    OPENSSL_cleanse(&key, sizeof key);
    OPENSSL_cleanse(&key_filename, sizeof key_filename);
    OPENSSL_cleanse(&key_length, sizeof key_length);
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

    if(key_length != 32) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS &&
             main_read_pkey(private_key_filename, &pkey, 1) != EXIT_SUCCESS) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS &&
             main_read_pkey(public_key_filename, &peerkey, 0) != EXIT_SUCCESS) {
        result = EXIT_FAILURE;
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


    if(skey != NULL) {
        OPENSSL_cleanse(skey, skeylen);
        free(skey);
    }
    OPENSSL_cleanse(&skey, sizeof skey);
    OPENSSL_cleanse(&skeylen, sizeof skeylen);
    OPENSSL_cleanse(&mdctx, sizeof mdctx);
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_cleanse(&ctx, sizeof ctx);
    EVP_PKEY_free(pkey);
    OPENSSL_cleanse(&pkey, sizeof pkey);
    EVP_PKEY_free(peerkey);
    OPENSSL_cleanse(&peerkey, sizeof peerkey);
    OPENSSL_cleanse(&private_key_filename, sizeof private_key_filename);
    OPENSSL_cleanse(&public_key_filename, sizeof public_key_filename);
    OPENSSL_cleanse(&key, sizeof key);
    OPENSSL_cleanse(&key_length, sizeof key_length);
    return result;
}

int main_encrypt(main_params *params, const char *plaintext_filename,
        const char *ciphertext_filename) {
    int result = EXIT_SUCCESS;
    char *sign_key_filename = malloc(params->filename_length + 1);
    char *public_key_filename = malloc(params->filename_length + 1);
    char *private_key_filename = malloc(params->filename_length + 1);
    unsigned char *tag = malloc(params->tag_length);
    unsigned char *iv = malloc(params->iv_length);
    unsigned char *key_salt = malloc(params->key_salt_length);
    size_t key_length = 32;
    unsigned char *key = malloc(key_length);
    unsigned char sign = 0;
    char *password = malloc(params->password_length + 1);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    fpos_t tag_pos;
    main_enum key_type;
    FILE *plaintext_file = NULL;
    FILE *ciphertext_file = NULL;

    if(public_key_filename == NULL || private_key_filename == NULL ||
            tag == NULL || iv == NULL || key_salt == NULL || key == NULL ||
            password == NULL || sign_key_filename == NULL) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS) {
        main_enum_init(&key_type, params->key_types);
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
        if(key_type.current_i == params->key_type_dh) {
            fprintf(params->out, "Suveskite kelią iki savo privačiojo rakto"
                    " failo (maksimalus ilgis yra ");
            fprintf(params->out, params->size_t_format_flex,
                    params->filename_length);
            fprintf(params->out, "): ");
            main_read_text(params, private_key_filename,
                    params->filename_length);
            fprintf(params->out, "Suveskite kelią iki gavėjo viešojo rakto"
                    " failo (maksimalus ilgis yra ");
            fprintf(params->out, params->size_t_format_flex,
                    params->filename_length);
            fprintf(params->out, "): ");
            main_read_text(params, public_key_filename,
                    params->filename_length);
            result = main_derive_key_dh(private_key_filename,
                    public_key_filename, key, key_length);
        } else if(key_type.current_i == params->key_type_rsa) {
            fprintf(params->out, "Suveskite kelią iki gavėjo viešojo rakto"
                    " failo (maksimalus ilgis yra ");
            fprintf(params->out, params->size_t_format_flex,
                    params->filename_length);
            fprintf(params->out, "): ");
            main_read_text(params, public_key_filename,
                    params->filename_length);
            result = main_derive_key_rsa(0, ciphertext_file,
                    public_key_filename, key, key_length);
        } else if(key_type.current_i == params->key_type_password) {
            fprintf(params->out, "Suveskite užšifravimo slaptažodį (maksimalus"
                    " ilgis yra ");
            fprintf(params->out, params->size_t_format_flex,
                    params->password_length);
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
        } else {
            result = main_error(params, 1,
                    "main_encrypt: unimplemented key_type");
        }
    }
    if(result == EXIT_SUCCESS) {
        fprintf(params->out, "Ar norėsite pasirašyti RSA parašu (taip/ne)? ");
        if(main_read_yesno(params, "taip", &sign) != EXIT_SUCCESS) {
            result = main_error(params, 1,
                    "main_encrypt: main_read_yesno (sign)");
        }
    }
    if(result == EXIT_SUCCESS && sign) {
        fprintf(params->out, "Suveskite kelią iki savo privačiojo RSA rakto"
                " failo (maksimalus ilgis yra ");
        fprintf(params->out, params->size_t_format_flex,
                params->filename_length);
        fprintf(params->out, "): ");
        main_read_text(params, sign_key_filename, params->filename_length);
    }
    if(result == EXIT_SUCCESS) {
        fprintf(params->out, "Operacija vykdoma, prašome palaukti.\n");
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
        if(result == EXIT_SUCCESS) {
            /* providing aad data, in our case one byte only */
            /* hack - reuse result - why create another variable just for this
             * dummy use?
             */
            if(EVP_EncryptUpdate(ctx, NULL, &result, &sign, 1)
                    == 1) {
                result = EXIT_SUCCESS;
            } else {
                result = main_error(params, 1,
                        "main_encrypt: EVP_EncryptUpdate (sign)");
            }
        }
        if(result == EXIT_SUCCESS &&
                key_type.current_i == params->key_type_password &&
                fwrite(key_salt, 1, params->key_salt_length, ciphertext_file) <
                params->key_salt_length) {
            result = main_error(params, 1,
                    "main_encrypt: fwrite (key_salt)");
        }
        if(result == EXIT_SUCCESS && fwrite(iv, 1, params->iv_length,
                    ciphertext_file) < params->iv_length) {
            result = main_error(params, 1,
                    "main_encrypt: fwrite (iv)");
        }
        if(result == EXIT_SUCCESS && fputc(sign, ciphertext_file) == EOF) {
            result = main_error(params, 1,
                    "main_encrypt: fputc (sign)");
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
                    plaintext_file, ciphertext_file,
                    sign ? sign_key_filename : NULL) != EXIT_SUCCESS) {
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
    if(result == EXIT_SUCCESS) {
        fprintf(params->out, "Užšifravimo operacija baigta vykdyti"
                " sėkmingai\n");
    }

    if(private_key_filename != NULL) {
        OPENSSL_cleanse(private_key_filename, params->password_length + 1);
        free(private_key_filename);
    }
    OPENSSL_cleanse(&private_key_filename, sizeof private_key_filename);
    if(public_key_filename != NULL) {
        OPENSSL_cleanse(public_key_filename, params->password_length + 1);
        free(public_key_filename);
    }
    OPENSSL_cleanse(&public_key_filename, sizeof public_key_filename);
    if(sign_key_filename != NULL) {
        OPENSSL_cleanse(sign_key_filename, params->password_length + 1);
        free(sign_key_filename);
    }
    OPENSSL_cleanse(&sign_key_filename, sizeof sign_key_filename);
    if(tag != NULL) {
        OPENSSL_cleanse(tag, params->tag_length);
        free(tag);
    }
    OPENSSL_cleanse(&tag, sizeof tag);
    if(iv != NULL) {
        OPENSSL_cleanse(iv, params->iv_length);
        free(iv);
    }
    OPENSSL_cleanse(&iv, sizeof iv);
    if(key_salt != NULL) {
        OPENSSL_cleanse(key_salt, params->key_salt_length);
        free(key_salt);
    }
    OPENSSL_cleanse(&key_salt, sizeof key_salt);
    OPENSSL_cleanse(&key_length, sizeof key_length);
    if(password != NULL) {
        OPENSSL_cleanse(password, params->password_length + 1);
        free(password);
    }
    OPENSSL_cleanse(&password, sizeof password);
    OPENSSL_cleanse(&sign, sizeof sign);
    if(key != NULL) {
        OPENSSL_cleanse(key, key_length);
        free(key);
    }
    OPENSSL_cleanse(&key, sizeof key);
    OPENSSL_cleanse(&tag_pos, sizeof tag_pos);
    OPENSSL_cleanse(&key_type, sizeof key_type);
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(&ctx, sizeof ctx);
    if(ciphertext_file != NULL) {
        if(fclose(ciphertext_file) == EOF) {
            result = main_error(params, 1,
                    "main_encrypt: fclose (ciphertext_file)");
        }
    }
    OPENSSL_cleanse(&ciphertext_file, sizeof ciphertext_file);
    if(plaintext_file != NULL) {
        if(fclose(plaintext_file) == EOF) {
            result = main_error(params, 1,
                    "main_encrypt: nepavyko uždaryti tekstogramos failo");
        }
    }
    OPENSSL_cleanse(&plaintext_file, sizeof plaintext_file);
    OPENSSL_cleanse(&params, sizeof params);
    OPENSSL_cleanse(&plaintext_filename, sizeof plaintext_filename);
    OPENSSL_cleanse(&ciphertext_filename, sizeof ciphertext_filename);
    return result;
}

size_t main_size_t_bytes(size_t size) {
    size_t buffer_length = sizeof size;
    size_t mask = ((size_t)UCHAR_MAX) << ((buffer_length - 1) * CHAR_BIT);

    while(!(mask & size) && buffer_length > 0) {
        buffer_length -= 1;
        mask >>= CHAR_BIT;
    }

    OPENSSL_cleanse(&size, sizeof size);
    OPENSSL_cleanse(&mask, sizeof mask);
    return buffer_length;
}

int main_decrypt_pipe(main_params *params, EVP_CIPHER_CTX *ctx, FILE *in,
        FILE *out, const char *key_filename) {
    int result = EXIT_SUCCESS;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *mdctx = NULL;
    size_t status = 0;
    size_t max_frame_length = 0;
    size_t frame_length = 0;
    size_t ciphertext_chunk_length;
    size_t ciphertext_buffer_length = params->pipe_buffer_length;
    unsigned char *ciphertext = malloc(ciphertext_buffer_length);
    size_t signature_length = 0;
    unsigned char *signature = NULL;
    size_t plaintext_processed;
    size_t plaintext_left = 0;
    size_t plaintext_offset = 0;
    int plaintext_chunk_length = 0;
    size_t plaintext_buffer_length = 2 * ciphertext_buffer_length;
    size_t plaintext_written = 0;
    unsigned char *plaintext_prev = malloc(plaintext_buffer_length);
    unsigned char *plaintext_;
    unsigned char *plaintext = malloc(plaintext_buffer_length);
    clock_t last_progress_clock = clock();
    clock_t current_clock = 0;
    size_t clocks_per_progress = CLOCKS_PER_SEC / 25;

    if(result == EXIT_SUCCESS && (plaintext == NULL || ciphertext == NULL)) {
        result = EXIT_FAILURE;
    }
    if(key_filename != NULL) {
        if(result == EXIT_SUCCESS && (mdctx = EVP_MD_CTX_create()) == NULL) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS &&
                main_read_pkey(key_filename, &key, 0) != EXIT_SUCCESS) {
            result = EXIT_FAILURE;
        }
        if(result == EXIT_SUCCESS && EVP_DigestVerifyInit(mdctx, NULL,
                        EVP_sha256(), NULL, key) != 1) {
            result = EXIT_FAILURE;
        }
    }
    if(result == EXIT_SUCCESS) {
        fprintf(params->out, "Įrašyta tekstogramos baitų: ");
        fprintf(params->out, params->size_t_format, plaintext_written);
    }
    while(result == EXIT_SUCCESS && status != 5) {
        memcpy(plaintext_prev, plaintext + plaintext_offset, plaintext_left);
        plaintext_ = plaintext_prev;
        plaintext_prev = plaintext;
        plaintext = plaintext_;
        plaintext_offset = 0;

        /* In EVP_Decrypt* there is an assumption that plaintext length
         * is never bigger than ciphertext length.
         */
        if(result == EXIT_SUCCESS && plaintext_offset + plaintext_left +
                ciphertext_buffer_length > plaintext_buffer_length) {
            result = EXIT_FAILURE;
        }

        /* ciphertext file into plaintext buffer */
        if(result == EXIT_SUCCESS && in != NULL) {
            if(feof(in)) {
                if(EVP_DecryptFinal_ex(ctx, plaintext + plaintext_offset +
                            plaintext_left, &plaintext_chunk_length) != 1) {
                    result = EXIT_FAILURE;
                }
                if(result == EXIT_SUCCESS) {
                    in = NULL;
                }
            } else {
                ciphertext_chunk_length = fread(ciphertext, 1,
                        ciphertext_buffer_length, in);
                if(ferror(in)) {
                    result = EXIT_FAILURE;
                }
                if(result == EXIT_SUCCESS &&
                        EVP_DecryptUpdate(ctx,
                            plaintext + plaintext_offset + plaintext_left,
                            &plaintext_chunk_length, ciphertext,
                            (int)ciphertext_chunk_length) != 1) {
                    result = EXIT_FAILURE;
                }
            }
        }
        if(result == EXIT_SUCCESS) {
            plaintext_left += (size_t)plaintext_chunk_length;
        }

        /* plaintext buffer into plaintext file */
        plaintext_processed = 1;
        while(result == EXIT_SUCCESS && plaintext_processed) {
            plaintext_processed = 0;
            if(status == 0) {
                /* read max frame size */
                if(main_read_size_t_bin_buffer(plaintext + plaintext_offset,
                        &max_frame_length, plaintext_left,
                        &plaintext_processed) == EXIT_SUCCESS &&
                        max_frame_length > params->pipe_buffer_length) {
                    result = EXIT_FAILURE;
                }
                if(result == EXIT_SUCCESS) {
                    status = 1;
                }
            } else if(status == 1) {
                /* read frame size */
                if(main_read_size_t_bin_buffer(plaintext + plaintext_offset,
                        &frame_length, plaintext_left,
                        &plaintext_processed) == EXIT_SUCCESS) {
                    if(!frame_length) {
                        status = 2;
                        frame_length = max_frame_length;
                    } else {
                        status = 3;
                    }
                }
            } else if(status == 2 || status == 3) {
                /* read frame */
                if(frame_length <= plaintext_left) {
                    if(fwrite(plaintext + plaintext_offset, 1,
                                frame_length, out) < frame_length) {
                        result = EXIT_FAILURE;
                    }
                    if(key_filename != NULL) {
                        if(result == EXIT_SUCCESS &&
                                EVP_DigestVerifyUpdate(mdctx,
                                    plaintext + plaintext_offset,
                                    frame_length) != 1) {
                            result = EXIT_FAILURE;
                        }
                    }
                    if(result == EXIT_SUCCESS) {
                        plaintext_processed += frame_length;
                        plaintext_written += frame_length;
                        current_clock = clock();
                        if((size_t)(current_clock - last_progress_clock) >
                                clocks_per_progress) {
                            last_progress_clock = current_clock;
                            main_write_char(params->out, '\b',
                                    params->size_max_digits);
                            fprintf(params->out, params->size_t_format,
                                    plaintext_written);
                        }
                        frame_length = 0;
                        if(status == 3) {
                            status = 4;
                        } else if(status == 2) {
                            status = 1;
                        }
                    }
                }
            } else if(status == 4) {
                /* read signature */
                if(in == NULL) {
                    if(key_filename != NULL) {
                        if(EVP_DigestVerifyFinal(mdctx,
                                    plaintext + plaintext_offset,
                                    plaintext_left) != 1) {
                            result = EXIT_FAILURE;
                        }
                        if(result == EXIT_SUCCESS) {
                            plaintext_processed += plaintext_left;
                        }
                    }
                    if(result == EXIT_SUCCESS) {
                        status = 5;
                    }
                }
            }
            plaintext_offset += plaintext_processed;
            plaintext_left -= plaintext_processed;
        }
    }
    main_write_char(params->out, '\b', params->size_max_digits);
    fprintf(params->out, params->size_t_format, plaintext_written);
    fprintf(params->out, "\n");

    if(ciphertext != NULL) {
        OPENSSL_cleanse(ciphertext, ciphertext_buffer_length);
        free(ciphertext);
    }
    OPENSSL_cleanse(&ciphertext, sizeof ciphertext);
    if(plaintext_prev != NULL) {
        OPENSSL_cleanse(plaintext_prev, plaintext_buffer_length);
        free(plaintext_prev);
    }
    OPENSSL_cleanse(&plaintext_prev, sizeof plaintext_prev);
    if(plaintext != NULL) {
        OPENSSL_cleanse(plaintext, plaintext_buffer_length);
        free(plaintext);
    }
    OPENSSL_cleanse(&plaintext_written, sizeof plaintext_written);
    OPENSSL_cleanse(&plaintext, sizeof plaintext);
    OPENSSL_cleanse(&plaintext_, sizeof plaintext_);
    if(signature != NULL) {
        OPENSSL_cleanse(signature, signature_length);
        free(signature);
    }
    OPENSSL_cleanse(&signature, sizeof signature);
    if(mdctx != NULL) {
        EVP_MD_CTX_destroy(mdctx);
    }
    OPENSSL_cleanse(&mdctx, sizeof mdctx);
    EVP_PKEY_free(key);
    OPENSSL_cleanse(&key, sizeof key);
    OPENSSL_cleanse(&last_progress_clock, sizeof last_progress_clock);
    OPENSSL_cleanse(&current_clock, sizeof current_clock);
    OPENSSL_cleanse(&clocks_per_progress, sizeof clocks_per_progress);
    OPENSSL_cleanse(&signature_length, sizeof signature_length);
    OPENSSL_cleanse(&status, sizeof status);
    OPENSSL_cleanse(&plaintext_offset, sizeof plaintext_offset);
    OPENSSL_cleanse(&max_frame_length, sizeof max_frame_length);
    OPENSSL_cleanse(&frame_length, sizeof frame_length);
    OPENSSL_cleanse(&plaintext_buffer_length, sizeof plaintext_buffer_length);
    OPENSSL_cleanse(&plaintext_chunk_length, sizeof plaintext_chunk_length);
    OPENSSL_cleanse(&plaintext_processed, sizeof plaintext_processed);
    OPENSSL_cleanse(&ciphertext_buffer_length, sizeof ciphertext_buffer_length);
    OPENSSL_cleanse(&ciphertext_chunk_length, sizeof ciphertext_chunk_length);
    OPENSSL_cleanse(&plaintext_left, sizeof plaintext_left);
    OPENSSL_cleanse(&params, sizeof params);
    OPENSSL_cleanse(&ctx, sizeof ctx);
    OPENSSL_cleanse(&in, sizeof in);
    OPENSSL_cleanse(&out, sizeof out);
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
                result = main_error(params, 1, "main_read_key_type: fputs");
                break;
            }
        }
        if(result == EXIT_SUCCESS) {
            fprintf(params->out, ": ");
            result = main_read_enum(params, key_type);
            if(result != EXIT_SUCCESS) {
                main_error(params, 1, "main_read_key_type: main_read_enum");
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

    OPENSSL_cleanse(&params, sizeof params);
    OPENSSL_cleanse(&key_type, sizeof key_type);
    OPENSSL_cleanse(&i, sizeof i);
    return result;
}

int main_decrypt(main_params *params, const char *ciphertext_filename,
        const char *plaintext_filename) {
    int result = EXIT_SUCCESS;
    char *sign_key_filename = malloc(params->filename_length + 1);
    FILE *plaintext_file = NULL;
    FILE *ciphertext_file = NULL;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    char *public_key_filename = malloc(params->filename_length + 1);
    char *private_key_filename = malloc(params->filename_length + 1);
    unsigned char *tag = malloc(params->tag_length);
    unsigned char *iv = malloc(params->iv_length);
    unsigned char *key_salt = malloc(params->key_salt_length);
    unsigned char sign = 0;
    size_t key_length = 32;
    unsigned char *key = malloc(key_length);
    char *password = malloc(params->password_length + 1);
    main_enum key_type;

    if(tag == NULL || iv == NULL || key_salt == NULL || key == NULL ||
            password == NULL || public_key_filename == NULL ||
            private_key_filename == NULL || sign_key_filename == NULL) {
        result = EXIT_FAILURE;
    }
    if(result == EXIT_SUCCESS) {
        main_enum_init(&key_type, params->key_types);
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
    if(key_type.current_i == params->key_type_password) {
        if(result == EXIT_SUCCESS) {
            fprintf(params->out, "Suveskite iššifravimo slaptažodį (maksimalus"
                    " ilgis yra ");
            fprintf(params->out, params->size_t_format_flex,
                    params->password_length);
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
    } else if(key_type.current_i == params->key_type_rsa) {
        if(result == EXIT_SUCCESS) {
            fprintf(params->out, "Suveskite kelią iki savo privačiojo rakto"
                    " failo (maksimalus ilgis yra ");
            fprintf(params->out, params->size_t_format_flex,
                    params->filename_length);
            fprintf(params->out, "): ");
            main_read_text(params, private_key_filename,
                    params->filename_length);
            result = main_derive_key_rsa(1, ciphertext_file,
                    private_key_filename, key, key_length);
        }
    } else if(key_type.current_i == params->key_type_dh) {
        if(result == EXIT_SUCCESS) {
            fprintf(params->out, "Suveskite kelią iki savo privačiojo rakto"
                    " failo (maksimalus ilgis yra ");
            fprintf(params->out, params->size_t_format_flex,
                    params->filename_length);
            fprintf(params->out, "): ");
            main_read_text(params, private_key_filename,
                    params->filename_length);
            fprintf(params->out, "Suveskite kelią iki siuntėjo viešojo rakto"
                    " failo (maksimalus ilgis yra ");
            fprintf(params->out, params->size_t_format_flex,
                    params->filename_length);
            fprintf(params->out, "): ");
            main_read_text(params, public_key_filename,
                    params->filename_length);
            result = main_derive_key_dh(private_key_filename,
                    public_key_filename, key, key_length);
        }
    } else {
        result = main_error(params, 1, "main_decrypt: unimplemented key_type");
    }
    if(result == EXIT_SUCCESS) {
        fread(iv, 1, params->iv_length, ciphertext_file);
        if(ferror(ciphertext_file)) {
            result = main_error(params, 1,
                    "main_decrypt: nepavyko nuskaityti inicializacijos"
                    " vektoriaus");
        }
    }
    if(result == EXIT_SUCCESS &&
            fread(&sign, 1, 1, ciphertext_file) < 1) {
        result = main_error(params, 1, "main_decrypt: fgetc (sign)");
    }
    if(result == EXIT_SUCCESS && sign) {
        fprintf(params->out, "Suveskite kelią iki siuntėjo viešojo RSA rakto"
                " failo (maksimalus ilgis yra ");
        fprintf(params->out, params->size_t_format_flex,
                params->filename_length);
        fprintf(params->out, "): ");
        main_read_text(params, sign_key_filename, params->filename_length);
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
    if(result == EXIT_SUCCESS) {
        /* hack - reuse result - why create another variable just for this
         * dummy use?
         */
        if(EVP_DecryptUpdate(ctx, NULL, &result, &sign, 1)
                == 1) {
            result = EXIT_SUCCESS;
        } else {
            result = main_error(params, 1,
                    "main_decrypt: EVP_DecryptUpdate (sign)");
        }
    }
    if(result == EXIT_SUCCESS && main_decrypt_pipe(params, ctx,
                ciphertext_file, plaintext_file,
                sign ? sign_key_filename : NULL) != EXIT_SUCCESS) {
        result = main_error(params, 1, "main_decrypt: main_decrypt_pipe");
    }
    if(result == EXIT_SUCCESS) {
        fprintf(params->out, "Iššifravimo operacija baigta vykdyti"
                " sėkmingai\n");
    }

    if(plaintext_file != NULL) {
        if(fclose(plaintext_file) == EOF) {
            result = main_error(params, 1, "main_decrypt: fclose"
                    " (plaintext_file)");
        }
    }
    OPENSSL_cleanse(&plaintext_file, sizeof plaintext_file);
    if(ciphertext_file != NULL) {
        if(fclose(ciphertext_file) == EOF) {
            result = main_error(params, 1,
                    "main_decrypt: fclose (ciphertext_file)");
        }
    }
    OPENSSL_cleanse(&ciphertext_file, sizeof ciphertext_file);
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(&ctx, sizeof ctx);
    if(private_key_filename != NULL) {
        OPENSSL_cleanse(private_key_filename, params->password_length + 1);
        free(private_key_filename);
    }
    OPENSSL_cleanse(&private_key_filename, sizeof private_key_filename);
    if(public_key_filename != NULL) {
        OPENSSL_cleanse(public_key_filename, params->password_length + 1);
        free(public_key_filename);
    }
    OPENSSL_cleanse(&public_key_filename, sizeof public_key_filename);
    if(sign_key_filename != NULL) {
        OPENSSL_cleanse(sign_key_filename, params->password_length + 1);
        free(sign_key_filename);
    }
    OPENSSL_cleanse(&sign_key_filename, sizeof sign_key_filename);
    if(tag != NULL) {
        OPENSSL_cleanse(tag, params->tag_length);
        free(tag);
    }
    OPENSSL_cleanse(&tag, sizeof tag);
    if(iv != NULL) {
        OPENSSL_cleanse(iv, params->iv_length);
        free(iv);
    }
    OPENSSL_cleanse(&iv, sizeof iv);
    if(key_salt != NULL) {
        OPENSSL_cleanse(key_salt, params->key_salt_length);
        free(key_salt);
    }
    OPENSSL_cleanse(&key_salt, sizeof key_salt);
    if(key != NULL) {
        OPENSSL_cleanse(key, key_length);
        free(key);
    }
    OPENSSL_cleanse(&key, sizeof key);
    OPENSSL_cleanse(&key_length, sizeof key_length);
    OPENSSL_cleanse(&sign, sizeof sign);
    if(password != NULL) {
        OPENSSL_cleanse(password, params->password_length + 1);
        free(password);
    }
    OPENSSL_cleanse(&password, sizeof password);
    OPENSSL_cleanse(&key_type, sizeof key_type);
    OPENSSL_cleanse(&params, sizeof params);
    OPENSSL_cleanse(&ciphertext_filename, sizeof ciphertext_filename);
    OPENSSL_cleanse(&plaintext_filename, sizeof plaintext_filename);
    return result;
}

int main_write_bytes_hex(main_params *params, unsigned char *bytes,
        size_t length) {
    int result = EXIT_SUCCESS;
    size_t i;

    for(i = 0; i < length; i += 1) {
        if(fprintf(params->out, "%x", bytes[i]) < 0) {
            result = EXIT_FAILURE;
            break;
        }
    }

    OPENSSL_cleanse(&i, sizeof i);
    OPENSSL_cleanse(&params, sizeof params);
    OPENSSL_cleanse(&bytes, sizeof bytes);
    OPENSSL_cleanse(&length, sizeof length);
    return result;
}

