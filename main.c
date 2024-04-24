#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void en_de_crypt(const char* input_file, const char* output_file, const unsigned char* key, int encrypt) {
    FILE *infile = fopen(input_file, "rb");
    FILE *outfile = fopen(output_file, "wb");
    if (infile == NULL || outfile == NULL) {
        perror("File opening failed");
        exit(1);
    }

    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        fprintf(stderr, "Could not create random bytes.\n");
        exit(1);
    }

    fwrite(iv, 1, AES_BLOCK_SIZE, outfile); // Write the IV for decryption purposes

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (encrypt) {
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();
    } else {
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
            handleErrors();
    }

    int len;
    unsigned char indata[1024];
    unsigned char outdata[1024 + AES_BLOCK_SIZE];

    while (1) {
        int num_bytes_read = fread(indata, 1, 1024, infile);
        if (num_bytes_read <= 0) break;
        if (encrypt) {
            if (1 != EVP_EncryptUpdate(ctx, outdata, &len, indata, num_bytes_read))
                handleErrors();
        } else {
            if (1 != EVP_DecryptUpdate(ctx, outdata, &len, indata, num_bytes_read))
                handleErrors();
        }
        fwrite(outdata, 1, len, outfile);
    }

    if (encrypt) {
        if (1 != EVP_EncryptFinal_ex(ctx, outdata + len, &len))
            handleErrors();
    } else {
        if (1 != EVP_DecryptFinal_ex(ctx, outdata + len, &len))
            handleErrors();
    }
    fwrite(outdata + len, 1, len, outfile);

    EVP_CIPHER_CTX_free(ctx);
    fclose(infile);
    fclose(outfile);
}

int main(int argc, char* argv[]) {
    if (argc != 7) {
        printf("Usage: %s -i <input_file> -o <output_file> -k <key> -e|-d\n", argv[0]);
        return 1;
    }

    char *input_file = NULL, *output_file = NULL, *key = NULL;
    int encrypt = 1; // Default to encryption mode

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            input_file = argv[i + 1];
        } else if (strcmp(argv[i], "-o") == 0) {
            output_file = argv[i + 1];
        } else if (strcmp(argv[i], "-k") == 0) {
            key = argv[i + 1];
        } else if (strcmp(argv[i], "-e") == 0) {
            encrypt = 1;
        } else if (strcmp(argv[i], "-d") == 0) {
            encrypt = 0;
        }
    }

    en_de_crypt(input_file, output_file, (unsigned char *)key, encrypt);

    return 0;
}
