#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#define byte uint8_t

int sign(const char*msg, EVP_PKEY*key) {
        EVP_MD_CTX * mdctx = NULL;
        int ret = 0;

        unsigned char*sig = (unsigned char*)malloc(SHA512_DIGEST_LENGTH);

        /* Create the Message Digest Context */
        mdctx = EVP_MD_CTX_create();

        /* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
        EVP_DigestSignInit(mdctx, NULL, EVP_sha512(), NULL, key);

        /* Call update with the message */
        EVP_DigestSignUpdate(mdctx, msg, strlen(msg));

        /* Finalise the DigestSign operation */
        /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
         * signature. Length is returned in slen */
        size_t * slen = (size_t *) malloc(sizeof(size_t *));
        EVP_DigestSignFinal(mdctx, NULL, slen);
        printf("dlugosc:%zu\n", slen);
        /* Allocate memory for the signature based on size in slen */
        sig = (unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*( * slen));
        /* Obtain the signature */
        EVP_DigestSignFinal(mdctx, sig, slen);

        /* Success */
        ret = 1;
        char mdString[ SHA512_DIGEST_LENGTH * 2 + 1];
        for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
            sprintf( & mdString[i * 2], "%02x", (unsigned int)sig[i]);

        printf("%dSHA512 digest: %s\n", sizeof(sig), mdString);
        FILE * fp = fopen("signature", "w");
        if (fp != NULL) {
            fwrite(sig, 256, 1, fp);
            fclose(fp);
        }
        /* Clean up */
        if (*sig && !ret)OPENSSL_free(sig);
        if (mdctx) EVP_MD_CTX_destroy(mdctx);
        return 0;
    }

    void verify_it(const char*msg, int size,const unsigned char*sig, EVP_PKEY*key) {
        EVP_MD_CTX * mdctx = EVP_MD_CTX_create();
        size_t slen = (size_t) malloc(sizeof(size_t));
        int ret = 0;
        printf("%d\n", EVP_DigestVerifyInit(mdctx, NULL, EVP_sha512(), NULL, key));
        ERR_print_errors_fp(stderr);
        printf("%d\n", EVP_DigestVerifyUpdate(mdctx, msg, size));
        ERR_print_errors_fp(stderr);

        size_t len = sizeof(sig);
        if (1 == EVP_DigestVerifyFinal(mdctx, sig, 256)) {
            printf("%s", "Signature is valid");
        } else {
            printf("%s\n", "Signature is not valid");
            ERR_print_errors_fp(stderr);
        }
    }


// gcc sha512.cpp -o sha -lcrypto 
// ./sha file private.pem
// ./sha file signature public.pem
    int main(int argc, char*argv[]) {
        if (argc == 3) {
            FILE * pFile = fopen(argv[2], "rt");
            EVP_PKEY * pPrivKey = NULL;
            pPrivKey = PEM_read_PrivateKey(pFile, NULL, NULL, NULL);
            fclose(pFile);
            FILE * file;
            char*buffer;
            unsigned long fileLen;
            file = fopen(argv[1], "rb");
            fseek(file, 0, SEEK_END);
            fileLen = ftell(file);
            fseek(file, 0, SEEK_SET);
            buffer = ( char*)malloc(fileLen + 1);
            fread(buffer, fileLen, 1, file);
            fclose(file);
            sign(buffer, pPrivKey);
        } else {
            EVP_PKEY * pPublicKey = NULL;
            FILE * pFile = fopen(argv[3], "rt");
            pPublicKey = PEM_read_PUBKEY(pFile, NULL, NULL, NULL);
            fclose(pFile);
            pFile = NULL;
            FILE * file;
            char*buffer;
            unsigned long fileLen;
            file = fopen(argv[1], "rb");
            fseek(file, 0, SEEK_END);
            fileLen = ftell(file);
            fseek(file, 0, SEEK_SET);
            buffer = ( char*)malloc(fileLen + 1);
            fread(buffer, fileLen, 1, file);
            fclose(file);

            unsigned char*signature;
            unsigned long sigLen;
            file = fopen(argv[2], "rb");
            fseek(file, 0, SEEK_END);
            sigLen = ftell(file);
            fseek(file, 0, SEEK_SET);

            FILE * secret_fp = fopen("signature", "rb");
            unsigned long file_len = 256;
            signature = (unsigned char*)malloc(file_len);
            fread(signature, file_len, 1, secret_fp);

            verify_it(buffer, fileLen, signature, pPublicKey);
        }

    }