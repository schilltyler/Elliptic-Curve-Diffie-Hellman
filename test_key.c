/*
 *
 * CS62: AES encrypt/decrypt using openssl and ECDH derived key
 *
 * Megan and Tyler
 *
 * Spring 2026
 * */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int main(int argc, char *argv[]){

    if (argc != 2) {
    	fprintf(stderr, "usage: %s keyfile\n", argv[0]);
	    return EXIT_FAILURE;
    }

    char *keyfile = argv[1]; 

    FILE *fp = fopen(keyfile, "rb");
    if (fp == NULL) {
    	fprintf(stderr, "Error opening keyfile\n");
	    return EXIT_FAILURE;
    }

    unsigned char key[EVP_MAX_MD_SIZE];

    // use fread to read the binary key exactly as it is 
    if (fread(key, 1,  EVP_MAX_MD_SIZE, fp) != 32) { // AES - 256 has 32 byte key = 256 bits
    	fprintf(stderr, "Error grabbing key\n");
	    return EXIT_FAILURE;
    }
    
    // AES encrypt
    EVP_CIPHER_CTX *e_ctx = EVP_CIPHER_CTX_new(); // null check?
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC", NULL);
    unsigned char iv[16];

    if (!RAND_bytes(iv, sizeof(iv))) {
        fprintf(stderr, "Error generating IV\n");
        return EXIT_FAILURE;
    }

    // setting iv == NULL for right now
    if (!EVP_EncryptInit_ex2(e_ctx, cipher, key, iv, NULL)) {
        fprintf(stdout, "Error initializing AES\n");
        return EXIT_FAILURE;
    }

    // ask user for input
    unsigned char *message = malloc(200);
    if (message == NULL) {
        fprintf(stderr, "Could not allocate space for message\n");
        return EXIT_FAILURE;
    }

    if (!fgets((char *)message, 200, stdin)) {
        fprintf(stderr, "Error reading input\n");
        return EXIT_FAILURE;
    }

    //fprintf(stdout, "Message: %s\n", message);

    int plaintext_len = strlen((char *)message);
    //fprintf(stdout, "plaintext len: %d\n", plaintext_len);
    unsigned char cipher_text[256];
    int e_out_len1;
    int e_out_len2;

    if (!EVP_EncryptUpdate(e_ctx, cipher_text, &e_out_len1, message, plaintext_len)) {
        fprintf(stdout, "Error encrypting\n");
        return EXIT_FAILURE;
    }

    if (!EVP_EncryptFinal_ex(e_ctx, cipher_text + e_out_len1, &e_out_len2)) {
        fprintf(stdout, "Error finalizing encryption\n");
        return EXIT_FAILURE;
    }

    fprintf(stdout, "Ciphertext: ");
    for (int i = 0; i < e_out_len1 + e_out_len2; i ++) {
        fprintf(stdout, "%02x", cipher_text[i]);
    }
    fprintf(stdout, "\n");

    // AES decrypt

    // create new context
    EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new(); // null check?

    if (!EVP_DecryptInit_ex2(d_ctx, cipher, key, iv, NULL)) {
        fprintf(stderr, "Error initializing decryption\n");
        return EXIT_FAILURE;
    }

    unsigned char decrypted_text[256];
    int d_out_len1;
    int d_out_len2;
    int ciphertext_len = e_out_len1 + e_out_len2;

    if (!EVP_DecryptUpdate(d_ctx, decrypted_text, &d_out_len1, cipher_text, ciphertext_len)) {
        fprintf(stderr, "Error decrypting\n");
        return EXIT_FAILURE;
    }

    if (!EVP_DecryptFinal_ex(d_ctx, decrypted_text + d_out_len1, &d_out_len2)) {
        fprintf(stdout, "Error finalizing decryption\n");
        return EXIT_FAILURE;
    }

    decrypted_text[d_out_len1 + d_out_len2] = '\0';

    fprintf(stdout, "Decrypted Text: %s\n", decrypted_text);

    // free structures
    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(e_ctx);
    EVP_CIPHER_CTX_free(d_ctx);

    return EXIT_SUCCESS;

}
