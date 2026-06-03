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

int main(int argc, char *argv[]){
    if (argc != 2) {
    	fprintf(stderr, "usage: %s keyfile plaintext\n", argv[0]);
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
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // null check?
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC", NULL);

    // setting iv == NULL for right now
    if (!EVP_EncryptInit_ex2(ctx, cipher, key, NULL, NULL)) {
        fprintf(stdout, "Error initializing AES\n");
        return EXIT_FAILURE;
    }

    // ask user for input
    unsigned char *message = malloc(200);
    if (message == NULL) {
        fprintf(stderr, "Could not allocate space for message\n");
        return EXIT_FAILURE;
    }

    if (fscanf(stdin, "%s", message) != 1) {
        fprintf(stderr, "Error reading input\n");
        return EXIT_FAILURE;
    }

    int plaintext_len = strlen((char *)message);
    int *out_len = malloc(sizeof(int));
    if (out_len == NULL) {
        fprintf(stderr, "Could not allocate memory for out_len\n");
        return EXIT_FAILURE;
    }

    unsigned char cipher_text[256];

    if (!EVP_EncryptUpdate(ctx, cipher_text, out_len, message, plaintext_len)) {
        fprintf(stdout, "Error encrypting\n");
        return EXIT_FAILURE;
    }

    if (!EVP_EncryptFinal_ex(ctx, cipher_text, out_len)) {
        fprintf(stdout, "Error finalizing encryption\n");
        return EXIT_FAILURE;
    }

    fprintf(stdout, "Ciphertext: %s\n", cipher_text);

    // AES decrypt
    if (!EVP_DecryptInit_ex2(ctx, cipher, key, NULL, NULL)) {
        fprintf(stderr, "Error initializing decryption\n");
        return EXIT_FAILURE;
    }

    unsigned char decrypted_text[256];

    if (!EVP_DecryptUpdate(ctx, decrypted_text, out_len, cipher_text, *out_len)) {
        fprintf(stderr, "Error decrypting\n");
        return EXIT_FAILURE;
    }

    if (!EVP_DecryptFinal_ex(ctx, decrypted_text, out_len)) {
        fprintf(stdout, "Error finalizing decryption\n");
        return EXIT_FAILURE;
    }

    fprintf(stdout, "Decrypted Text: %s\n", decrypted_text);

    return EXIT_SUCCESS;

}
