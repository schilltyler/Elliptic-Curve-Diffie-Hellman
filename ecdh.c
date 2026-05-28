/*
 * Elliptic Curve Diffie Hellman
 *
 * Megan Judd and Tyler Schill
 * Spring 2026
 */
#include <stdlib.h>
#include <stdio.h>
#include <openssl/bn.h>
#include <string.h>

/*
 * Curve info:
 *
 * secp256r1 (aka P-256)
 *
 * p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
 * (115792089210356248762697446949407573530086143415290314195533631308867097853951)
 * a: 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
 * (115792089210356248762697446949407573530086143415290314195533631308867097853948)
 * b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
 * (41058363725152142129326129780047268409114441015993725554835256314039467401291)
 * Gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
 * (48439561293906451759052585252797914202762949526041747995844080717082404635286)
 * Gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
 * (36134250956749795798585127919587881956611106672985015071877198253568414405109)
 * n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
 * (115792089210356248762697446949407573529996955224135760342422259061068512044369)
 * h: 1
 */
#define p "115792089210356248762697446949407573530086143415290314195533631308867097853951"
#define a "115792089210356248762697446949407573530086143415290314195533631308867097853948"
#define b "41058363725152142129326129780047268409114441015993725554835256314039467401291"
#define Gx "48439561293906451759052585252797914202762949526041747995844080717082404635286"
#define Gy "36134250956749795798585127919587881956611106672985015071877198253568414405109"
#define n "115792089210356248762697446949407573529996955224135760342422259061068512044369"
#define h 1

/*
 * Test values:
 *
 * p: 23
 * a: 1
 * b: 1
 * Gx: 4
 * Gy: 5
 * n: 7
 * h: 1
 */ 

#define test_p 23
#define test_a 1
#define test_b 1
#define test_Gx 4
#define test_Gy 5
#define test_n 7
#define test_h 1

int main() {

    // bignum stuff
    BIGNUM *bn_p = BN_new();
    BIGNUM *bn_a = BN_new();
    BIGNUM *bn_b = BN_new();
    BIGNUM *bn_Gx = BN_new();
    BIGNUM *bn_Gy = BN_new();
    BIGNUM *bn_n = BN_new();
    // did we say we did not have to do one for h?
    
    //BN_dec2bn(&bn_p, str_num);
    BN_dec2bn(&bn_p, p);
    BN_dec2bn(&bn_a, a);
    BN_dec2bn(&bn_b, b);
    BN_dec2bn(&bn_Gx, Gx);
    BN_dec2bn(&bn_Gy, Gy);
    BN_dec2bn(&bn_n, n);


    if (BN_print_fp(stdout, bn_p) == 0) {
        fprintf(stderr, "Could not print out bignum\n");
        return EXIT_FAILURE;
    }
    fprintf(stdout, "\n");
    if (BN_print_fp(stdout, bn_a) == 0) {
        fprintf(stderr, "Could not print out bignum\n");
        return EXIT_FAILURE;
    }
    fprintf(stdout, "\n");

    if (BN_print_fp(stdout, bn_b) == 0) {
        fprintf(stderr, "Could not print out bignum\n");
        return EXIT_FAILURE;
    }
    fprintf(stdout, "\n");

    if (BN_print_fp(stdout, bn_Gx) == 0) {
        fprintf(stderr, "Could not print out bignum\n");
        return EXIT_FAILURE;
    }
    fprintf(stdout, "\n");
    
    if (BN_print_fp(stdout, bn_Gy) == 0) {
        fprintf(stderr, "Could not print out bignum\n");
        return EXIT_FAILURE;
    }
    fprintf(stdout, "\n");

    if (BN_print_fp(stdout, bn_n) == 0) {
        fprintf(stderr, "Could not print out bignum\n");
        return EXIT_FAILURE;
    }
    fprintf(stdout, "\n\n");
    
    
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *a_sec = BN_new();
    BIGNUM *b_sec = BN_new();
	
    
    if(BN_rand_range(a_sec, bn_n) == 0 || BN_rand_range(b_sec, bn_n) == 0){
        fprintf(stderr, "Could not generate rand\n");
	return EXIT_FAILURE;
    }

    if(BN_print_fp(stdout, a_sec) == 0){
    	fprintf(stderr, "Could not print out bignum\n");
        return EXIT_FAILURE;
    }
    fprintf(stdout, "\n");

    if(BN_print_fp(stdout, b_sec) == 0){
        fprintf(stderr, "Could not print out bignum\n");
        return EXIT_FAILURE;
    }
    fprintf(stdout, "\n");
    

    BIGNUM *a_key_x = BN_new(); // test with double pointer make sure to dereference ptr
	
    if(BN_mul(a_key_x, bn_Gx, a_sec, ctx) == 0){
    	fprintf(stderr, "Could not multiply\n");
	return EXIT_FAILURE;
    }
    
    BIGNUM *b_key_x = BN_new();
    if(BN_mul(b_key_x, bn_Gx, b_sec, ctx) == 0){
    	fprintf(stderr, "Could not multiply\n");
	return EXIT_FAILURE;
    }

    BIGNUM *shared_sec = BN_new();

    if(BN_mul(shared_sec, a_sec, b_key_x, ctx) == 0){
    	fprintf(stderr, "Could not multiply\n");
	return EXIT_FAILURE;
    }


    // now check that bob's calculation of shared x equals what alice calculated for sec
    BIGNUM* check = BN_new();
    if(BN_mul(check, a_key_x, b_sec, ctx) == 0){
    	fprintf(stderr, "Could not multiply\n");
	return EXIT_FAILURE;
    }
    
    if(BN_cmp(shared_sec, check) == 0){
        fprintf(stdout, "Yayayayaya we won BIG(num)!\n");
    }
    BN_free(bn_p); BN_free(bn_a); BN_free(bn_b); BN_free(bn_Gx); BN_free(bn_Gy); BN_free(bn_n);
    BN_free(a_sec); BN_free(b_sec); BN_free(shared_sec); BN_free(check);
    BN_free(a_key_x); BN_free(b_key_x);
    BN_CTX_free(ctx);


    /*// randomly generate Alice's secret
    int a_secret = 1 + rand() % 5;

    // randomly generate Bob's secret
    int b_secret = 1 + rand() % 5;

    // calculate Alice public key
    int a_public[2];

    a_public[0] = test_Gx * a_secret;
    a_public[1] = test_Gy * a_secret;

    // calculate Bob public key
    int b_public[2];

    b_public[0] = test_Gx * b_secret;
    b_public[1] = test_Gy * b_secret;

    // Alice calculate shared secret
    int shared_secret[2];

    shared_secret[0] = b_public[0] * a_secret;
    shared_secret[1] = b_public[1] * a_secret;

    // Bob calculate shared secret (compare to Alice)
    if (a_public[0] * b_secret == shared_secret[0]) {
        fprintf(stdout, "Yayayayaya we won!\n");
    }*/
    

    return EXIT_SUCCESS;
}
