/*
 * Elliptic Curve Diffie Hellman
 *
 * Megan Judd and Tyler Schill
 * Spring 2026
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

/*
 * Curve info:
 *
 * secp256r1 (aka P-256)
 *
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
 */ 

#define test_p 23
#define test_a 1
#define test_b 1
#define test_Gx 4
#define test_Gy 5
#define test_n 7
#define test_h 1

/*
 * Point Structure
 */
typedef struct point {
    
    BIGNUM *x; // x-coordinate
    BIGNUM *y; // y-coordinate

} point_t;

/*
 * Hashed Key Derivation Function
 *
 * Definition: produces a 128 bit key
 *
 * Parameters:
 *
 * salt:
 *
 * ikm: (input key material) this is the shared secret
 * we generate from Diffie Hellman
 *
 */
long hkdf(long salt, ikm) {

    long key;

    return key;
}

point_t* point_addition(point_t *p, point_t *q, BIGNUM *n) {

    point_t *result = malloc(sizeof(point_t));

    if (result == NULL) {
        fprintf(stderr, "Could not malloc new point\n");
        return NULL;
    }
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *x_slope = BN_new();
    BIGNUM *y_slope = BN_new();
    BIGNUM *y_slope_inv = BN_new();
    BIGNUM *slope = BN_new();
    
    //(q->y - p->y) / (q->x - p->x);
    if(BN_mod_sub(x_slope, p->x, q->x, n, ctx) == 0 || BN_mod_sub(y_slope, p->y, q->y, n, ctx) == 0 || 
		    BN_mod_inverse(y_slope_inv, y_slope, n, ctx) == 0 || BN_mod_mul(slope, x_slope, y_slope_inv, n, ctx) == 0){
    	fprintf(stderr, "Could not calculate the slope\n");
	return NULL;
    }

 
    // (slope)^2 - x_two - x_one
    BIGNUM *slope_2 = BN_new();
    BIGNUM *new_x = BN_new();
    if(BN_mod_mul(slope_2, slope, slope, n, ctx) == 0 || BN_mod_sub(new_x, x_slope, slope_2, n, ctx) == 0){
	    fprintf(stderr, "Could not calculate new x\n");
	    return NULL;
    }

    // slope(x_two - x_one) - y_one
    BIGNUM *slope_xdiff = BN_new();
    BIGNUM *new_y = BN_new();
    if(BN_mod_mul(slope_xdiff, slope, x_slope, n, ctx) === 0 || BN_mod_sub(new_y, p->y, slope_xdiff, n, ctx) == 0){
    	fprintf(stderr, "Could not calculate new y\n");
	return NULL;
    }

    result->x = new_x;
    result->y = new_y;

    return result;
}

point_t* point_mult(){}

int main() {

    // bignum stuff
    BIGNUM *bn_p = BN_new();
    BIGNUM *bn_a = BN_new();
    BIGNUM *bn_b = BN_new();
    BIGNUM *bn_Gx = BN_new();
    BIGNUM *bn_Gy = BN_new();
    BIGNUM *bn_n = BN_new();
    
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

    // key derivation
    char *secret_in_hex = BN_bn2hex(shared_sec);

    if (secret_in_hex == NULL) {
        fprintf(stdout, "Could not generate secret in hex\n");
        return EXIT_FAILURE;
    }

    int secret_in_hex_len = strlen(secret_in_hex);
    unsigned char *key = malloc(sizeof(char) * 32);

    int result_derivation = PKCS5_PBKDF2_HMAC_SHA1(secret_in_hex,
                                                   secret_in_hex_len,
                                                   NULL,
                                                   0,
                                                   1000,
                                                   32,
                                                   key);

    int test_len = strlen(key);
    if(test_len != 32){
        fprintf(stderr, "Key length does not match desired length\n");
        return EXIT_FAILURE;
    }

    fprintf(stdout, "\nThe generated key is %s\n", key);
    

    // now test this key with a symmetric encryption algorithm, like AES/DES for example


    // free stuff
    BN_free(bn_p); BN_free(bn_a); BN_free(bn_b); BN_free(bn_Gx); BN_free(bn_Gy); BN_free(bn_n);
    BN_free(a_sec); BN_free(b_sec); BN_free(shared_sec); BN_free(check);
    BN_free(a_key_x); BN_free(b_key_x);
    BN_CTX_free(ctx);

    return EXIT_SUCCESS;
}
