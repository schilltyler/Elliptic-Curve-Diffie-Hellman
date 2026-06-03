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
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/*
 * Curve info:
 *
 * secp256r1 (aka P-256)
 * parameters for curve math 
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
 * Point Structure:
 *
 * Points along the graph require an x,y component, necessary struct for point addition and multiplication 
 *
 */
typedef struct point {
    
    BIGNUM *x; // x-coordinate
    BIGNUM *y; // y-coordinate
    int is_infinity; // to mark whether this is a point at infinity, in which you treat it as the identity element 
} point_t;

point_t* point_new() {

    point_t *point = malloc(sizeof(point_t*));

    if (point == NULL){
    	return NULL;
    }

    point->x = BN_new();
    point->y = BN_new();
    point->is_infinity = 0; // make it automatically not the point at infinity
    return point;
}

void free_point(point_t *point){
    BN_free(point->x); BN_free(point->y);
    free(point);
}
/*
 * Hashed Key Derivation Function
 *
 * Definition: produces a 128 bit key
 *
 * Parameters:
 *
 * salt: random number
 *
 * ikm: (input key material) this is the shared secret
 * we generate from Diffie Hellman
 *
 */
int hkdf(unsigned char *key, long salt, BIGNUM *ikm) {

    EVP_MD_CTX *ctx = EVP_MD_CTX_create();

    EVP_MD_CTX_init(ctx);

    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
        fprintf(stderr, "Error initializing hash\n");

        // free before returning
        EVP_MD_CTX_free(ctx);

        return EXIT_FAILURE;
    }

    int ikm_num_bytes = BN_num_bytes(ikm);

    if (!EVP_DigestUpdate(ctx, ikm, ikm_num_bytes)) {
        fprintf(stderr, "Error hashing ikm\n");

        // free before returning
        EVP_MD_CTX_free(ctx);

        return EXIT_FAILURE;
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    if (!EVP_DigestFinal_ex(ctx, hash, &hash_len)) {
        fprintf(stderr, "Error retreiving hash\n");
        
        // free before returning
        EVP_MD_CTX_free(ctx);

        return EXIT_FAILURE;
    }

    //fprintf(stdout, "Hash: %s\n", hash);

    fprintf(stdout, "Hash: ");
    for (int i = 0; i < hash_len; i ++) {
        fprintf(stdout, "%02x", hash[i]);
    }
    fprintf(stdout, "\n");

    memcpy(key, hash, hash_len);

    // free before returning
    EVP_MD_CTX_free(ctx);

    return EXIT_SUCCESS;
}

static point_t* point_addition(point_t *r, point_t *q, BIGNUM *bn_p, BIGNUM *bn_a) {

    point_t *result = point_new();

    if (result == NULL) {
        fprintf(stderr, "Could not malloc new point\n");
        free_point(result);
	    return NULL;
    }

    // first check if they are the "zero" points
    if(r->is_infinity == 1) {
    	result = q;
	    return result;
    }

    if(q->is_infinity == 1) {
	    result = r;
    	return result;
    }

    // now test that whether the points are inverses
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *test_y = BN_new();

    if (!BN_mod_add(test_y, r->y, q->y, bn_p, ctx)) {
    	fprintf(stderr, "Cannot add y vals\n");
	    free_point(result); BN_CTX_free(ctx); BN_free(test_y);
	    return NULL;
    }

    if (BN_cmp(r->x, q->x) == 0 && BN_is_zero(test_y)) {
        // we have inverses of each other, so store the point as a point at infinity
        result->is_infinity = 1; // mark this true, we should check if its infinity before other calculations
    	BN_free(test_y); BN_CTX_free(ctx);
	    return result;
    }

    BN_free(test_y);

    // prepare to calculate slope in any case
    BIGNUM *slope = BN_new();

    // check if the points are the same
    if (BN_cmp(r->x, q->x) == 0 && BN_cmp(r->y, q->y) == 0) {    

        // first, consider that y is 0
	    if (BN_is_zero(r->y)) {
	        result->is_infinity = 1;
	        BN_free(slope); BN_CTX_free(ctx);
	        return result;	
	    }

        BIGNUM *rx_squared = BN_new(); // free this

        // square r->x
        if (!BN_mod_mul(rx_squared, r->x, r->x, bn_p, ctx)) {
            fprintf(stderr, "Could not square x\n");
	        BN_free(slope); BN_CTX_free(ctx); BN_free(rx_squared); free_point(result);
	        return NULL;
        }

        // multiply (r->x)^2 by 3
        BIGNUM *rx_sqr_mul = BN_new(); // free this
	    BIGNUM *bn_3 = BN_new();
	    BN_dec2bn(&bn_3, "3");

        if (!BN_mod_mul(rx_sqr_mul, rx_squared, bn_3, bn_p, ctx)) {
	        fprintf(stderr, "Could not multiply 3 and rx^2.\n");
	        BN_free(slope); BN_CTX_free(ctx); BN_free(bn_3); BN_free(rx_squared);
	        BN_free(rx_sqr_mul); free_point(result);
	        return NULL;
	    }

        BN_free(bn_3); BN_free(rx_squared);	

	    // continue by adding a
	    BIGNUM *numerator = BN_new(); 
	    if (!BN_mod_add(numerator, rx_sqr_mul, bn_a, bn_p, ctx)) {
	        fprintf(stderr, "Could not add for numerator\n");
	        BN_free(numerator); BN_free(slope); BN_free(rx_sqr_mul); BN_free(slope); BN_CTX_free(ctx); free_point(result);
	        return NULL;
	    }
	    
        BN_free(rx_sqr_mul);

	    BIGNUM *denominator = BN_new();
	    BIGNUM *denom_inv = BN_new();
	    BIGNUM *bn_2 = BN_new();
	    BN_dec2bn(&bn_2, "2");

	    if (!BN_mod_mul(denominator, r->y, bn_2, bn_p, ctx)) {
	        fprintf(stderr, "Could not multiply denominator\n");
	        BN_free(slope); BN_free(denominator); BN_free(denom_inv); BN_free(bn_2); BN_CTX_free(ctx); BN_free(numerator); free_point(result);
	        return NULL;
	    }
	    
        BN_free(bn_2);

	    // now calculate the inverse and finish with the product
	    if (!BN_mod_inverse(denom_inv, denominator, bn_p, ctx)) {
	        fprintf(stderr, "Could not calculate denominator inverse\n");
	        BN_free(slope); BN_free(denominator); BN_free(denom_inv); BN_CTX_free(ctx); BN_free(numerator); free_point(result);
	        return NULL;
	    }
	    
        BN_free(denominator);

	    if (!BN_mod_mul(slope, numerator, denom_inv, bn_p, ctx)) {
	        fprintf(stderr, "Could not multiply to find the slope for adding two points.\n");
	        BN_free(slope); BN_free(numerator); BN_free(denom_inv); BN_CTX_free(ctx); free_point(result);
	        return NULL;
	    }
	    
        BN_free(denom_inv); BN_free(numerator); // finish cleaning 
	}
    else {
        // adding points that are different and NOT points at infinity
	    BIGNUM *x_slope = BN_new();
    	BIGNUM *y_slope = BN_new();
    	BIGNUM *x_slope_inv = BN_new();

        //(r->y - q->y) / (r->x - q->x);
        if (BN_mod_sub(x_slope, r->x, q->x, bn_p, ctx) == 0) {
            fprintf(stderr, "Could not calculate x_slope\n");
	        BN_free(slope); BN_free(y_slope); BN_free(x_slope); BN_free(x_slope_inv); BN_CTX_free(ctx); free_point(result);
            return NULL;
        }

        if (BN_mod_sub(y_slope, r->y, q->y, bn_p, ctx) == 0) {
            fprintf(stderr, "Could not calculate y_slope\n");
	        BN_free(slope); BN_free(y_slope); BN_free(x_slope); BN_free(x_slope_inv); BN_CTX_free(ctx); free_point(result);
            return NULL;
        }

        if (BN_mod_inverse(x_slope_inv, x_slope, bn_p, ctx) == NULL) {
            // get the error code
            unsigned long err_code = ERR_get_error();

            // print out the code in human-readable way
            fprintf(stderr, "%s\n", ERR_error_string(err_code, NULL));

            fprintf(stderr, "Could not caculate y slope inverse\n");
	        BN_free(slope); BN_free(y_slope); BN_free(x_slope); BN_free(x_slope_inv); BN_CTX_free(ctx); free_point(result);
            return NULL;
        }
	    
        BN_free(x_slope);

        if (BN_mod_mul(slope, y_slope, x_slope_inv, bn_p, ctx) == 0) {
            fprintf(stderr, "Could not calculate slope\n");
            BN_free(slope); BN_free(y_slope); BN_free(x_slope_inv); BN_CTX_free(ctx); free_point(result);
	        return NULL;
        }

	    BN_free(y_slope); BN_free(x_slope_inv);
    }

    // (slope)^2 - x_two - x_one
    BIGNUM *slope_2 = BN_new();
    BIGNUM *x_sum = BN_new();
    BIGNUM *new_x = BN_new();

    if (BN_mod_add(x_sum, r->x, q->x, bn_p, ctx) == 0) { // crucial mistake, do not subtract here
    	fprintf(stderr, "Could not subtract xs\n");
	    free_point(result); BN_free(slope); BN_free(x_sum); BN_CTX_free(ctx); BN_free(new_x); BN_free(slope_2);
	    return NULL;
    }

    if (BN_mod_mul(slope_2, slope, slope, bn_p, ctx) == 0 || BN_mod_sub(new_x, slope_2, x_sum, bn_p, ctx) == 0){
	    fprintf(stderr, "Could not calculate new x\n");
	    BN_free(new_x);
	    BN_free(slope_2); BN_free(slope); BN_free(x_sum); BN_CTX_free(ctx);
	    return NULL;
    }

    // slope(x_two - new_x) - y_one -> bug here, it uses the x result
    BIGNUM *new_xdiff = BN_new();

    if (!BN_mod_sub(new_xdiff, r->x, new_x, bn_p, ctx)) {
    	fprintf(stderr, "Could not subtract new x and old x\n");
	    BN_free(new_x); 
        BN_free(slope_2); BN_free(slope); BN_free(new_xdiff); BN_free(x_sum); BN_CTX_free(ctx);
	    return NULL;
    }

    BIGNUM *slope_xdiff = BN_new();
    BIGNUM *new_y = BN_new();

    if (BN_mod_mul(slope_xdiff, slope, new_xdiff, bn_p, ctx) == 0 || BN_mod_sub(new_y, slope_xdiff, r->y, bn_p, ctx) == 0) {
    	fprintf(stderr, "Could not calculate new y\n");
	    BN_free(new_x); BN_free(new_y); BN_free(slope_xdiff);
	    BN_free(slope_2); BN_free(slope); BN_free(new_xdiff); BN_free(x_sum); BN_CTX_free(ctx);
	    return NULL;
    }

    result->x = new_x;
    result->y = new_y;
    result->is_infinity = 0;
    BN_free(slope_xdiff); BN_free(slope_2); BN_free(slope); BN_free(new_xdiff); BN_free(x_sum); BN_CTX_free(ctx);
   
    return result;
}

// the segfault inducer 
static point_t *point_multiplication(point_t *r, BIGNUM *sec, BIGNUM *bn_p, BIGNUM *bn_a){

    // to multiply efficiently, do 2 * r, if most-sig bit is 1, add r, if not, add 0, save current result and continue
    int numbits = BN_num_bits(sec);

    point_t *result = point_new();

    // set the infinity to yes for now
    result->is_infinity = 1;

    for (int i = numbits - 1; i >= 0; i --) {

	    // from serious crypto: point is multiplied by 2 on each step regardless
	    point_t *mult_2 = point_addition(result, result, bn_p, bn_a);

        // free the current result and store it
	    if (mult_2 == NULL) {
            fprintf(stderr, "Error in addition\n");
            free_point(result); free_point(mult_2);
		    return NULL;
        }

	    result = mult_2;

	    // now check if the extra step of adding P in is needed 
	    if (BN_is_bit_set(sec, i) == 1) {
            point_t *add_r = point_addition(result, r, bn_p, bn_a);
	        result = add_r;
        }
    }

    return result;
}

/*
 * Main implementation of ECDHKE
 *
 * */
int main() {

    // transfer the strings into bignum parameters
    BIGNUM *bn_p = BN_new();
    BIGNUM *bn_a = BN_new();
    BIGNUM *bn_b = BN_new();
    BIGNUM *bn_Gx = BN_new();
    BIGNUM *bn_Gy = BN_new();
    BIGNUM *bn_n = BN_new();
    
    // BN_dec2bn: takes in a string representation of a decimal number and makes it a bignum 
    BN_dec2bn(&bn_p, p);
    BN_dec2bn(&bn_a, a);
    BN_dec2bn(&bn_b, b);
    BN_dec2bn(&bn_Gx, Gx);
    BN_dec2bn(&bn_Gy, Gy);
    BN_dec2bn(&bn_n, n);

    // print p
    fprintf(stdout, "p: ");

    if (BN_print_fp(stdout, bn_p) == 0) {
        fprintf(stderr, "Could not print out bignum\n");
        return EXIT_FAILURE;
    }

    fprintf(stdout, "\n");

    // print a
    fprintf(stdout, "a: ");

    if (BN_print_fp(stdout, bn_a) == 0) {
        fprintf(stderr, "Could not print out bignum\n");
        return EXIT_FAILURE;
    }

    fprintf(stdout, "\n");

    // print b
    fprintf(stdout, "b: ");

    if (BN_print_fp(stdout, bn_b) == 0) {
        fprintf(stderr, "Could not print out bignum\n");
        return EXIT_FAILURE;
    }

    fprintf(stdout, "\n");

    // print Gx
    fprintf(stdout, "Gx: ");

    if (BN_print_fp(stdout, bn_Gx) == 0) {
        fprintf(stderr, "Could not print out bignum\n");
        return EXIT_FAILURE;
    }

    fprintf(stdout, "\n");
    
    // print Gy
    fprintf(stdout, "Gy: ");

    if (BN_print_fp(stdout, bn_Gy) == 0) {
        fprintf(stderr, "Could not print out bignum\n");
        return EXIT_FAILURE;
    }

    fprintf(stdout, "\n");

    // print n
    fprintf(stdout, "n: ");

    if (BN_print_fp(stdout, bn_n) == 0) {
        fprintf(stderr, "Could not print out bignum\n");
        return EXIT_FAILURE;
    }

    fprintf(stdout, "\n\n");
    
    // create struct for initial point
    point_t *gx_gy = point_new();

    if (gx_gy == NULL){
    	fprintf(stderr, "Could not malloc for point\n");
	    return EXIT_FAILURE;
    }
    // store gx and gy as a point
    gx_gy->x = bn_Gx; gx_gy->y = bn_Gy;


    // begin calculations 
    BIGNUM *a_sec = BN_new();
    BIGNUM *b_sec = BN_new();
	
    
    if(BN_rand_range(a_sec, bn_n) == 0 || BN_rand_range(b_sec, bn_n) == 0){
        fprintf(stderr, "Could not generate rand\n");
	    return EXIT_FAILURE;
    }

    // print a's secret
    fprintf(stdout, "a's secret: ");

    if(BN_print_fp(stdout, a_sec) == 0){
    	fprintf(stderr, "Could not print out bignum\n");
        return EXIT_FAILURE;
    }
    fprintf(stdout, "\n");

    // print b's secret
    fprintf(stdout, "b's secret: ");

    if(BN_print_fp(stdout, b_sec) == 0){
        fprintf(stderr, "Could not print out bignum\n");
        return EXIT_FAILURE;
    }
    fprintf(stdout, "\n");
    
    // calculate alice and bob's keys
    point_t *a_key = point_multiplication(gx_gy, a_sec, bn_p, bn_a);
    if(a_key == NULL){
    	fprintf(stderr, "Point multiplication did not work\n");
	    return EXIT_FAILURE;    
    }

    point_t *b_key = point_multiplication(gx_gy, b_sec, bn_p, bn_a);
    if(b_key == NULL){
    	fprintf(stderr, "Point multiplication did not work\n");
	    return EXIT_FAILURE;  	
    }
    
    // calculate their shared secret, and then check that the calculations work 
    point_t *shared_sec = point_multiplication(b_key, a_sec, bn_p, bn_a); 
    if(shared_sec == NULL){
    	fprintf(stderr, "Point multiplication did not work\n");
        return EXIT_FAILURE;
    }

    // print shared secret
    fprintf(stdout, "Shared secret: ");

    if(BN_print_fp(stdout, shared_sec->x) == 0){
        fprintf(stderr, "Could not print out bignum\n");
        return EXIT_FAILURE;
    }

    fprintf(stdout, "\n");

    // now check that bob's calculation of shared x equals what alice calculated for sec
    point_t *check = point_multiplication(a_key, b_sec, bn_p, bn_a);
    if(check == NULL){
    	fprintf(stderr, "Point multiplication did not work\n");
        return EXIT_FAILURE;
    }


    if(BN_cmp(shared_sec->x, check->x) == 0 && BN_cmp(shared_sec->y, check->y) == 0){
        fprintf(stdout, "Shared secrets are the same!\n");
    }

    FILE* fp = fopen("key.txt", "w");
    if (fp == NULL) {
    	fprintf(stderr, "Error opening file for writing\n");
	return EXIT_FAILURE;
    }

    // key derivation
    long salt = 0;
    unsigned char key[EVP_MAX_MD_SIZE];
    
    if (hkdf(key, salt, shared_sec->x) == EXIT_FAILURE) {
        fprintf(stderr, "Error deriving key\n");
        return EXIT_FAILURE;
    }

    // free openssl variables
    BN_free(bn_p); BN_free(bn_a); BN_free(bn_b); BN_free(bn_n);
    BN_free(a_sec); BN_free(b_sec); free_point(check); free_point(b_key); free_point(a_key); free_point(shared_sec);

    fprintf(fp, "%s", key);
    fclose(fp);
    
    return EXIT_SUCCESS;
    
}

