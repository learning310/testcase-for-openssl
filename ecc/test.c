#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <stdio.h>

void handle_errors()
{
	ERR_print_errors_fp(stderr);
	abort();
}

// Function to print EC_POINT in affine coordinates (x, y)
void print_ec_point(const EC_GROUP *curve, const EC_POINT *point)
{
	BN_CTX *ctx = BN_CTX_new(); // Context to hold temporary variables
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();

	if (!EC_POINT_get_affine_coordinates(curve, point, x, y, ctx)) {
		handle_errors();
	}

	char *x_str = BN_bn2hex(x);
	char *y_str = BN_bn2hex(y);
	printf("x: %s\n", x_str);
	printf("y: %s\n", y_str);

	OPENSSL_free(x_str);
	OPENSSL_free(y_str);
	BN_free(x);
	BN_free(y);
	BN_CTX_free(ctx);
}

int main()
{
	// Initialize OpenSSL
	ERR_load_crypto_strings();
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

	// 1. Create an elliptic curve group object, by using the P-256 curve
	EC_GROUP *curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if (!curve)
		handle_errors();

	// 2. Define a scalar and curve points
	EC_POINT *P = EC_POINT_new(curve);
	EC_POINT *Q = EC_POINT_new(curve);
	EC_POINT *R = EC_POINT_new(curve);
	BIGNUM *k = BN_new();

	// 3. Set fixed scalar and point
	BN_hex2bn(&k, "2");
	if (!EC_POINT_copy(P, EC_GROUP_get0_generator(curve)))
		handle_errors();

	// Print scalar k
	printf("Scalar k: ");
	BN_print_fp(stdout, k);
	printf("\n");
	printf("Generator Point P:\n");
	print_ec_point(curve, P); // Print coordinates of point Q

	// 4. Perform scalar multiplication Q = k * P
	if (!EC_POINT_mul(curve, Q, NULL, P, k, NULL))
		handle_errors();

	printf("Scalar multiplication result Q = k * P:\n");
	print_ec_point(curve, Q); // Print coordinates of point Q

	// 5. Perform point addition R = P + Q
	if (!EC_POINT_add(curve, R, P, Q, NULL))
		handle_errors();

	printf("Point addition result R = P + Q:\n");
	print_ec_point(curve, R); // Print coordinates of point R

	// 6. Clean up
	EC_POINT_free(P);
	EC_POINT_free(Q);
	EC_POINT_free(R);
	BN_free(k);
	EC_GROUP_free(curve);

	// Clean up OpenSSL resources
	ERR_free_strings();

	return 0;
}
