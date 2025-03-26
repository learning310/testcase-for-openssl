#include <stdio.h>
#include <openssl/bn.h>

void montgomery_modexp(const BIGNUM *base, const BIGNUM *exponent,
		       const BIGNUM *modulus, BIGNUM *result)
{
	BN_CTX *ctx = BN_CTX_new();
	BN_MONT_CTX *mont_ctx = BN_MONT_CTX_new();

	BN_MONT_CTX_set(mont_ctx, modulus, ctx);

	BIGNUM *base_mont = BN_new();
	BIGNUM *temp = BN_new();
	BIGNUM *one = BN_new();

	BN_one(one);
	BN_to_montgomery(base_mont, base, mont_ctx, ctx);
	BN_to_montgomery(temp, one, mont_ctx, ctx);

	for (int i = BN_num_bits(exponent) - 1; i >= 0; i--) {
		BN_mod_mul_montgomery(temp, temp, temp, mont_ctx, ctx);
		if (BN_is_bit_set(exponent, i)) {
			BN_mod_mul_montgomery(temp, temp, base_mont, mont_ctx,
					      ctx);
		}
	}

	BN_from_montgomery(result, temp, mont_ctx, ctx);

	BN_free(base_mont);
	BN_free(temp);
	BN_free(one);
	BN_MONT_CTX_free(mont_ctx);
	BN_CTX_free(ctx);
}

void print_result(const char *label, const BIGNUM *result)
{
	char *result_str = BN_bn2hex(result);
	printf("%s: %s\n", label, result_str);
	OPENSSL_free(result_str);
}

void run_example(const char *base_str, const char *exponent_str,
		 const char *modulus_str, const char *label)
{
	BIGNUM *base = BN_new();
	BIGNUM *exponent = BN_new();
	BIGNUM *modulus = BN_new();
	BIGNUM *result = BN_new();

	BN_hex2bn(&base, base_str);
	BN_hex2bn(&exponent, exponent_str);
	BN_hex2bn(&modulus, modulus_str);

	montgomery_modexp(base, exponent, modulus, result);

	print_result(label, result);

	BN_free(base);
	BN_free(exponent);
	BN_free(modulus);
	BN_free(result);
}

int main()
{
	run_example("17", "175", "2EB", "small number");
	run_example(
		"61626364656667686162636465666768616263646566676861626364656667686162636465666768616263646566676861626364656667686162636465666768",
		"10001",
		"E90955D92163EB6BB6DC2CA5445A4F22186DA69CF9991D660F6A53DE7630F21A075853E1CB81D951347449E2577F180278472866E10A73D540D88386DC5DFE5F",
		"Big Number");

	return 0;
}