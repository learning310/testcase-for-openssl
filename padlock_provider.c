#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/sha.h>

struct provctx_st {
	OSSL_LIB_CTX *libctx;
};

static OSSL_FUNC_digest_newctx_fn padlock_newctx;
static void *padlock_newctx(void *provctx)
{
	SHA256_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
	return ctx;
}

static OSSL_FUNC_digest_freectx_fn padlock_freectx;
static void padlock_freectx(void *bctx)
{
	SHA256_CTX *ctx = bctx;
	OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static OSSL_FUNC_digest_dupctx_fn padlock_dupctx;
static void *padlock_dupctx(void *bctx)
{
	SHA256_CTX *in = bctx;
	SHA256_CTX *ret = OPENSSL_zalloc(sizeof(*ret));
	if (ret != NULL)
		*ret = *in;
	return ret;
}

static OSSL_FUNC_digest_init_fn padlock_init;
static int padlock_init(void *bctx, const OSSL_PARAM *params)
{
	SHA256_CTX *c = bctx;
	memset(c, 0, sizeof(*c));
	c->h[0] = 0x6a09e667UL;
	c->h[1] = 0xbb67ae85UL;
	c->h[2] = 0x3c6ef372UL;
	c->h[3] = 0xa54ff53aUL;
	c->h[4] = 0x510e527fUL;
	c->h[5] = 0x9b05688cUL;
	c->h[6] = 0x1f83d9abUL;
	c->h[7] = 0x5be0cd19UL;
	c->md_len = SHA256_DIGEST_LENGTH;
	return 1;
}

void padlock_sha256_blocks(void *ctx, const void *inp, size_t len)
{
	asm volatile(
		"mov %[ctx], %%rdx           \n\t"
		"mov %%rdx, %%rcx            \n\t"
		"mov %[ctx], %%rdi           \n\t"
		"movups (%[ctx]), %%xmm0     \n\t"
		"sub $128+8, %%rsp           \n\t"
		"movups 16(%[ctx]), %%xmm1   \n\t"
		"movaps %%xmm0, (%%rsp)      \n\t"
		"mov %%rsp, %%rdi            \n\t"
		"movaps %%xmm1, 16(%%rsp)    \n\t"
		"mov $-1, %%rax              \n\t"
		".byte 0xf3, 0x0f, 0xa6, 0xd0 \n\t"
		"movaps (%%rsp), %%xmm0      \n\t"
		"movaps 16(%%rsp), %%xmm1    \n\t"
		"add $128+8, %%rsp           \n\t"
		"movups %%xmm0, (%[ctx])     \n\t"
		"movups %%xmm1, 16(%[ctx])   \n\t"
		:
		: [ctx] "r"(ctx)
		: "rax", "rcx", "rdx", "rdi", "xmm0", "xmm1", "memory");
}

static OSSL_FUNC_digest_update_fn padlock_update;
static int padlock_update(void *bctx, const unsigned char *data_, size_t len)
{
	SHA256_CTX *c = bctx;
	const unsigned char *data = data_;
	unsigned char *p;
	SHA_LONG l;
	size_t n;

	if (len == 0)
		return 1;

	l = (c->Nl + (((SHA_LONG)len) << 3)) & 0xffffffffUL;
	if (l < c->Nl) /* overflow */
		c->Nh++;
	c->Nh += (SHA_LONG)(len >> 29); /* might cause compiler warning on
                                       * 16-bit */
	c->Nl = l;

	n = c->num;
	if (n != 0) {
		p = (unsigned char *)c->data;

		if (len >= SHA256_CBLOCK || len + n >= SHA256_CBLOCK) {
			memcpy(p + n, data, SHA256_CBLOCK - n);
			padlock_sha256_blocks(c->h, p, 1);
			n = SHA256_CBLOCK - n;
			data += n;
			len -= n;
			c->num = 0;
			/*
             * We use memset rather than OPENSSL_cleanse() here deliberately.
             * Using OPENSSL_cleanse() here could be a performance issue. It
             * will get properly cleansed on finalisation so this isn't a
             * security problem.
             */
			memset(p, 0, SHA256_CBLOCK); /* keep it zeroed */
		} else {
			memcpy(p + n, data, len);
			c->num += (unsigned int)len;
			return 1;
		}
	}

	n = len / SHA256_CBLOCK;
	if (n > 0) {
		padlock_sha256_blocks(c->h, data, n);
		n *= SHA256_CBLOCK;
		data += n;
		len -= n;
	}

	if (len != 0) {
		p = (unsigned char *)c->data;
		c->num = (unsigned int)len;
		memcpy(p, data, len);
	}
	return 1;
}

#define HOST_l2c(l, c)                               \
	({                                           \
		unsigned int r = (l);                \
		asm("bswapl %0" : "=r"(r) : "0"(r)); \
		*((unsigned int *)(c)) = r;          \
		(c) += 4;                            \
		r;                                   \
	})

static OSSL_FUNC_digest_final_fn padlock_final;
static int padlock_final(void *bctx, unsigned char *out, size_t *outl,
			 size_t outsz)
{
	if (outsz < SHA256_DIGEST_LENGTH) {
		return 0;
	}

	SHA256_CTX *c = bctx;
	unsigned char *p = (unsigned char *)c->data;
	size_t n = c->num;

	p[n] = 0x80; /* there is always room for one */
	n++;

	if (n > (SHA256_CBLOCK - 8)) {
		memset(p + n, 0, SHA256_CBLOCK - n);
		n = 0;
		padlock_sha256_blocks(c->h, p, 1);
	}
	memset(p + n, 0, SHA256_CBLOCK - 8 - n);

	p += SHA256_CBLOCK - 8;

	(void)HOST_l2c(c->Nh, p);
	(void)HOST_l2c(c->Nl, p);

	p -= SHA256_CBLOCK;
	padlock_sha256_blocks(c->h, p, 1);
	c->num = 0;
	memset(p, 0, SHA256_CBLOCK);
	memcpy(out, c->h, c->md_len);

	return 1;
}

#define PROV_DIGEST_FLAG_XOF 0x0001
#define PROV_DIGEST_FLAG_ALGID_ABSENT 0x0002
#define SHA2_FLAGS PROV_DIGEST_FLAG_ALGID_ABSENT
static OSSL_FUNC_digest_get_params_fn padlock_get_params;
static int padlock_get_params(OSSL_PARAM *params)
{
	OSSL_PARAM *p = NULL;

	p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, SHA256_CBLOCK)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, SHA256_DIGEST_LENGTH)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF);
	if (p != NULL &&
	    !OSSL_PARAM_set_int(p, (SHA2_FLAGS & PROV_DIGEST_FLAG_XOF) != 0)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_ALGID_ABSENT);
	if (p != NULL &&
	    !OSSL_PARAM_set_int(p, (SHA2_FLAGS &
				    PROV_DIGEST_FLAG_ALGID_ABSENT) != 0)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}
	return 1;
}

static const OSSL_DISPATCH padlock_sha256_functions[] = {
	{ OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))padlock_newctx },
	{ OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))padlock_freectx },
	{ OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))padlock_dupctx },
	{ OSSL_FUNC_DIGEST_INIT, (void (*)(void))padlock_init },
	{ OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))padlock_update },
	{ OSSL_FUNC_DIGEST_FINAL, (void (*)(void))padlock_final },
	{ OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))padlock_get_params },
	{ 0, NULL }
};

#define PROV_NAMES_SHA2_256 "SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1"
static const OSSL_ALGORITHM padlock_digests[] = {
	{ PROV_NAMES_SHA2_256, "provider=padlock", padlock_sha256_functions,
	  "padlock support for sha256 algorithm" },
	{ NULL, NULL, NULL, NULL }
};

static OSSL_FUNC_provider_query_operation_fn query;
static const OSSL_ALGORITHM *padlock_query(void *provctx, int operation_id,
					   int *no_cache)
{
	*no_cache = 0;
	switch (operation_id) {
	case OSSL_OP_DIGEST:
		return padlock_digests;
	}
	return NULL;
}

static OSSL_FUNC_provider_teardown_fn teardown;
void teardown(void *provctx)
{
	struct provctx_st *pctx = provctx;

	OSSL_LIB_CTX_free(pctx->libctx);
	free(provctx);
}

const OSSL_DISPATCH provfns[] = {
	{ OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))teardown },
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))padlock_query },
	{ 0, NULL },
};

OSSL_provider_init_fn OSSL_provider_init; /* Check function signature */
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
		       const OSSL_DISPATCH **out, void **provctx)
{
	struct provctx_st *pctx = malloc(sizeof(struct provctx_st));

	memset(pctx, 0, sizeof(*pctx));
	*provctx = pctx;
	*out = provfns;

	pctx->libctx = OSSL_LIB_CTX_new_from_dispatch(handle, in);
	if (pctx->libctx == NULL) {
		teardown(*provctx);
		*provctx = NULL;
		return 0;
	}

	return 1;
}