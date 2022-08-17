#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <math.h>
#include <ctype.h>
#include <iostream>
#include <cstring>

using namespace std;

void BN_scanf(BIGNUM *input)
/*given input to BN */
{
	int x;
	scanf("%d", &x);
	BN_set_word(input, x);
}

void BN_printf(const BIGNUM *input)
{
    cout << BN_bn2dec(input) << endl;
}

BIGNUM* BN_Square_Multi(BIGNUM *x, BIGNUM *a, BIGNUM *n) // x^(a) mod n = ? 
{
	BIGNUM *z; 
	z = BN_new();
	BN_set_word(z, 1);
	
	BN_CTX *ctx = BN_CTX_new();
	for (int i = BN_num_bits(a)-1; i >= 0 ; i--){
		BN_mod_mul(z, z, z, n, ctx); // z = z^2 mod n
		if (BN_is_bit_set(a, i) == 1){ // BN_is_bit_set(~)
			BN_mod_mul(z, z, x, n, ctx);
		}
	}

	return z;
}
int main(int argc, char* argv[]) {
	BIGNUM *x, *a, *n, *result;
	x = BN_new(); a = BN_new(); n = BN_new();
	cout << "FAST Exponentiation (Square and Multiply)" << endl;
	cout << "////////////  x^(a) mod n = ?   /////////////////" << endl;
	printf("x : "); BN_scanf(x);
	printf("a : "); BN_scanf(a);
	printf("n : "); BN_scanf(n);
	result = BN_Square_Multi(x, a, n);
	cout << "result = "; BN_printf(result); cout << endl;
	BN_free(x); BN_free(a); BN_free(n); BN_free(result);
	return 0;
}