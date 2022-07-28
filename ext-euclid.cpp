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

using namespace std;

void BN_scanf(BIGNUM *input) {
	int x;
	scanf("%d", &x);
	BN_set_word(input, x);
}

void BN_printf(const BIGNUM *input) {
	char *c = BN_bn2dec(input);
	printf("%s ", c);
}

class BN_dxy{
public:
    BIGNUM *d;
	BIGNUM *x;
	BIGNUM *y;

    BN_dxy(const BIGNUM *d, const BIGNUM *x, const BIGNUM *y){
        this->d = BN_new(); this->x = BN_new(); this->y = BN_new();
        // if(d == NULL) return dxy;
        BN_copy(this->d, d);
        BN_copy(this->x, x);
        BN_copy(this->y, y);
    }
    // void BN_copy(BIGNUM *d, BIGNUM *x, BIGNUM *y){
    //     BN_copy(this->d, d);
	//     BN_copy(this->x, x);
	//     BN_copy(this->y, y);
    // }
    // ~BN_dxy(){
    //     BN_free(this->d);
	//     BN_free(this->x);
	//     BN_free(this->y);
    // }
    
    void Print(){
        cout << "d : " << BN_bn2dec(this->d) << endl;
        cout << "x : " << BN_bn2dec(this->x) << endl;
        cout << "y : " << BN_bn2dec(this->y) << endl;
    }
};



BN_dxy BN_Ext_Euclid(BIGNUM* a, BIGNUM* b) {
	BN_CTX *ctx = BN_CTX_new();
	
	if (BN_is_zero(b)) {
		BN_dxy dxy = BN_dxy(a, BN_value_one(), b);
		return dxy;
	}
	else {
		/* your code here */
		BIGNUM *tmp1 = BN_new(); BIGNUM *tmp2 = BN_new();
		BN_mod(tmp1, a, b, ctx); // tmp = a mod b
		BN_dxy _dxy = BN_Ext_Euclid(b, tmp1); // Ext-Euclid(b, a mod b)
		BN_div(tmp2, NULL, a, b, ctx); // (a/b)
		BN_mul(tmp2, tmp2, _dxy.y, ctx); // (a/b)*y'
		BN_sub(tmp2, _dxy.x, tmp2); // x - (a/b)y'
		BN_dxy dxy = BN_dxy(_dxy.d, _dxy.y, tmp2);
		return dxy;
	}
}

int main(int argc, char* argv[]) {
	BIGNUM *a, *b;
	a = BN_new(); b = BN_new();
	printf("a: "); BN_scanf(a);
	printf("b: "); BN_scanf(b);
	BN_dxy dxy = BN_Ext_Euclid(a, b);
	cout << "====== result ======" << endl;
    dxy.Print();
	return 0;
}