#include <stdio.h>
#include <bitset>
#include <iostream>
#include <string>
#include <openssl/bn.h>

using namespace std;

// https://www.openssl.org/docs/man1.0.2/man3/bn.html
int main(void) {
	BIGNUM *a = BN_new(); // bignum 선언
	BIGNUM *b = BN_new();
	BIGNUM *r = BN_new();
	
	BN_set_word(a, 1023);
	BN_set_word(b, 128);

    string a_hex = BN_bn2hex(a);
    string b_dec = BN_bn2dec(b);
    cout << "a as hex : " << a_hex << endl;
    cout << "b as dec : " << b_dec << endl;
	
	cout << "a to binary ... ";
	unsigned char *bin = (unsigned char*)calloc(16, sizeof(unsigned char));
	int len = BN_bn2bin(a, bin);

	for(int i=0; i<len; i++) {
		cout << hex << (uint)bin[i];
	}
	cout << endl;	

	BN_add(r, a, b);
	cout <<"a+b : "<< BN_bn2dec(r) << endl;

	BN_sub(r, a, b);
	cout << "a-b : "<< BN_bn2dec(r) << endl;

	
	BN_free(a);
	BN_free(b);	
	BN_free(r);
	
	return 0;
}