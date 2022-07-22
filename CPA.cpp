#include <iostream>
#include <string>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <malloc.h>
#include <random>

typedef unsigned char U8;
typedef unsigned int U32;

using namespace std;

int BN_xor(BIGNUM *b_r, int bits, const BIGNUM *b_a, const BIGNUM *b_b)
{
	//error
	if(b_r==NULL || b_a == NULL || b_b == NULL) 
		return 0;
	//bytes = bits / 8
	int i, bytes = bits >> 3;
	//calloc for type casting(BIGNUM to U8)
	U8 *r = (U8*)calloc(bytes,sizeof(U8));
	U8 *a = (U8*)calloc(bytes,sizeof(U8));
	U8 *b = (U8*)calloc(bytes,sizeof(U8));
	//BN_num_bytes(a) : return a's bytes 
	int byte_a = BN_num_bytes(b_a);
	int byte_b = BN_num_bytes(b_b);
	//difference between A and B
	int dif = abs(byte_a-byte_b);
	//minimum
	int byte_min = (byte_a < byte_b)? byte_a : byte_b;
	//type casting(BIGNUM to U8)
	BN_bn2bin(b_a,a);
	BN_bn2bin(b_b,b);
	//xor compute
	for(i=1;i<=byte_min;i++)
		r[bytes - i] = a[byte_a - i] ^ b[byte_b - i];
	for(i=1;i<=dif;i++)
		r[bytes - byte_min - i] = (byte_a>byte_b)? a[dif-i] : b[dif-i];
	//type casting(U8 to BIGNUM)
	BN_bin2bn(r,bytes,b_r);
	//Free memory
	free(a);
	free(b);
	free(r);
	return 1;//correct
} 

class CPA {
    uint bitsize = 128; // 128 로 고정
    uint byteSize = 16;
    AES_KEY encKey;
    AES_KEY decKey;

    int Gen(){
        // TODO
        unsigned char user_key[byteSize];
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<int> dis(0, 256);
        for (int i=0 ; i<byteSize; i++)
            user_key[i] = dis(gen) & 0xff;
        return AES_set_encrypt_key(user_key, (int)bitsize, &encKey);
    }

public:
    CPA(){
        Gen();
    }
    
    U8** Enc(U8* msg){
        int i;
	    U8 **c = (U8 **)calloc(2, sizeof(U8*)); // C = [r, F_k(r)]
	    for (i = 0; i < 2; i++)
		    c[i] = (U8 *)calloc(byteSize, sizeof(U8)); // 16 bytes cipher text
        // TODO
        BIGNUM *Fkr_BN = BN_new();
        BIGNUM *msg_BN = BN_new();
        BIGNUM *c2_BN = BN_new();

        // c1 = r
        unsigned char r[byteSize];
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<int> dis(0, 256); 
        for (int i=0 ; i<byteSize; i++){
            c[0][i] = dis(gen) & 0xff;
        }

        // c2 = F_{k}(r) XOR m
        unsigned char *Fkr;
        Fkr = (U8 *)calloc(byteSize, sizeof(U8));
        AES_encrypt(c[0], Fkr, &encKey);
        BN_bin2bn(Fkr, 16, Fkr_BN); // Fkr to BN
        BN_bin2bn(msg, 16, msg_BN); // msg to BN
        BN_xor(c2_BN, 128, Fkr_BN, msg_BN); // // c2 = F_k(r) XOR msg

        cout << "r\t: ";
        for(int i=0 ; i<16; i++)
            cout << hex << (int)c[0][i];
        cout << endl;
        cout << "Fkr\t: ";
        for(int i=0 ; i<16; i++)
            cout << hex << (int)Fkr[i];
        cout << endl;

        BN_bn2bin(c2_BN, c[1]);
        return c;
    }

    U8* Dec(U8** c){
	    U8 *M = (U8*)calloc(byteSize, sizeof(U8));

		// TODO
        BIGNUM *Fkc_BN = BN_new();
        BIGNUM *c2_BN = BN_new();
        BIGNUM *pt_BN = BN_new();

        // Fkc
        unsigned char *Fkc;
        Fkc = (U8 *)calloc(byteSize, sizeof(U8));
        AES_encrypt(c[0], Fkc, &encKey);

        cout << endl << "Fkc\t: ";
        for(int i=0 ; i<16; i++)
            cout << hex << (int)Fkc[i];
        cout << endl;

        BN_bin2bn(Fkc, 16, Fkc_BN); // Fkc to BN
        BN_bin2bn(c[1], 16, c2_BN); // c2 to BN
        BN_xor(pt_BN, 128, Fkc_BN, c2_BN); // // c2 = F_k(r) XOR msg

        BN_bn2bin(pt_BN, M);
        return M;
    } 
};

int main(){
    U8 msg[16] = "CPA-secure";
    CPA cpa = CPA();

    cout << "msg\t: " << msg << endl;

    U8** enc = cpa.Enc(msg);

    cout << "C1\t: ";
    for(int i=0 ; i<16; i++)
        cout << hex << (int)enc[0][i];

    cout << endl << "C2\t: ";
    for(int i=0 ; i<16; i++)
        cout << hex << (int)enc[1][i];
    
    U8* dec = cpa.Dec(enc);
    cout << "dec\t: ";
    for(int i=0; i<16 ;i++)
        cout << dec[i];
    cout << endl;

    return 0;
}