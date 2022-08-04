#include <iostream>
#include <string>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <random>

using namespace std;

typedef unsigned char   u8;
typedef uint32_t        u32; 
typedef uint64_t        u64;


class AES {
    uint bitsize;
    uint byteSize;
    AES_KEY encKey;
    AES_KEY decKey;
    void keyGen(AES_KEY *encKey, AES_KEY *decKey){
        unsigned char user_key[byteSize];
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<int> dis(0, 255);
        for (int i=0 ; i<byteSize; i++)
            user_key[i] = dis(gen) & 0xff;

        cout << "set enc key " << AES_set_encrypt_key(user_key, (int)bitsize, encKey) << endl;
	    AES_set_decrypt_key(user_key, (int)bitsize, decKey);
    }
public:
    // size must be 128, 192, 256 
    AES(uint size){
        this->bitsize = size;
        this->byteSize = (uint)bitsize / 8;
        
        keyGen(&this->encKey, &this->decKey);
    }
    void Enc(unsigned char* m, unsigned char* ct){
        AES_encrypt(m, ct, &encKey);
        return;
    }
    void Dec(unsigned char* ct, unsigned char* m){
        AES_decrypt(ct, m, &decKey);
        return;
    }
};

int main(){
    int bitSize = 256;
    int byteSize= bitSize/8; // 32
    u8 msg[byteSize] = "AES encryption example !";
    u8 ct[16];

    AES aes(bitSize);

    aes.Enc(msg, ct);
    cout << "cipher text : ";
    for (int i=0; i<16; i++)
        cout << hex << (int)ct[i];
    cout << endl;

    aes.Dec(ct, msg);
    cout << "decrypted msg : ";
    for (int i=0 ;i<byteSize; i++)
        cout << msg[i];
    cout << endl;
}
