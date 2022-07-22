#include <stdio.h>
#include <string.h>
#include <iostream>
#include <string>
#include <openssl/sha.h>

using namespace std;

/*
 * https://www.openssl.org/docs/man1.0.2/man3/SHA1_Final.html
 * https://www.openssl.org/docs/manmaster/man3/SHA256_Update.html 
 */
int main(){
    unsigned char digest[SHA256_DIGEST_LENGTH];
    char str[] = "hello world";

    // Use SHA256
    SHA256((unsigned char*)&str, strlen(str), (unsigned char*)&digest);
    char mdString[SHA256_DIGEST_LENGTH*2+1];

    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
    printf("SHA256 digest: %s\n", mdString);


    // Use SHA256_CTX
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, str, strlen(str));
    SHA256_Final(digest, &ctx);

    cout << "SHA256 digest: ";
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        printf("%02x" , digest[i]);
    cout << endl;

    // use string 
    string data =  "hello world";
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.length());
    SHA256_Final(digest, &ctx);

    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
    printf("SHA256 digest: %s\n", mdString);

    return 0;
}
