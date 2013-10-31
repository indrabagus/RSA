/***************************************************************************
                
RSA Key generator, Encryption and Decryption 

authors        : Indra Bagus Wicaksono <indra.bagus@gmail.com>
                                       <indra@xirkachipset.com>
              
*****************************************************************************/


#ifndef RSA_H
#define RSA_H
#include <mpir.h>

#define USING_DECIPHER_CRT
//#define USING_DECIPHER_CRT2

#ifdef __cplusplus
extern "C" {
#endif

#define BITSTRENGTH (8*1024)

typedef struct rsapubkey{
    char strkey_n[BITSTRENGTH];
    char strkey_k[BITSTRENGTH];
}rsapubkey_t, *PRSAPUBKEY;

typedef struct rsaprivkey{
    char strkey_n[BITSTRENGTH];
    char strkey_j[BITSTRENGTH*2];
}rsaprivkey_t, *PRSAPRIVKEY;

typedef struct rsapubkey_ex{
    mpz_t p;
    mpz_t q;
    mpz_t e;
}rsapubkey_ex, *PPUBKEY_EX;

typedef struct rsaprivkey_ex{
    mpz_t p;
    mpz_t q;
    mpz_t d;
    mpz_t dp;
    mpz_t dq;
    mpz_t zp;
    mpz_t zq;
}rsaprivkey_ex, *PPRIVKEY_EX;

typedef struct rsa {
    rsapubkey_t     public_key;
    rsaprivkey_t    private_key;

}rsakey_t;

typedef rsakey_t *PRSAKEY;


int rsa_createkey(PRSAKEY pkey);
void rsa_encryptdata(const void* pdata, unsigned long length,void* pbuffer,PRSAPUBKEY ppubkey);
int rsa_decryptdata(const void* pdata,unsigned long length,void* pbuffer,PRSAPRIVKEY pprivkey);

int rsa_createkey_ex(PPUBKEY_EX ppubkey,PPRIVKEY_EX pprivkey);
void rsa_cleanup_key(PPUBKEY_EX ppubkey,PPRIVKEY_EX pprivkey);
int rsa_encryptdata_ex(mpz_t rop,mpz_t raw,PPUBKEY_EX ppubkey);
int rsa_decrypdata_ex(mpz_t rop,mpz_t ciphered,PPRIVKEY_EX pprivkey);


#ifdef __cplusplus
}
#endif

#endif