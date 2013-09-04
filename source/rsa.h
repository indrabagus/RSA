/***************************************************************************
                
RSA Key generator, Encryption and Decryption 

authors        : Indra Bagus Wicaksono <indra.bagus@gmail.com>
                                       <indra@xirkachipset.com>
              
*****************************************************************************/


#ifndef RSA_H
#define RSA_H
#ifdef __cplusplus
extern "C" {
#endif

#define BITSTRENGTH 1024

typedef struct rsapubkey{
    char strkey_n[1025];
    char strkey_k[32];
}rsapubkey_t, *PRSAPUBKEY;

typedef struct rsaprivkey{
    char strkey_n[1025];
    char strkey_j[4097];
}rsaprivkey_t, *PRSAPRIVKEY;

typedef struct rsa {
    rsapubkey_t     public_key;
    rsaprivkey_t    private_key;

}rsakey_t;

typedef rsakey_t *PRSAKEY;


int rsa_createkey(PRSAKEY pkey);
void rsa_encryptdata(const void* pdata, unsigned long length,void* pbuffer,PRSAPUBKEY ppubkey);
void rsa_decryptdata(const void* pdata,unsigned long length,void* pbuffer,PRSAPRIVKEY pprivkey);

#ifdef __cplusplus
}
#endif

#endif