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

#define BITSTRENGTH (8*1024)

typedef struct rsapubkey{
    char strkey_n[BITSTRENGTH];
    char strkey_k[BITSTRENGTH];
}rsapubkey_t, *PRSAPUBKEY;

typedef struct rsaprivkey{
    char strkey_n[BITSTRENGTH];
    char strkey_j[BITSTRENGTH*2];
}rsaprivkey_t, *PRSAPRIVKEY;

typedef struct rsaprivkey_ex{
    void* p;
    void* q;
    void* dp;
    void* dq;
    void* cz;
};

typedef struct rsa {
    rsapubkey_t     public_key;
    rsaprivkey_t    private_key;

}rsakey_t;

typedef rsakey_t *PRSAKEY;


int rsa_createkey(PRSAKEY pkey);
void rsa_encryptdata(const void* pdata, unsigned long length,void* pbuffer,PRSAPUBKEY ppubkey);
int rsa_decryptdata(const void* pdata,unsigned long length,void* pbuffer,PRSAPRIVKEY pprivkey);

#ifdef __cplusplus
}
#endif

#endif