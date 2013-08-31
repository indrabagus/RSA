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

typedef void* handle_t;

handle_t rsa_initialize(void);
int rsa_createkey(handle_t handle,PRSAKEY pkey);
void rsa_encryptdata(const void* pdata, unsigned long length,void* pbuffer,PRSAPUBKEY ppubkey);
void rsa_decryptdata(const void* pdata,unsigned long length,void* pbuffer,PRSAPUBKEY pprivkey);
void rsa_closehandle(handle_t h);

#ifdef __cplusplus
}
#endif

#endif