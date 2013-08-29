#ifndef RSA_H
#define RSA_H
#ifdef __cplusplus
extern "C" {
#endif

#define BITSTRENGTH 1024

typedef struct rsa {
    char publickey[64];
    char privatekey[64];

}rsakey_t;

typedef rsakey_t* PRSAKEY;

typedef void* handle_t;

handle_t rsa_initialize(void);
int rsa_createkey(handle_t handle,PRSAKEY key);
void rsa_encryptdata(const void* pdata, unsigned long length,void* pubuffer);
void rsa_decryptdata(const void* pdata,unsigned long length,void* pbuffer);
void rsa_closehandle(handle_t h);

#ifdef __cplusplus
}
#endif

#endif