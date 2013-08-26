#ifndef RSA_H
#define RSA_H

typedef struct rsa {

}rsakey_t;

typedef rsakey_t* PRSAKEY;

typedef void* handle_t;

handle_t rsa_initialize(void);
void rsa_createkey(handle_t handle,PRSAKEY_T key);
void rsa_encryptdata(const void* pdata, ulong_t length,void* pubuffer);
void rsa_decryptdata(const void* pdata,ulong_t length,void* pbuffer);
rsa_closehandle(handle_t h);

#endif