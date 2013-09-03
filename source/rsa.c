#include <gmp.h>
#include <stdlib.h>
#include "rsa.h"
#include <Windows.h>

//#pragma comment(linker,"/NODEFAULTLIB:LIBC");

#define PRIMESIZE   (BITSTRENGTH / 2)

typedef struct internalrsa {
    gmp_randstate_t hrandstate;
    mpz_t p;
    mpz_t q;
    mpz_t n;
    mpz_t z;
    mpz_t k;
    mpz_t j;
}privattrib_t,*PPRIVATEATTRIB;

#define HANDLE2PRIVATTRIB(handle) ((PPRIVATEATTRIB)handle)

handle_t 
rsa_initialize(void){
    PPRIVATEATTRIB phandle = (PPRIVATEATTRIB)malloc(sizeof(privattrib_t));
    gmp_randinit_default(phandle->hrandstate);
    gmp_randseed_ui(phandle->hrandstate,GetTickCount());
    mpz_init2(phandle->p,PRIMESIZE);
    mpz_init2(phandle->q,PRIMESIZE);
    mpz_init(phandle->n);
    mpz_init(phandle->z);
    mpz_init(phandle->k);
    mpz_init(phandle->j);
    return (handle_t)phandle;
}

void 
rsa_closehandle(handle_t h){
    mpz_clear(HANDLE2PRIVATTRIB(h)->p);
    mpz_clear(HANDLE2PRIVATTRIB(h)->q);
    mpz_clear(HANDLE2PRIVATTRIB(h)->n);
    mpz_clear(HANDLE2PRIVATTRIB(h)->z);
    mpz_clear(HANDLE2PRIVATTRIB(h)->k);
    mpz_clear(HANDLE2PRIVATTRIB(h)->j);
    free(HANDLE2PRIVATTRIB(h));
}


int 
rsa_createkey(handle_t handle,PRSAKEY pkey){
    /* inisialisasi variabel helper */
    mpz_t pminus;
    mpz_t qminus;
    mpz_t gcd;
    unsigned long int k_int = 65537;
    mpz_init(pminus);
    mpz_init(qminus);
    mpz_init(gcd);
    /* pick two random prime number (p and q ) */
    mpz_urandomb(HANDLE2PRIVATTRIB(handle)->p,HANDLE2PRIVATTRIB(handle)->hrandstate,PRIMESIZE);
    mpz_nextprime(HANDLE2PRIVATTRIB(handle)->p,HANDLE2PRIVATTRIB(handle)->p);
    gmp_randseed_ui(HANDLE2PRIVATTRIB(handle)->hrandstate,GetTickCount());
    mpz_urandomb(HANDLE2PRIVATTRIB(handle)->q,HANDLE2PRIVATTRIB(handle)->hrandstate,PRIMESIZE);
    mpz_nextprime(HANDLE2PRIVATTRIB(handle)->q,HANDLE2PRIVATTRIB(handle)->q);
    /* calculate n = (p * q) */
    mpz_mul(HANDLE2PRIVATTRIB(handle)->n,HANDLE2PRIVATTRIB(handle)->q,HANDLE2PRIVATTRIB(handle)->p);
    /* calculate z = (p-1) * ( q - 1) */
    mpz_sub_ui(pminus,HANDLE2PRIVATTRIB(handle)->p,(unsigned int)1);
    mpz_sub_ui(qminus,HANDLE2PRIVATTRIB(handle)->q,(unsigned int)1);
    mpz_mul(HANDLE2PRIVATTRIB(handle)->z,pminus,qminus);
    /* choose k, such that k is co-prime to z, i.e z is not divisible by k 
       or in other word gcd(k,z) = 1 */
    while(1){
        mpz_gcd_ui(gcd,HANDLE2PRIVATTRIB(handle)->z,k_int);
        if(mpz_cmp_ui(gcd,(unsigned long)1) == 0)
            break;
        k_int +=1;
    }
    mpz_set_ui(HANDLE2PRIVATTRIB(handle)->k,k_int);
    /* calculate j for ( k * j ) mod z = 1 */
    if(mpz_invert(HANDLE2PRIVATTRIB(handle)->j,HANDLE2PRIVATTRIB(handle)->k,HANDLE2PRIVATTRIB(handle)->z) == 0){
        /* cannot find j (multiplicative inverse) */
        return -1;
    }

    /* then we have publick key = [n,k] */ 
    mpz_get_str(pkey->public_key.strkey_k,16,HANDLE2PRIVATTRIB(handle)->k);
    mpz_get_str(pkey->public_key.strkey_n,16,HANDLE2PRIVATTRIB(handle)->n);
    /* and private key [n,j] */
    mpz_get_str(pkey->private_key.strkey_j,16,HANDLE2PRIVATTRIB(handle)->j);
    mpz_get_str(pkey->private_key.strkey_n,16,HANDLE2PRIVATTRIB(handle)->n);
    /* clean up everything */
    mpz_clear(pminus);
    mpz_clear(qminus);
    mpz_clear(gcd);
    
    return 0;
}


void
rsa_encryptdata(const void* pdata, 
                unsigned long length,
                void* pbuffer,
                PRSAPUBKEY ppubkey){

    mpz_t M;
    mpz_t c;
    mpz_t k;
    mpz_t n;
    unsigned char* pdatain = (unsigned char*)pdata;
    char* pdataout = (char*)pbuffer;
    /* saat ini hanya bisa 4 karakter yang diencrypt */
    char* pstrin = (char*)malloc((length*2)+1);
    int idx;
    //int tmpval;
    char strtmpval[4];
    memset(pstrin,0x00,(length*2)+1);

    for(idx = 0; idx < length ;++idx){
//        tmpval = (int)pdatain[idx];
        sprintf(strtmpval,"%2.2X",pdatain[idx]);
        strcat(pstrin,strtmpval);
    }
    mpz_init(M);
    mpz_init(c);
    mpz_init(k);
    mpz_init(n);
    mpz_set_str(k,ppubkey->strkey_k,16);
    mpz_set_str(n,ppubkey->strkey_n,16);
    mpz_set_str(M,pstrin,16);
    free(pstrin);

    /* c = M^k*/
    mpz_powm(c,M,k,n);
    mpz_get_str(pdataout,16,c);
    mpz_clear(M);
    mpz_clear(c);
    mpz_clear(k);
    mpz_clear(n);
}

void rsa_decryptdata(const void* pdata,
                     unsigned long length,
                     void* pbuffer,
                     PRSAPRIVKEY pprivkey){
    mpz_t c;
    mpz_t M;
    mpz_t n;
    mpz_t j;
    char* pdatain = (char*)pdata;
    char* pdataout = (char*)pbuffer;

    mpz_init(c);
    mpz_init(M);
    mpz_init(n);
    mpz_init(j);
    mpz_set_str(c,pdatain,16);
    mpz_set_str(n,pprivkey->strkey_n,16);
    mpz_set_str(j,pprivkey->strkey_j,16);
    /* M = (c^j)mod(n)*/
    mpz_powm(M,c,j,n);
    mpz_get_str(pdataout,16,M);
    mpz_clear(c);
    mpz_clear(M);
    mpz_clear(n);
    mpz_clear(j);
}


//void rsa_encrypt(Data P ){
//    /* let the encrypt function be 
//        E = (P ^ k) mod n */
//}
//
//void rsa_decrypt(Data Encr ) {
//    /* Let the decryption function be
//        P = (Encr ^ j) mode n*/
//}

//int main()
//{
//    static mpz_t result;
//    int idx;
//    mpz_init2(hbigint,1024);
//    mpz_set_str(hbigint,"c00ffec00ffec00ffec00ffec00ffec00ffec00ffec00ffec00ffec00ffec00ffec00ffe",16);
//    mpz_mul_ui(result,hbigint,0xDFDFAAAA);
//    printf("BIG Integer : %s\n",mpz_get_str(NULL,16,result));
//    printf("Allocated limb : %d,%d\n",hbigint->_mp_alloc,hbigint->_mp_size);
//    for(idx = 0 ; idx < hbigint->_mp_alloc ; ++idx){
//        printf("limb[%d] = %X \n",idx,hbigint->_mp_d[idx]);
//    }
//    mpz_clear(hbigint);
//    mpn_rshift (&hbigint->_mp_d[8], &hbigint->_mp_d[8], sizeof(mp_limb_t), 2);
//    printf("limb[8] = %X \n",hbigint->_mp_d[8]);
//    return 0;
//}