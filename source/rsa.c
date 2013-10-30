//#include <gmp.h>
#include <mpir.h>
#include <stdlib.h>
#include <stdio.h>
#include "rsa.h"
#include <Windows.h>

/*
Note:
#pragma comment(linker,"/NODEFAULTLIB:LIBC");
harus ditambahkan jika ingin mengcompile menggunakan 'cl' diconsole
*/
//#define SWAP4BYTE(val)  (((val & 0xFF000000)>>24)|((val & 0xFF0000) >> 8)|((val & 0xFF00) << 8) | ((val & 0xFF) << 24))

#define PRIMESIZE   (BITSTRENGTH / 2)

typedef struct internalrsa {
    gmp_randstate_t hrandstate;
    mpz_t p;
    mpz_t q;
    mpz_t pminus;
    mpz_t qminus;
    mpz_t gcd;
    mpz_t n;
    mpz_t z;
    mpz_t k;
    mpz_t j;
}privattrib_t,*PPRIVATEATTRIB;

#define HANDLE2PRIVATTRIB(handle) ((PPRIVATEATTRIB)handle)


static PPRIVATEATTRIB
create_private_attrib(void){
    PPRIVATEATTRIB pattrib = (PPRIVATEATTRIB)malloc(sizeof(privattrib_t));
    gmp_randinit_default(pattrib->hrandstate);
    gmp_randseed_ui(pattrib->hrandstate,GetTickCount());
    //mpz_init2(pattrib->p,PRIMESIZE);
    //mpz_init2(pattrib->q,PRIMESIZE);
    mpz_init(pattrib->p);
    mpz_init(pattrib->q);
    mpz_init(pattrib->pminus);
    mpz_init(pattrib->qminus);
    mpz_init(pattrib->gcd);
    mpz_init(pattrib->n);
    mpz_init(pattrib->z);
    mpz_init(pattrib->k);
    mpz_init(pattrib->j);
    return pattrib;
}

static void
destroy_private_attrib(PPRIVATEATTRIB pattrib){
    mpz_clear(pattrib->p);
    mpz_clear(pattrib->q);
    mpz_clear(pattrib->pminus);
    mpz_clear(pattrib->qminus);
    mpz_clear(pattrib->gcd);
    mpz_clear(pattrib->n);
    mpz_clear(pattrib->z);
    mpz_clear(pattrib->k);
    mpz_clear(pattrib->j);
    free(pattrib);
}

int 
rsa_createkey(PRSAKEY pkey){
    /* inisialisasi variabel helper */
    unsigned long int k_int = 65537;
    PPRIVATEATTRIB prsaattrib = create_private_attrib();
    if(prsaattrib==0x00)
        return -1;


    /* pick two random prime number (p and q ) */
    mpz_urandomb(prsaattrib->p,prsaattrib->hrandstate,PRIMESIZE);
    mpz_nextprime(prsaattrib->p,prsaattrib->p);
    //gmp_randseed_ui(prsaattrib->hrandstate,GetTickCount());
    mpz_urandomb(prsaattrib->q,prsaattrib->hrandstate,PRIMESIZE);
    mpz_nextprime(prsaattrib->q,prsaattrib->q);
    /* calculate n = (p * q) */
    mpz_mul(prsaattrib->n,prsaattrib->q,prsaattrib->p);
    /* calculate z = (p-1) * ( q - 1) */
    mpz_sub_ui(prsaattrib->pminus,prsaattrib->p,(unsigned int)1);
    mpz_sub_ui(prsaattrib->qminus,prsaattrib->q,(unsigned int)1);
    mpz_mul(prsaattrib->z,prsaattrib->pminus,prsaattrib->qminus);
    /* choose k, such that k is co-prime to z, i.e z is not divisible by k 
       or in other word gcd(k,z) = 1 */
    while(1){
        mpz_gcd_ui(prsaattrib->gcd,prsaattrib->z,k_int);
        if(mpz_cmp_ui(prsaattrib->gcd,(unsigned long)1) == 0)
            break;
        k_int +=1;
    }
    mpz_set_ui(prsaattrib->k,k_int);

    /* calculate j for ( k * j ) mod z = 1 */
    if(mpz_invert(prsaattrib->j,prsaattrib->k,prsaattrib->z) == 0){
        /* cannot find j (multiplicative inverse) */
        destroy_private_attrib(prsaattrib);
        return -1;
    }

    /* then we have public key = [n,k] */ 
    mpz_get_str(pkey->public_key.strkey_k,16,prsaattrib->k);
    mpz_get_str(pkey->public_key.strkey_n,16,prsaattrib->n);
    /* and private key [n,j] */
    mpz_get_str(pkey->private_key.strkey_j,16,prsaattrib->j);
    mpz_get_str(pkey->private_key.strkey_n,16,prsaattrib->n);
    /* clean up everything */
    destroy_private_attrib(prsaattrib);
    
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
    char* pstrin = (char*)malloc((length*2)+1);
    unsigned long idx;
    char strtmpval[4];
    memset(pstrin,0x00,(length*2)+1);

    for(idx = 0; idx < length ;++idx){
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

    /* c = (M ^ k) mod n*/
    mpz_powm(c,M,k,n);
    mpz_get_str(pdataout,16,c);
    mpz_clear(M);
    mpz_clear(c);
    mpz_clear(k);
    mpz_clear(n);
}

int rsa_decryptdata(const void* pdata,
                     unsigned long length,
                     void* pbuffer,
                     PRSAPRIVKEY pprivkey){
    mpz_t c;
    mpz_t M;
    mpz_t n;
    mpz_t j;
    char* pdatain = (char*)pdata;
    char* pdataout = (char*)pbuffer;
    char* plimbend;
    char* plimbiter;
    int retval;
    /* Inisialisasi Super integer */
    mpz_init(c);
    mpz_init(M);
    mpz_init(n);
    mpz_init(j);
    mpz_set_str(c,pdatain,16);
    mpz_set_str(n,pprivkey->strkey_n,16);
    mpz_set_str(j,pprivkey->strkey_j,16);
    /* M = (c^j)mod(n)*/
    mpz_powm(M,c,j,n);
    /* Karena inisialisasi data yang masuk pada super integer terbalik maka kita mentransfer 
    ke output buffer dari akhir buffer 'limb' pada super integer ke awal buffer super integer */
    retval = M->_mp_size*sizeof(mp_limb_t);
    plimbend = (char*)M->_mp_d;
    plimbiter = plimbend + ((M->_mp_size*sizeof(mp_limb_t))-1);
    while(plimbiter >= plimbend){
        if(*plimbiter == 0x00){
            plimbiter--;
            continue;
        }
        *pdataout++ = *plimbiter;
        plimbiter--;
    }
    /* Clean em all */
    mpz_clear(c);
    mpz_clear(M);
    mpz_clear(n);
    mpz_clear(j);
    return retval;
}


/*--------------------------------------------------------------------------*/

int 
rsa_createkey_ex(PPUBKEY_EX ppubkey,PPRIVKEY_EX pprivkey){
    int retval;
    gmp_randstate_t hrandstate;
    mpz_t n;
    mpz_t pminus;
    mpz_t qminus;
    mpz_t z;
    mpz_t gcd;
    //mpz_t d;
    unsigned long int k_int = 65537;
    /* inisialisasi semuanya */
    gmp_randinit_default(hrandstate);
    mpz_init(n);
    mpz_init(pminus);
    mpz_init(qminus);
    mpz_init(z);
    mpz_init(gcd);
    mpz_init(ppubkey->p);
    mpz_init(ppubkey->q);
    mpz_init(ppubkey->e);
    mpz_init(pprivkey->p);
    mpz_init(pprivkey->q);
    mpz_init(pprivkey->d);
    mpz_init(pprivkey->dp);
    mpz_init(pprivkey->dq);
    mpz_init(pprivkey->zp);
    mpz_init(pprivkey->zq);

    /* inisialisasi randomizer */
    gmp_randseed_ui(hrandstate,GetTickCount());
    /* pick two random prime number (p and q ) */
    mpz_urandomb(pprivkey->p,hrandstate,PRIMESIZE);
    mpz_nextprime(pprivkey->p,pprivkey->p);
    mpz_urandomb(pprivkey->q,hrandstate,PRIMESIZE);
    mpz_nextprime(pprivkey->q,pprivkey->q);
    /* set public key p and q */
    mpz_set(ppubkey->p,pprivkey->p);
    mpz_set(ppubkey->q,pprivkey->q);
    /* calculate n = (p * q) */
    mpz_mul(n,pprivkey->q,pprivkey->p);
    /* calculate z = (p-1) * ( q - 1) */
    mpz_sub_ui(pminus,pprivkey->p,(unsigned int)1);
    mpz_sub_ui(qminus,pprivkey->q,(unsigned int)1);
    mpz_mul(z,pminus,qminus);
    /* choose k, such that k is co-prime to z, i.e z is not divisible by k 
       or in other word gcd(k,z) = 1 */
    while(1){
        mpz_gcd_ui(gcd,z,k_int);
        if(mpz_cmp_ui(gcd,(unsigned long)1) == 0)
            break;
        k_int +=1;
    }
    mpz_set_ui(ppubkey->e,k_int);

    /* calculate d for  e * d  = 1 mod z 
       which result d = e^(-1) mod z;
    */
    if(mpz_invert(pprivkey->d,ppubkey->e,z) == 0){
        /* cannot find d (multiplicative inverse) */
        rsa_cleanup_pubkey(ppubkey);
        rsa_cleanup_privkey(pprivkey);
        retval = -1;
        goto closure;
    }
    /* dp = d mod (p-1), dq = d mod (q-1) */
    mpz_mod(pprivkey->dp,pprivkey->d,pminus);
    mpz_mod(pprivkey->dq,pprivkey->d,qminus);

    /* zp = q^(p-1) mod n, zq = p^(q-1) mod n */
    mpz_powm(pprivkey->zp,pprivkey->q,pminus,n);
    mpz_powm(pprivkey->zq,pprivkey->p,qminus,n);

    retval = 0;
    goto closure;



closure:
    mpz_clear(n);
    mpz_clear(pminus);
    mpz_clear(qminus);
    mpz_clear(z);
    mpz_clear(gcd);
    return retval;


}

void
rsa_cleanup_pubkey(PPUBKEY_EX ppubkey){
    mpz_clear(ppubkey->p);
    mpz_clear(ppubkey->q);
    mpz_clear(ppubkey->e);
}



void rsa_cleanup_privkey(PPRIVKEY_EX pprivkey){
    mpz_clear(pprivkey->p);
    mpz_clear(pprivkey->q);
    mpz_clear(pprivkey->dp);
    mpz_clear(pprivkey->dq);
    mpz_clear(pprivkey->zp);
    mpz_clear(pprivkey->zq);
}

int 
rsa_encryptdata_ex(mpz_t rop,mpz_t raw,PPUBKEY_EX ppubkey){
    mpz_t n;
    mpz_init(n);
    mpz_mul(n,ppubkey->p,ppubkey->q);
    mpz_powm(rop,raw,ppubkey->e,n);
    mpz_clear(n);
    return 0;
}

int 
rsa_decrypdata_ex(mpz_t rop,mpz_t ciphered,PPRIVKEY_EX pprivkey){

#ifdef USING_DECIPHER_CRT
    mpz_t cp;
    mpz_t cq;
    mpz_t pp;
    mpz_t pq;
    mpz_t sp;
    mpz_t sq;
    mpz_t ppzp;
    mpz_t pqzq;
    mpz_t n;
    mpz_t spsq;

    mpz_init(cp);
    mpz_init(cq);
    mpz_init(pp);
    mpz_init(pq);
    mpz_init(sp);
    mpz_init(sq);
    mpz_init(ppzp);
    mpz_init(pqzq);
    mpz_init(n);
    mpz_init(spsq);

    mpz_mod(cp,ciphered,pprivkey->p);
    mpz_mod(cq,ciphered,pprivkey->q);
    mpz_powm(pp,cp,pprivkey->dp,pprivkey->p);
    mpz_powm(pq,cq,pprivkey->dq,pprivkey->p);
    mpz_mul(ppzp,pp,pprivkey->zp);
    mpz_mul(pqzq,pq,pprivkey->zq);
    mpz_mul(n,pprivkey->p,pprivkey->q);
    mpz_mod(sp,ppzp,n);
    mpz_mod(sq,pqzq,n);
    mpz_add(spsq,sp,sq);
    if(mpz_cmp(spsq,n) >= 0)
        mpz_sub(rop,spsq,n);
    else
        mpz_set(rop,spsq);
    mpz_clear(spsq);
    mpz_clear(n);
    mpz_clear(cp);
    mpz_clear(cq);
    mpz_clear(pp);
    mpz_clear(pq);
    mpz_clear(sp);
    mpz_clear(sq);
    mpz_clear(ppzp);
    mpz_clear(pqzq);
#endif

#ifdef USING_GENERIC_RSADECIPHER
    mpz_t n;
    mpz_init(n);
    mpz_mul(n,pprivkey->p,pprivkey->q);
    mpz_powm(rop,ciphered,pprivkey->d,n);
    mpz_clear(n);
#endif
    return 0;
}
