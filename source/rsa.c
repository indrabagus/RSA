#include <gmp.h>
#include <stdio.h>

typedef struct internalrsa{
    mpz_t p;
    mpz_t q;
    mpz_t n;
    mpz_t z;
    mpz_t k;
}privattrib_t,*PPRIVATEATTRIB;

#define HANDLE2PRIVATTRIB(handle) ((PPRIVATEATTRIB)handle)

static mpz_t hbigint;

/* --------- Mersenne Twister Start Here ------------ */
static mpz_t MT[624];
static int index;



void rsa_genkey(){
/* pick two number (p and q ) */
/* calculate n = p* q */
    /* calculate z = (p-1) * ( q - 1) */
    /* choose k, such that k is co-prime to z, i.e z is not divisible by k */
    /* calculate j for ( k * j ) mod z = 1 */
    /* then we have publick key = [n,k] and private key [n,j] */
}

void rsa_encrypt(Data P ){
    /* let the encrypt function be 
        E = (P ^ k) mod n */
}

void rsa_decrypt(Data Encr ) {
    /* Let the decryption function be
        P = (Encr ^ j) mode n*/
}

int main()
{
    static mpz_t result;
    int idx;
    mpz_init2(hbigint,1024);
    mpz_set_str(hbigint,"c00ffec00ffec00ffec00ffec00ffec00ffec00ffec00ffec00ffec00ffec00ffec00ffe",16);
    mpz_mul_ui(result,hbigint,0xDFDFAAAA);
    printf("BIG Integer : %s\n",mpz_get_str(NULL,16,result));
    printf("Allocated limb : %d,%d\n",hbigint->_mp_alloc,hbigint->_mp_size);
    for(idx = 0 ; idx < hbigint->_mp_alloc ; ++idx){
        printf("limb[%d] = %X \n",idx,hbigint->_mp_d[idx]);
    }
    mpz_clear(hbigint);
    mpn_rshift (&hbigint->_mp_d[8], &hbigint->_mp_d[8], sizeof(mp_limb_t), 2);
    printf("limb[8] = %X \n",hbigint->_mp_d[8]);
    return 0;
}