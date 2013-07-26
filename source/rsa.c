#include "mini-gmp.h"
#include <stdio.h>

static mpz_t hbigint;

/* --------- Mersenne Twister Start Here ------------ */
static mpz_t MT[624];
static int index;

static void 
mersenne_twister_init(mpz_t seed){
    int i;
    index = 0;
    mpz_array_init(MT[0],624,1024);
    mpz_set(MT[0],seed);
    for(i=1;i<624;++i){
        mpz_tdiv_q_2exp(MT[i],MT[i-1],30);
        mpz_xor (MT[i], MT[i], MT[i-1]);
        mpz_mul_ui(MT[i],MT[i],1812433253);
        mpz_add_ui(MT[i],MT[i],1);
    }

}

static void
merstwister_init(mpz_t op,const mpz_t prev){
    int idx;
    // TODO check jumlah limb kedua ini harus sama

    for(idx=0;idx < op->_mp_size;++idx){
        mpn_rshift (&op->_mp_d[idx], &op->_mp_d[idx], sizeof(mp_limb_t), 30);
    }
}

static void
randominit(mpz_t seed){
    int i;
    index = 0;
    mpz_array_init(MT[0],624,1024);
    mpz_set(MT[0],seed);
    for(i=1;i<624;++i){
        merstwister_init(MT[i],MT[i-1]);
    }
}




/*
 // Generate an array of 624 untempered numbers
 function generate_numbers() {
     for i from 0 to 623 {
         int y := (MT[i] & 0x80000000)                       // bit 31 (32nd bit) of MT[i]
                        + (MT[(i+1) mod 624] & 0x7fffffff)   // bits 0-30 (first 31 bits) of MT[...]
         MT[i] := MT[(i + 397) mod 624] xor (right shift by 1 bit(y))
         if (y mod 2) != 0 { // y is odd
             MT[i] := MT[i] xor (2567483615) // 0x9908b0df
         }
     }
 }

*/
static void
mersenne_twister_gennumber(void){
    mpz_t mask1;
    mpz_t mask2;
}

static void
mersenne_twister_extract(mpz_t res){
}

/* --------- Mersenne Twister End Here ------------ */


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