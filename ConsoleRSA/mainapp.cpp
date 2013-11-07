#include <iostream>
#include <cassert>
#include <rsa.h>
#include <gmp.h>
#include <vector>
#include <Windows.h>
#include <fstream>

static rsakey_t rsakey;
//static const char strdatain[] = {'i','n','d','r','a','.','b','a',
//                                 'g','u','s','@','g','m','a','i',
//                                 'l','.','c','o','m'};

//static const char* strdatain = "Indra Bagus Wicaksono <indra@xirkachipset.com>";

static char bufferdataout[BITSTRENGTH*4];
static char bufferdecrypt[BITSTRENGTH*4];
static std::string szrandomdatain;
static std::vector<char> vectorinput;
static rsapubkey_ex rsapublic;
static rsaprivkey_ex rsaprivkey;

static void string2buffer(const std::string& szinput,std::vector<char>& output){
    if((szinput.size() % 2)){
        output.push_back(0);
    }

    char byte;
    char temp;
    for(int i =0;i<szinput.size();++i){
        if(szinput[i] == 'A' || szinput[i] == 'a')
            temp = 0xA;
        else if(szinput[i] == 'B' || szinput[i] == 'b')
            temp = 0xB;
        else if(szinput[i] == 'C' || szinput[i] == 'c')
            temp = 0xC;
        else if(szinput[i] == 'D' || szinput[i] == 'd')
            temp = 0xD;
        else if(szinput[i] == 'E' || szinput[i] == 'e')
            temp = 0xE;
        else if(szinput[i] == 'F' || szinput[i] == 'f')
            temp = 0xF;
        else
            temp = (szinput[i] - '0');
        
        if(!(i%2))
            byte = (temp << 4);
        else{
            byte |= temp;
            output.push_back(byte);
        }
    }


}


std::string generaterandomdata(int bitlength)
{
    gmp_randstate_t hrandstate;
    mpz_t hrandom;
    gmp_randinit_default(hrandstate);
    gmp_randseed_ui(hrandstate,GetTickCount());
    mpz_init(hrandom);
    mpz_urandomb(hrandom,hrandstate,bitlength-1);
    std::string retval = mpz_get_str(NULL,16,hrandom);
    mpz_clear(hrandom);
    return retval;
}




static int gentestvector(int numvector){
    int retval;
    char filename[64];

    std::cout<<"RSA Key creation"<<std::endl;
    do{
        retval = rsa_createkey(&rsakey);
    }while(retval != 0);
    std::cout<<std::endl;
    sprintf(filename,"publickey_%d.txt",numvector);
    std::ofstream ofspubkey(filename);
    ofspubkey<<rsakey.public_key.strkey_k<<std::endl<<std::endl;
    ofspubkey<<rsakey.public_key.strkey_n<<std::endl;
    ofspubkey.flush();
    std::cout<<"Public Key K: "<<rsakey.public_key.strkey_k<<std::endl;
    std::cout<<"Public Key N: "<<strlen(rsakey.public_key.strkey_n)/2<<" Bytes"<<
    std::endl<<rsakey.public_key.strkey_n<<std::endl<<std::endl<<std::endl;

    sprintf(filename,"privatekey_%d.txt",numvector);
    std::ofstream ofsprivkey(filename);
    ofsprivkey<<rsakey.private_key.strkey_j<<std::endl<<std::endl;
    ofsprivkey<<rsakey.private_key.strkey_n<<std::endl;
    ofsprivkey.flush();

    std::cout<<"Private Key J: "<<strlen(rsakey.private_key.strkey_j)/2<<" Bytes"
             <<std::endl<<rsakey.private_key.strkey_j<<std::endl<<std::endl;
    std::cout<<"Private Key N: "<<strlen(rsakey.private_key.strkey_n)/2<<" Bytes"
             <<std::endl<<rsakey.public_key.strkey_n<<std::endl<<std::endl;
    
    //static int statsuccess = 0;
    static int statfailed = 0;
    int i=0;
    while(i<2){
        szrandomdatain = generaterandomdata(BITSTRENGTH-1);
        vectorinput.clear();
        string2buffer(szrandomdatain,vectorinput);
        std::cout<<"Random Data Input, size="<<vectorinput.size()<<" Byte(s)"<<std::endl;

        rsa_encryptdata((char*)&vectorinput[0],vectorinput.size(),bufferdataout,&rsakey.public_key);
        std::cout<<"Encrypted Data: "<<strlen(bufferdataout)<<" Bytes"<<std::endl;
        int len = rsa_decryptdata(bufferdataout,sizeof(bufferdataout),bufferdecrypt,&rsakey.private_key);
        //if (strcmp(bufferdecrypt,szrandomdatain.c_str())!=0){
        if(memcmp(&vectorinput[0],bufferdecrypt,len)){
            std::cout<<"RSA FAILED"<<std::endl;
            ++statfailed;
            if(statfailed == 1000)
                return -1;
        }
        else{
            std::cout<<"RSA SUCCESS"<<std::endl;
            sprintf(filename,"datatrial_%d_%d.txt",numvector,i);
            std::ofstream ofsdatatrial(filename);
            ofsdatatrial<<"INPUT DATA"<<std::endl;
            ofsdatatrial<<szrandomdatain.c_str()<<std::endl<<std::endl;
            ofsdatatrial<<"ENCRYPTED DATA"<<std::endl;
            ofsdatatrial<<bufferdataout<<std::endl<<std::endl;
            ofsdatatrial.flush();
            ofsdatatrial.close();
            ++i;
        }
    }
    return 0;
}


void
cipherdecipher(void){
    mpz_t datain;
    mpz_t ciphertext;
    mpz_t dataout;
    mpz_t m;
    int retval;
    unsigned char* szp;
    gmp_randstate_t hrandstate;

    mpz_init(datain);
    mpz_init(ciphertext);
    mpz_init(dataout);
    mpz_init(m);



    /* generate key */
    std::cout<<"Generating key..."<<std::endl;
    do{
        retval = rsa_createkey_ex(&rsapublic,&rsaprivkey);
    }while(retval != 0);
    /* pastikan data input valid */
    mpz_mul(m,rsaprivkey.p,rsaprivkey.q);

    
    /* generate random input dengan syarat input > (p*q) */
    std::cout<<"Generating "<<BITSTRENGTH<<" bit input..."<<std::endl<<std::endl;
    do{
        gmp_randinit_default(hrandstate);
        gmp_randseed_ui(hrandstate,GetTickCount());
        mpz_urandomb(datain,hrandstate,BITSTRENGTH);
    }while(mpz_cmp(m,datain) <= 0);


    size_t sizelen = mpz_sizeinbase(rsapublic.p,16);
    szp = new unsigned char[(sizelen*3)+2];
    mpz_get_str((char*)szp,16,rsapublic.p);
    std::cout<<"[KEY P, size = "<<mpz_size(rsapublic.p)*sizeof(mp_limb_t)<<" Byte ]"<<std::endl<<szp<<std::endl<<std::endl;
    mpz_get_str((char*)szp,16,rsapublic.q);
    std::cout<<"[KEY Q, size = "<<mpz_size(rsapublic.p)*sizeof(mp_limb_t)<<" Byte ]"<<std::endl<<szp<<std::endl<<std::endl;
    mpz_get_str((char*)szp,16,rsaprivkey.d);
    std::cout<<"[PARAM D, size = "<<mpz_size(rsaprivkey.d)*sizeof(mp_limb_t)<<" Byte ]"<<std::endl<<szp<<std::endl<<std::endl;
    mpz_get_str((char*)szp,16,rsaprivkey.dp);
    std::cout<<"[PARAM Dp, size = "<<mpz_size(rsaprivkey.dp)*sizeof(mp_limb_t)<<" Byte ]"<<std::endl<<szp<<std::endl<<std::endl;
    mpz_get_str((char*)szp,16,rsaprivkey.dq);
    std::cout<<"[PARAM Dq, size = "<<mpz_size(rsaprivkey.dq)*sizeof(mp_limb_t)<<" Byte ]"<<std::endl<<szp<<std::endl<<std::endl;
    mpz_get_str((char*)szp,16,rsaprivkey.zp);
    std::cout<<"[PARAM Zp, size = "<<mpz_size(rsaprivkey.zp)*sizeof(mp_limb_t)<<" Byte ]"<<std::endl<<szp<<std::endl<<std::endl;
    mpz_get_str((char*)szp,16,rsaprivkey.zq);
    std::cout<<"[PARAM Zq, size = "<<mpz_size(rsaprivkey.zq)*sizeof(mp_limb_t)<<" Byte ]"<<std::endl<<szp<<std::endl<<std::endl;

    rsa_encryptdata_ex(ciphertext,datain,&rsapublic);
    mpz_get_str((char*)szp,16,ciphertext);
    std::cout<<"[CIPHERED TEXT]"<<std::endl<<szp<<std::endl<<std::endl;
    rsa_decrypdata_ex(dataout,ciphertext,&rsaprivkey);
    mpz_get_str((char*)szp,16,dataout);

    std::cout<<"[DECIPHERED TEXT]"<<std::endl<<szp<<std::endl<<std::endl;
    if(mpz_cmp(datain,dataout) != 0){
        std::cout<<"Encrypt Decrypt: F.A.I.L.E.D"<<std::endl;
    }
    else{
        std::cout<<"Encrypt Decrypt: S.U.C.C.E.E.S"<<std::endl;
    }
    delete[] szp;
    mpz_clear(datain);
    mpz_clear(ciphertext);
    mpz_clear(dataout);
    mpz_clear(m);
    rsa_cleanup_key(&rsapublic,&rsaprivkey);
}

int main(void)
{


    //int i=0;
    //while(i<4){
    //    if(gentestvector(i) == -1)
    //        continue;
    //    ++i;
    //}
    cipherdecipher();
    return 0;
}