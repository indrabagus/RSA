#include <iostream>
#include <cassert>
#include <rsa.h>

static rsakey_t rsakey;
//static const char strdatain[] = {'i','n','d','r','a','.','b','a',
//                                 'g','u','s','@','g','m','a','i',
//                                 'l','.','c','o','m'};
static const char* strdatain = "Indra Bagus Wicaksono <indra@xirkachipset.com>";
static char bufferdataout[BITSTRENGTH];
static char bufferdecrypt[BITSTRENGTH];
int main(void)
{
    int retval;
    std::cout<<"RSA Key creation"<<std::endl;
    do{
        retval = rsa_createkey(&rsakey);
        std::cout<<".";
    }while(retval != 0);
    std::cout<<std::endl;
    std::cout<<"Public Key K: "<<rsakey.public_key.strkey_k<<std::endl;
    std::cout<<"Public Key N: "<<strlen(rsakey.public_key.strkey_n)<<" Bytes"<<
    std::endl<<rsakey.public_key.strkey_n<<std::endl<<std::endl<<std::endl;
    std::cout<<"Private Key J: "<<strlen(rsakey.private_key.strkey_j)<<" Bytes"
             <<std::endl<<rsakey.private_key.strkey_j<<std::endl<<std::endl;
    std::cout<<"Private Key N: "<<strlen(rsakey.private_key.strkey_n)<<" Bytes"
             <<std::endl<<rsakey.public_key.strkey_n<<std::endl<<std::endl;
    rsa_encryptdata(strdatain,strlen(strdatain),bufferdataout,&rsakey.public_key);
    std::cout<<"Encrypted Data: "<<strlen(bufferdataout)<<" Bytes"
             <<std::endl<<bufferdataout<<std::endl<<std::endl;
    rsa_decryptdata(bufferdataout,strlen(bufferdataout),bufferdecrypt,&rsakey.private_key);
    std::cout<<"Decrypted Data"<<std::endl<<bufferdecrypt<<std::endl;
    return 0;
}