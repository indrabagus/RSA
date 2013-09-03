#include <iostream>
#include <cassert>
#include <rsa.h>

static handle_t hrsa;
static rsakey_t rsakey;
static const char strdatain[] = {'i','n','d','r','a','.','b','a',
                                 'g','u','s','@','g','m','a','i',
                                 'l','.','c','o','m'};
static char bufferdataout[1024];
static char bufferdecrypt[1024];
int main(void)
{
    std::cout<<"RSA initialization"<<std::endl;
    hrsa = rsa_initialize();
    assert(hrsa != 0);
    int retval;
    std::cout<<"RSA Key creation"<<std::endl;
    do{
        retval = rsa_createkey(hrsa,&rsakey);
    }while(retval != 0);
    std::cout<<"Public Key K: "<<rsakey.public_key.strkey_k<<std::endl;
    std::cout<<"Public Key N: "<<rsakey.public_key.strkey_n<<std::endl<<std::endl<<std::endl;
    std::cout<<"Private Key J: "<<rsakey.private_key.strkey_j<<std::endl<<std::endl;
    std::cout<<"Private Key N: "<<rsakey.public_key.strkey_n<<std::endl<<std::endl;
    rsa_encryptdata(strdatain,sizeof(strdatain),bufferdataout,&rsakey.public_key);
    std::cout<<"Encrypted data : "<<bufferdataout<<std::endl;
    rsa_decryptdata(bufferdataout,strlen(bufferdataout),bufferdecrypt,&rsakey.private_key);
    std::cout<<"Decrypt data : "<<bufferdecrypt<<std::endl;
    std::cout<<"RSA close handle"<<std::endl;
    rsa_closehandle(hrsa);
    return 0;
}