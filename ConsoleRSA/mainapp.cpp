#include <iostream>
#include <cassert>
#include <rsa.h>

static handle_t hrsa;
static rsakey_t rsakey;
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
    std::cout<<"RSA close handle"<<std::endl;
    rsa_closehandle(hrsa);
    return 0;
}