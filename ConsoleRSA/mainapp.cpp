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
        szrandomdatain = generaterandomdata(BITSTRENGTH);
        vectorinput.clear();
        string2buffer(szrandomdatain,vectorinput);
        std::cout<<"Random Data Input, size="<<vectorinput.size()<<" Byte(s)"<<std::endl;

        rsa_encryptdata((char*)&vectorinput[0],vectorinput.size(),bufferdataout,&rsakey.public_key);
        std::cout<<"Encrypted Data: "<<strlen(bufferdataout)<<" Bytes"<<std::endl;
        int len = rsa_decryptdata(bufferdataout,strlen(bufferdataout),bufferdecrypt,&rsakey.private_key);
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


int main(void)
{
    //int retval;
    //std::cout<<"RSA Key creation"<<std::endl;
    //do{
    //    retval = rsa_createkey(&rsakey);
    //    std::cout<<".";
    //}while(retval != 0);
    //std::cout<<std::endl;
    //std::cout<<"Public Key K: "<<rsakey.public_key.strkey_k<<std::endl;
    //std::cout<<"Public Key N: "<<strlen(rsakey.public_key.strkey_n)/2<<" Bytes"<<
    //std::endl<<rsakey.public_key.strkey_n<<std::endl<<std::endl<<std::endl;
    //std::cout<<"Private Key J: "<<strlen(rsakey.private_key.strkey_j)/2<<" Bytes"
    //         <<std::endl<<rsakey.private_key.strkey_j<<std::endl<<std::endl;
    //std::cout<<"Private Key N: "<<strlen(rsakey.private_key.strkey_n)/2<<" Bytes"
    //         <<std::endl<<rsakey.public_key.strkey_n<<std::endl<<std::endl;

    //static int statsuccess = 0;
    //static int statfailed = 0;
    ////for(int i=0;i<100;++i){
    //while(1){
    //    szrandomdatain = generaterandomdata(BITSTRENGTH);
    //    vectorinput.clear();
    //    string2buffer(szrandomdatain,vectorinput);
    //    //std::cout<<"Random Data Input, size="<<szrandomdatain.size()<<" Byte(s)"<<std::endl;
    //    //std::cout<<szrandomdatain.c_str()<<std::endl<<std::endl;
    //    std::cout<<"Random data input,size="<<vectorinput.size()<<" Byte(s)"<<std::endl;
    //    std::cout<<szrandomdatain.c_str()<<std::endl;
    //    //rsa_encryptdata((char*)szrandomdatain.c_str(),szrandomdatain.size(),bufferdataout,&rsakey.public_key);
    //    rsa_encryptdata(&vectorinput[0],vectorinput.size(),bufferdataout,&rsakey.public_key);
    //    std::cout<<"Encrypted Data: "<<strlen(bufferdataout)<<" Bytes"<<std::endl
    //             <<bufferdataout<<std::endl;
    //    int decrlen = rsa_decryptdata(bufferdataout,strlen(bufferdataout),bufferdecrypt,&rsakey.private_key);
    //    //std::cout<<"Decrypt  Data: "<<strlen(bufferdecrypt)<<" Bytes"<<std::endl
    //    //         <<std::endl<<bufferdecrypt<<std::endl<<std::endl;
    //    //if (strcmp(bufferdecrypt,szrandomdatain.c_str())!=0){
    //    if(memcmp(&vectorinput[0],bufferdecrypt,decrlen)){
    //        std::cout<<"RSA FAILED"<<std::endl;
    //        ++statfailed;
    //    }
    //    else{
    //        std::cout<<"RSA SUCCESS"<<std::endl;
    //        ++statsuccess;
    //        if(statsuccess == 10)
    //            break;
    //    }
    //    std::cout<<std::endl;
    //}
    //std::cout<<"Number of failed  = "<<statfailed<<std::endl;
    //std::cout<<"Number of success = "<<statsuccess<<std::endl;
    //std::cout<<"Decrypted Data"<<std::endl<<bufferdecrypt<<std::endl;

    int i=0;
    while(i<4){
        if(gentestvector(i) == -1)
            continue;
        ++i;
    }
    return 0;
}