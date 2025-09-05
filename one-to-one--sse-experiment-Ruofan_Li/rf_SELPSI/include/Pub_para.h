#pragma once

#include <NTL/ZZ.h>
#include <string>
#include <iostream>
#include <siphash.h>
#include <aes.h>
using namespace std;
using namespace NTL;
using namespace CryptoPP;

class Pub_para
{
public:
    const int KEY_LEN = 16;
    const int NUM_OF_CUCKOO_HASH = 3;
    ZZ alpha;
    ZZ alpha_inv;
    ZZ alpha1;
    ZZ alpha_inv1;
    ZZ beta;
    ZZ beta1;
    ZZ N;
    SipHash<2, 4, true> siphash;
    vector<SipHash<2, 4, true>> hash_list;
    AESEncryption aesEncryptor; //加密器
    AESDecryption aesDecryptor; //解密器

    Pub_para();
    /**
     * @brief aes加密函数
     *
     * @param aesKey 加密密钥，16byte长
     * @param inBlock 加密消息，不能超过16byte
     * @return SecByteBlock 加密过后的密文，16byte
     */
    SecByteBlock aes_Enc(const SecByteBlock &aesKey, const SecByteBlock &inBlock);

    /**
     * @brief aes解密函数
     *
     * @param aesKey 加密密钥，16byte长
     * @param outBlock 密文长度，不能超过16byte
     * @return SecByteBlock 解密之后的消息，16byte
     */
    SecByteBlock aes_Dec(const SecByteBlock &aesKey, const SecByteBlock &outBlock);
    
};