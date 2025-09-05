//
// Created by root on 2022/3/24.
//

#ifndef SM2_SM2_H
#define SM2_SM2_H

#include <time.h>
#include <stdlib.h>
#include <string>
#include "../include/eccbaseop.h"
#include "../include/random.h"
#include "../include/sm3.h"

// sm2密钥对结构体
struct sm2_key
{
    string pk; //前32个字节是x,后32个字节是y
    string sk;
};

class EccCrypto {
    friend class Sm2Executor;
private:
    static void KDF(unsigned char *data, unsigned int data_len, unsigned int key_len, unsigned char *key);
    static int EccMakeKey(unsigned char *sk, unsigned int sk_len,
                   unsigned char *pk, unsigned int pk_len, int type);
    static int EccSign(const unsigned char *hash, unsigned int hash_len,
                unsigned char *random, unsigned int random_len,
                unsigned char *sk, unsigned int sk_len,
                unsigned char *sign, unsigned int sign_len);
    static int EccVerify(const unsigned char *hash, unsigned int hash_len,
                  unsigned char *pk, unsigned int pk_len,
                  unsigned char *sign, unsigned int sign_len);
    static int EccEncrypt(unsigned char *plain, unsigned int plain_len,
                   unsigned char *random, unsigned int random_len,
                   unsigned char *pk, unsigned int pk_len,
                   unsigned char *cipher, unsigned int cipher_len);
    static int EccDecrypt(unsigned char *cipher, unsigned int cipher_len,
                   unsigned char *sk, unsigned int sk_len,
                   unsigned char *plain, unsigned int plain_len);
    static unsigned char *Get_rand_sk(Random &r); //获取随机私钥
};

class Sm2Executor {
private:
    static unsigned char *get_random(Random &r);

public:
    static int sm2_keygen(sm2_key &key, Random &r);
    static int sm2_encrypt(const string &m, const string &sm2_pk, string &cipher, Random &r);
    static int sm2_decrypt(const string &c, const string &sm2_sk, string &plain);
    static int sm2_sign(const string &c, const string &sm2_key_sk, string &signature, Random &r);
    static int sm2_verify(const string &mess, const string &sig, const string &sm2_key_pk);
    //static sm2_key search_sm2_skey(int sm2_skey_id);

public:
    //static int sm2_keygen_id();
    /*static string sm2_encrypt(string m, int sm2_skey_id);
    static string sm2_decrypt(string c, int sm2_skey_id);
    static string sm2_sign(string c, int sm2_skey_id);
    static int sm2_verify(string mess, string sig, int sm2_skey_id);*/
};

#endif //SM2_SM2_H
