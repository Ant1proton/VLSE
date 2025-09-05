/********* SM3.cpp *********
      SM4算法接口定义头文件
            ghf
         2022/04/06
****** @company TTAI ******/
#ifndef SM4_H
#define SM4_H

#include <cstdint>
#include <cstring>
#include <string>
#include <sys/timeb.h>
using namespace std;

#define SM4_ECB 1
#define SM4_CBC 2
#define SM4_CFB 3
#define SM4_OFB 4

class SM4
{
public:
    typedef struct
    {
        uint32_t rkey[32];
        uint8_t iv[16];
        uint8_t mode;
    } sm4_ctx_t;

    constexpr static uint32_t FK[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

    static int sm4_encrypt(string &m, int sm4_skey_id, string iv, int mode);                                         //使用key_id进行加密
    static int sm4_decrypt(string &m, int sm4_skey_id, string iv, int mode);                                         //使用key_id进行解密
    static int sm4_encrypt(string &c, string m, const string &sm4_key, string iv = "123456789012345", int mode = 1); //使用key进行加密
    static int sm4_decrypt(string &c, string m, string sm4_key, string iv = "123456789012345", int mode = 1);        //使用key进行解密
    static void sm4_calc_block(const uint32_t rkey[32], const uint8_t in[16], uint8_t out[16]);
    static int create_key(string &key);
    ~SM4();

private:
    static void sm4_calc_key(const uint8_t key[16], uint32_t rkey[32]);
    // ECB模式
    static void sm4_ecb_encrypt(const uint8_t key[16], size_t len, const uint8_t *plain, uint8_t *cipher);
    static void sm4_ecb_decrypt(const uint8_t key[16], size_t len, const uint8_t *cipher, uint8_t *plain);
    // CBC模式
    static void sm4_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t *plain, uint8_t *cipher);
    static void sm4_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t *cipher, uint8_t *plain);
    // CFB模式
    static void sm4_cfb_encrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t *plain, uint8_t *cipher);
    static void sm4_cfb_decrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t *cipher, uint8_t *plain);
    // OFB模式
    static void sm4_ofb_en2de(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t *plain, uint8_t *cipher);
};

#endif