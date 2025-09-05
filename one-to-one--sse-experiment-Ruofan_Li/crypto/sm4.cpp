/********* SM3.cpp *********
        SM3算法接口实现
            ghf
         2022/04/06
****** @company TTAI ******/
#include <iostream>
#include <utility>
#include "../include/sm4.h"

/*------------------定义------------------*/
static const uint8_t SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48};
static const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279};

/*------------------字符串格式转换------------------*/
string uctostring(unsigned char *c)
{
    string str = (char *)c;
    return str;
}

unsigned char *stringtouchex(string str)
{
    int i;
    auto *output = new unsigned char[str.size() / 2];
    int temp;
    int len = 0;
    for (i = 0; i < str.size(); i += 2)
    { //每两位转换成十进制int,如 "01"=> 16(字符串为十六进制)
        temp = 0;
        char tmp = str[i];
        int ll = isdigit(tmp) ? tmp - '0' : tmp - 'a' + 10;
        temp = temp * 16 + ll;
        tmp = str[i + 1];
        ll = isdigit(tmp) ? tmp - '0' : tmp - 'a' + 10;
        temp = temp * 16 + ll;
        output[len++] = (unsigned char)temp;
    }
    return output;
}

unsigned char *stringtouc(const string &str)
{
    auto *s = new unsigned char[str.size() + 1];
    string temp(str);
    int i;
    int len = temp.length();
    for (i = 0; i < len; ++i)
        s[i] = (unsigned char)temp[i];
    s[i] = '\0';
    return s;
}

string convert_hex(const unsigned char *md /*字符串*/, int nLen /*转义多少个字符*/)
{
    string strSha1;
    static const char hex_chars[] = "0123456789abcdef";
    unsigned int c;
    // 查看unsigned char占几个字节,实际占1个字节,8位
    for (int i = 0; i < nLen; i++)
    {
        // 查看md一个字节里的信息
        unsigned int x;
        c = (md[i] >> 4) & 0x0f; //取高四位转换成数字与字母
        strSha1 += hex_chars[c];
        x = md[i] & 0x0f;
        strSha1 += hex_chars[x]; //取低四位转换成数字与字母
    }
    return strSha1;
}

int Getlength(const string &str)
{
    int i = 0;
    while (true)
    {
        if (16 * i >= str.size()) //因为需要128b，并且填充不满128b的数据
            break;
        i++;
    }
    return i * 16; //返回填充完的数据长度
}

/*------------------加密函数的宏定义------------------*/
static inline uint32_t load_be_u32(const uint8_t bs[4])
{
    return ((uint32_t)bs[0] << unsigned(24)) | ((uint32_t)bs[1] << unsigned(16)) | ((uint32_t)bs[2] << unsigned(8)) | bs[3];
}

static inline void store_be_u32(const uint32_t x, uint8_t bs[4])
{
    bs[0] = (x >> 24) & 0xff;
    bs[1] = (x >> 16) & 0xff;
    bs[2] = (x >> 8) & 0xff;
    bs[3] = (x)&0xff;
}

static inline uint32_t lshift(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static inline void xor_block(uint8_t *out, const uint8_t *in, size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        out[i] ^= in[i];
    }
}

static inline uint32_t sbox(uint32_t x)
{
    uint8_t u[4];
    *(uint32_t *)u = x;
    u[0] = SBOX[u[0]];
    u[1] = SBOX[u[1]];
    u[2] = SBOX[u[2]];
    u[3] = SBOX[u[3]];
    return *(uint32_t *)u;
}

static inline uint32_t st1(uint32_t x)
{
    x = sbox(x);
    return x ^ lshift(x, 2) ^ lshift(x, 10) ^ lshift(x, 18) ^ lshift(x, 24);
}

static inline uint32_t st2(uint32_t x)
{
    x = sbox(x);
    return x ^ lshift(x, 13) ^ lshift(x, 23);
}

/*------------------计算------------------*/
void SM4::sm4_calc_key(const uint8_t key[16], uint32_t rkey[32])
{
    uint32_t x[5];
    x[0] = load_be_u32(key);
    x[1] = load_be_u32(key + 4);
    x[2] = load_be_u32(key + 8);
    x[3] = load_be_u32(key + 12);
    x[0] ^= SM4::FK[0];
    x[1] ^= SM4::FK[1];
    x[2] ^= SM4::FK[2];
    x[3] ^= SM4::FK[3];
    for (int i = 0; i < 32; ++i)
    {
        uint32_t *y0 = x + (i % 5);
        uint32_t *y1 = x + ((i + 1) % 5);
        uint32_t *y2 = x + ((i + 2) % 5);
        uint32_t *y3 = x + ((i + 3) % 5);
        uint32_t *y4 = x + ((i + 4) % 5);
        *y4 = *y0 ^ st2(*y1 ^ *y2 ^ *y3 ^ CK[i]);
        rkey[i] = *y4;
    }
}
void SM4::sm4_calc_block(const uint32_t rkey[32], const uint8_t in[16], uint8_t out[16])
{
    uint32_t x[5];
    x[0] = load_be_u32(in);
    x[1] = load_be_u32(in + 4);
    x[2] = load_be_u32(in + 8);
    x[3] = load_be_u32(in + 12);
    for (int i = 0; i < 32; ++i)
    {
        uint32_t *y0 = x + (i % 5);
        uint32_t *y1 = x + ((i + 1) % 5);
        uint32_t *y2 = x + ((i + 2) % 5);
        uint32_t *y3 = x + ((i + 3) % 5);
        uint32_t *y4 = x + ((i + 4) % 5);
        *y4 = *y0 ^ st1(*y1 ^ *y2 ^ *y3 ^ rkey[i]);
    }
    store_be_u32(x[0], out);
    store_be_u32(x[4], out + 4);
    store_be_u32(x[3], out + 8);
    store_be_u32(x[2], out + 12);
}

/*------------------加密模式宏定义------------------*/
static inline void ecb(const uint32_t *rkey, size_t len, const uint8_t *in, uint8_t *out)
{
    for (size_t i = 0; i < len; i += 16)
    {
        SM4::sm4_calc_block(rkey, in + i, out + i);
    }
}

static inline void cbc_encrypt(const uint32_t *rkey, uint8_t *iv, size_t len, const uint8_t *plain, uint8_t *cipher)
{
    for (size_t i = 0; i < len; i += 16)
    {
        xor_block(iv, plain + i, 16);
        SM4::sm4_calc_block(rkey, iv, cipher + i);
        memcpy(iv, cipher + i, 16);
    }
}

static inline void cbc_decrypt(const uint32_t *rkey, uint8_t *iv, size_t len, const uint8_t *cipher, uint8_t *plain)
{
    for (size_t i = 0; i < len; i += 16)
    {
        SM4::sm4_calc_block(rkey, cipher + i, plain + i);
        xor_block(plain + i, iv, 16);
        memcpy(iv, cipher + i, 16);
    }
}

static inline void cfb_encrypt(const uint32_t *rkey, uint8_t *iv, size_t len, const uint8_t *plain, uint8_t *cipher)
{
    for (size_t i = 0; i < len; i += 16)
    {
        SM4::sm4_calc_block(rkey, iv, cipher + i);
        xor_block(cipher + i, plain + i, 16);
        memcpy(iv, cipher + i, 16);
    }
}

static inline void cfb_decrypt(const uint32_t *rkey, uint8_t *iv, size_t len, const uint8_t *cipher, uint8_t *plain)
{
    for (size_t i = 0; i < len; i += 16)
    {
        SM4::sm4_calc_block(rkey, iv, plain + i);
        xor_block(plain + i, cipher + i, 16);
        memcpy(iv, cipher + i, 16);
    }
}

static inline void ofb(const uint32_t *rkey, uint8_t *iv, size_t len, const uint8_t *in, uint8_t *out)
{
    for (size_t i = 0; i < len; i += 16)
    {
        SM4::sm4_calc_block(rkey, iv, out + i);
        memcpy(iv, out + i, 16);
        xor_block(out + i, in + i, 16);
    }
}

/*------------------加密模式宏定义------------------*/
void SM4::sm4_ecb_encrypt(const uint8_t *key, size_t len, const uint8_t *plain, uint8_t *cipher)
{
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);
    ecb(rkey, len, plain, cipher);
}

void SM4::sm4_ecb_decrypt(const uint8_t key[16], size_t len, const uint8_t *cipher, uint8_t *plain)
{
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);
    for (int i = 0; i < 16; ++i)
    {
        uint32_t t = rkey[i];
        rkey[i] = rkey[31 - i];
        rkey[31 - i] = t;
    }
    ecb(rkey, len, cipher, plain);
}

void SM4::sm4_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t *plain, uint8_t *cipher)
{
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);
    uint8_t out[16];
    memcpy(out, iv, 16);
    cbc_encrypt(rkey, out, len, plain, cipher);
}

void SM4::sm4_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t *cipher, uint8_t *plain)
{
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);
    for (int i = 0; i < 16; ++i)
    {
        uint32_t t = rkey[i];
        rkey[i] = rkey[31 - i];
        rkey[31 - i] = t;
    }
    uint8_t out[16];
    memcpy(out, iv, 16);
    cbc_decrypt(rkey, out, len, cipher, plain);
}

void SM4::sm4_cfb_encrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t *plain, uint8_t *cipher)
{
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);
    uint8_t out[16];
    memcpy(out, iv, 16);
    cfb_encrypt(rkey, out, len, plain, cipher);
}

void SM4::sm4_cfb_decrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t *cipher, uint8_t *plain)
{
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);
    uint8_t out[16];
    memcpy(out, iv, 16);
    cfb_decrypt(rkey, out, len, cipher, plain);
}

void SM4::sm4_ofb_en2de(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t *plain, uint8_t *cipher)
{ //加解密同
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);
    uint8_t out[16];
    memcpy(out, iv, 16);
    ofb(rkey, out, len, plain, cipher);
}

/*------------------函数加解密------------------*/
int SM4::sm4_encrypt(string &c, string m, const string &sm4_key, string iv, int mode)
{ //已知密钥,执行sm4加密,iv是初始化向量,由用户自定义
    if (m.length() % 16 != 0)
    { //补空格
        int dis = 16 - (m.length() % 16);
        for (int i = 0; i < dis; ++i)
        {
            m += ' ';
        }
    }
    int len = Getlength(m); //获取明文长度m
    if (iv.size() < 16 && mode != 1)
    {
        cout << "iv length error!";
        return 7;
    }
    string new_iv;
    if (iv.length() >= 16)
    {
        for (int i = 0; i < 16; ++i)
        {
            new_iv += iv[i];
        }
    }
    string().swap(iv);
    unsigned char *conv_iv = stringtouc(new_iv);   //仅cbc、cfb、ofb需要用户自定义初始向量
    unsigned char *conv_m = stringtouc(m);         //将加密明文转换成unsigned char
    unsigned char *conv_key = stringtouc(sm4_key); //将密钥转换成unsigned char
    auto *output = new unsigned char[len];         //为输出密文在堆上开辟长度m的空间
    switch (mode)
    { //模式选择
    case 1:
        sm4_ecb_encrypt(conv_key, len, conv_m, output);
        break;
    case 2:
        sm4_cbc_encrypt(conv_key, conv_iv, len, conv_m, output);
        break;
    case 3:
        sm4_ofb_en2de(conv_key, conv_iv, len, conv_m, output);
        break;
    case 4:
        sm4_cfb_encrypt(conv_key, conv_iv, len, conv_m, output);
        break;
    default:
        break;
    }
    string().swap(m);             //或者m.shrink_to_fit();释放内存并清空,m.clear()仅清空
    m = convert_hex(output, len); //将密文转换成16进制覆盖明文信息
    c = m;
    return 0;
}

int SM4::sm4_decrypt(string &c, string m, string sm4_key, string iv, int mode)
{ //已知密钥，执行sm4解密
    string key;
    if (iv.size() < 16 && mode != 1)
    {
        cout << "iv length error!";
        return 7;
    }
    string new_iv;
    if (iv.length() >= 16)
    {
        for (int i = 0; i < 16; ++i)
        {
            new_iv += iv[i];
        }
    }
    string().swap(iv);
    key = std::move(sm4_key);
    // key = 查询函数(sm4_skey_id)
    // sm4_ctx_t *ctx = new sm4_ctx_t();
    auto len = m.length() / 2;
    auto *output = new unsigned char[len];
    unsigned char *conv_key = stringtouc(key);
    unsigned char *conv_iv = stringtouc(new_iv);
    unsigned char *conv_m = stringtouchex(m);
    switch (mode)
    {
    case 1:
        sm4_ecb_decrypt(conv_key, len, conv_m, output);
        break;
    case 2:
        sm4_cbc_decrypt(conv_key, conv_iv, len, conv_m, output);
        break;
    case 3:
        sm4_ofb_en2de(conv_key, conv_iv, len, conv_m, output);
        break;
    case 4:
        sm4_cfb_decrypt(conv_key, conv_iv, len, conv_m, output);
        break;
    default:
        break;
    }
    string().swap(m);
    uctostring(output);
    for (int j = 0; j < len; ++j)
    {
        m += output[j];
    }
    c = m;
    return 0;
}

int SM4::sm4_encrypt(string &m, int sm4_skey_id, string iv, int mode)
{ //通过索引查询密钥
    string key;
    if (iv.size() < 16 && mode != 1)
    {
        cout << "iv length error!";
        return 7;
    }
    string new_iv;
    if (iv.size() >= 16)
    {
        for (int i = 0; i < 16; ++i)
        {
            new_iv += iv[i];
        }
    }
    string().swap(iv);
    // key = 查询函数(sm4_skey_id);
    key = "asdf1234asdf1234";
    int len = Getlength(m);
    unsigned char *conv_iv = stringtouc(new_iv);
    unsigned char *conv_m = stringtouc(m);
    unsigned char *conv_key = stringtouc(key);
    auto *output = new unsigned char[len];
    switch (mode)
    {
    case 1:
        sm4_ecb_encrypt(conv_key, len, conv_m, output);
        break;
    case 2:
        sm4_cbc_encrypt(conv_key, conv_iv, len, conv_m, output);
        break;
    case 3:
        sm4_ofb_en2de(conv_key, conv_iv, len, conv_m, output);
        break;
    case 4:
        sm4_cfb_encrypt(conv_key, conv_iv, len, conv_m, output);
        break;
    default:
        break;
    }
    string().swap(m);
    m = convert_hex(output, len);
    return 0;
}

int SM4::sm4_decrypt(string &m, int sm4_skey_id, string iv, int mode)
{ //通过索引查询密钥
    string key;
    if (iv.size() < 16 && mode != 1)
    {
        cout << "iv length error!";
        return 7;
    }
    string new_iv;
    if (iv.size() >= 16)
    {
        for (int i = 0; i < 16; ++i)
        {
            new_iv += iv[i];
        }
    }
    string().swap(iv);
    key = "asdf1234asdf1234";
    // key = 查询函数(sm4_skey_id)
    // sm4_ctx_t *ctx = new sm4_ctx_t();
    auto len = m.size() / 2;
    auto *output = new unsigned char[len];
    unsigned char *conv_key = stringtouc(key);
    unsigned char *conv_iv = stringtouc(new_iv);
    unsigned char *conv_m = stringtouchex(m);
    switch (mode)
    {
    case 1:
        sm4_ecb_decrypt(conv_key, len, conv_m, output);
        break;
    case 2:
        sm4_cbc_decrypt(conv_key, conv_iv, len, conv_m, output);
        break;
    case 3:
        sm4_ofb_en2de(conv_key, conv_iv, len, conv_m, output);
        break;
    case 4:
        sm4_cfb_decrypt(conv_key, conv_iv, len, conv_m, output);
        break;
    default:
        break;
    }
    string().swap(m);
    uctostring(output); // unsigned char转换成string输出
    for (int j = 0; j < len; ++j)
    { //截断字符串,否则解密后的明文字符串长度不对
        m += output[j];
    }
    return 0;
}

SM4::~SM4() = default;

/*------------------生成密钥------------------*/
int SM4::create_key(string &key)
{
    string strTmp = "1234567890ABCDEF";
    struct timeb timer
    {
    };
    ftime(&timer);
    srand(timer.time * 1000 + timer.millitm); //毫秒种子
    for (int i = 0; i < 16; i++)
    {
        int j = rand() % 16;
        key += strTmp.at(j);
    }
    return 0;
}