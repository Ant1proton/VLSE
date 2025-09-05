#include "../include/tool.h"
/**
 * @brief 生成search token
 *
 * @param stoken search token
 * @param query 单关键词查询
 * @param key 密钥
 * @param N 公开参数
 */
void gen_search_token(string &stoken, string query, string key, string N)
{
    if (key.substr(0, 1) != "0x")
        key = "0x" + key;
    if (N.substr(0, 1) != "0x")
        N = "0x" + N;
    mpz_t stoken_t, key_t, N_t;
    mpz_init_set_str(key_t, key.c_str(), 0);
    mpz_init_set_str(N_t, N.c_str(), 0);
    SM3::sm3(stoken, query);
    mpz_init_set_str(stoken_t, stoken.c_str(), 0);
    mpz_powm(stoken_t, stoken_t, key_t, N_t);
    stoken = mpz_get_str(NULL, 16, stoken_t);
}

/**
 * @brief 生成可以解密相应id号的密钥
 *
 * @param dkey 解密密钥
 * @param query 单关键词查询
 * @param key 密钥
 * @param N 公开参数
 */
void gen_decrypt_key(string &dkey, string query, string key, string N)
{
    if (key.substr(0, 1) != "0x")
        key = "0x" + key;
    if (N.substr(0, 1) != "0x")
        N = "0x" + N;
    mpz_t dkey_t, key_t, N_t;
    mpz_init_set_str(key_t, key.c_str(), 0);
    mpz_init_set_str(N_t, N.c_str(), 0);
    SM3::sm3(dkey, query);
    mpz_init_set_str(dkey_t, dkey.c_str(), 0);
    mpz_powm(dkey_t, dkey_t, key_t, N_t);
    dkey = mpz_get_str(NULL, 16, dkey_t);
    SM3::sm3(dkey, dkey);
    dkey = dkey.substr(2, 17);
}

/**
 * @brief 解密当前全体id密文
 *
 * @param plain id明文
 * @param cipher id密文
 * @param dkey 解密密钥
 */
void decrypt_id(vector<string> &plain, vector<string> cipher, string dkey)
{
    plain.resize(cipher.size());
    for (int i = 0; i < cipher.size(); ++i)
    {
        SM4::sm4_decrypt(plain[i], cipher[i], dkey, "123456789012345", 1);
    }
}