#ifndef _TOOL_
#define _TOOL_
#include <vector>
#include <string>
#include <gmpxx.h>
#include "../include/sm3.h"
#include "../include/sm4.h"
using namespace std;

/**
 * @brief 生成search token
 *
 * @param stoken search token
 * @param query 单关键词查询
 * @param key 密钥
 * @param N 公开参数
 */
void gen_search_token(string &stoken, string query, string key, string N);

/**
 * @brief 生成可以解密相应id号的密钥
 *
 * @param dkey 解密密钥
 * @param query 单关键词查询
 * @param key 密钥
 * @param N 公开参数
 */
void gen_decrypt_key(string &dkey, string query, string key, string N);

/**
 * @brief 解密当前全体id密文
 *
 * @param plain id明文
 * @param cipher id密文
 * @param dkey 解密密钥
 */
void decrypt_id(vector<string> &plain, vector<string> cipher, string dkey);
#endif