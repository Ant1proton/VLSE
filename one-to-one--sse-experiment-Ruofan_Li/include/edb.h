#ifndef _EDB_
#define _EDB_
#include "../include/sm3.h"
#include "../include/sm4.h"
#include "../include/util.h"
#include "../include/database.h"
#include <fstream>
#include <map>
#include <vector>
#include <string>
#include <gmpxx.h>
using namespace std;

/**
 * @brief 生成加密数据库edb
 *
 * @param edb 加密数据库
 * @param DB_invert 反向索引数据库
 * @param key 用于加密每个关键词对应的密钥(计算H(word)^key(mod N))
 * @param prf_key 计算关键词对应的伪随机函数值(H(word)^prf_key(mod N)）
 * @param N 公开参数
 */
void edb_gen(map<string, vector<string> > &edb, map<string, vector<string> > DB_invert, string key, string prf_key, string N);

/**
 * @brief 写入加密数据库
 *
 * @param path 输出路径
 * @param edb 需要备份的加密数据库
 * @return int 成功返回1,失败返回0
 */
int write_edb(string &path, map<string, vector<string> > edb);

/**
 * @brief 读取加密数据库
 *
 * @param edb 需要读取的加密数据库
 * @param path 加密数据库路径
 * @return int 成功返回1,失败返回0
 */
int read_edb(map<string, vector<string> > &edb, string path);
#endif