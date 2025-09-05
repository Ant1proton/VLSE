#ifndef _STORE_FILE_
#define _STORE_FILE
#include <string>
#include <fstream>
using namespace std;
struct MK
{
    string sk;
};
struct EDB
{
};
/**
 * @brief EDB写操作,返回文件路径
 *
 * @param path 文件路径
 * @param edb 加密数据库
 */
void write_EDB(string path, EDB edb);

/**
 * @brief EDB读操作
 *
 * @param path 文件路径
 * @return EDB 加密数据库
 */
EDB read_EDB(string path);

/**
 * @brief MK写操作，返回文件路径
 *
 * @param path 文件路径
 * @param mk 密钥
 */
void write_MK(string path, MK mk);

/**
 * @brief MK读操作
 *
 * @param path 文件路径
 * @return MK 密钥
 */
MK read_MK(string path);

/**
 * @brief 导出公开参数
 *
 * @param path 文件路径
 */
void write_pub_para(string path);

/**
 * @brief 导入公开参数
 *
 * @param path 文件路径
 */
void read_pub_para(string path);
#endif
