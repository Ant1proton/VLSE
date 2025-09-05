#ifndef _DATABASE_
#define _DATABASE_
#include <fstream>
#include <vector>
#include <map>
#include <string>
using namespace std;
//这个database没有实现具体的算法。需要参考后续调用的map来实现。
/**
 * @brief 导入数据库
 *
 * @param path 数据库(inverted_index)
 * @return map<string, vector<string> >  导入的数据库

map<string, vector<string>> DB_build_by_inverted(string path);
 */
std::map<std::string, std::vector<std::string>> DB_build_by_inverted(const std::string &path);

/**
 * @brief 导入数据库
 *
 * @param path 数据库(front_index)
 * @return map<string, vector<string> >  导入的数据库
map<string, vector<string> > DB_build_by_front(string path);
 */
/**
 * @brief Get the id object
 *
 * @param temp 字符串
 * @return vector<string> 导出id号列表
 */


#endif