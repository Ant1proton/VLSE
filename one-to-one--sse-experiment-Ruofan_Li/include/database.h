#ifndef _DATABASE_
#define _DATABASE_
#include <fstream>
#include <vector>
#include <map>
#include <string>
using namespace std;
/**
 * @brief 导入数据库
 *
 * @param path 数据库(inverted_index)
 * @return map<string, vector<string> >  导入的数据库
 */
map<string, vector<string> > DB_build_by_inverted(string path);

/**
 * @brief 导入数据库
 *
 * @param path 数据库(front_index)
 * @return map<string, vector<string> >  导入的数据库
 */
map<string, vector<string> > DB_build_by_front(string path);

/**
 * @brief Get the id object
 *
 * @param temp 字符串
 * @return vector<string> 导出id号列表
 */
vector<string> get_id(string temp);

#endif