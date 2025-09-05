#ifndef _UTIL_
#define _UTIL_
#include <string>
#include <vector>
using namespace std;
//十进制转十六进制
string dec_to_hex(vector<int> dec);
//十六进制转十进制
vector<int> hex_to_dec(string hex);
//计算二进制的异或值
vector<int> operator^(vector<int> a, vector<int> b);
#endif