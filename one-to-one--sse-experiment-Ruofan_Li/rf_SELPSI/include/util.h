#pragma once

#include <NTL/ZZ.h>
#include <iostream>
#include <string>
#include <aes.h>
#include <time.h>
#include <fstream>
#include <siphash.h>
#include <randpool.h>

using namespace std;
using namespace NTL;
using namespace CryptoPP;

//分割字符串
vector<string> split(const string line, const string sep);

//去除字符串首尾的空格
string &trim(string &s);

//去除字符串当中非数字部分
string &erasePending(string &str);
