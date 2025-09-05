#ifndef XYSSL_CONV_H
#define XYSSL_CONV_H
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <string>
//#include "../key_management/master_key.h"
using namespace std;

//十六进制字符
//把一个无符号型的字符数组从下标0开始，每一个无符号字符转化成16进制数.
/*
 * 例如：
 * md={1,2,3,4,5,6}->"010203040506",注意：1是整数1，而非'1'.
 */
string convert_hex(unsigned char *md /*字符串*/, int nLen /*转义多少个字符*/); //将unsigned char* 转换成十六进制的字符串、

//string每两个char一组，以16进制的方式转化成无符号的字符数组
/*
例:
"010203040506"=>{1,2,3,4,5,6}
*/
unsigned char *stringtouchexs(string str);

//将字符串str变成无符号字符数组形式的字符串。
/*例如：
 * “010203040506”->{'0','1','0','2','0','3','0','4','0','5','0','6'}
 * */
unsigned char *stringtouc(string str);

/**
 * 此函数和stringtouc是互逆的
 * @param c 待转换的字符数组
 * @return
 */
string uctostring(unsigned char *c, int c_len);       //将unsigned char*转换成string


int GetTextLength(unsigned char *in_data); //计算unsigned char*的长度
int Getlength(string str);                 //计算明文填充后总长度,应为16的倍数

#endif
