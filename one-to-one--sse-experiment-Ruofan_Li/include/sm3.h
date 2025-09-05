/********* SM3.cpp *********
      SM3算法接口定义头文件
            ghf
         2022/04/06
****** @company TTAI ******/
#ifndef SM3_HASH_H
#define SM3_HASH_H

#include <string>

using namespace std;

class SM3
{
public:
    typedef struct
    {
        unsigned int IV[8];
        unsigned char m[64];
        unsigned int len;
    } SM3_state;

    static int sm3(string &hash, string m);
    //仅供sm2使用
    static int SM3_Hash(unsigned char *msg, unsigned int msg_len, unsigned char *hash, unsigned int hash_len);
    static int SM3_HASH(unsigned char *msg, unsigned int msg_len, unsigned int all_len, unsigned char *hash,
                        unsigned int hash_len, unsigned int flag);
    ~SM3();

private:
    static unsigned char *s2uc(const string &str);                                              //将string转换成unsigned char*
    static string convert_hex(const unsigned char *md /*字符串*/, int nLen /*转义多少个字符*/); //将unsigned char* 转换成十六进制的字符串
    static void SM3_Compress(SM3_state *ctx);
    /***************************************************
    * function			   : SM3_Init
    * description		   : 哈希初始化
    * parameters:
    -- ctx[out]		   : 哈希上下文
    * return 			   : void
    ***************************************************/
    static void SM3_Init(SM3_state *ctx);

    /***************************************************
    * function			   : SM3_Update
    * description		   : 哈希更新
    * parameters:
    -- ctx[in]		   : 哈希上下文
    -- data[in]	       : 数据长度
    -- data_len[in]    : 数据长度(字节数)
    * return 			   : 0--success;
    非0--error code
    ***************************************************/
    static int SM3_Update(SM3_state *ctx, const unsigned char *data, unsigned int data_len);

    /***************************************************
    * function			   : SM3_Final
    * description		   : 哈希结束
    * parameters:
    -- hash[out]	   : 哈希值
    -- hash_len[in]	   : 哈希值长度
    -- ctx[in]	       : 哈希上下文
    -- data_len[in]	   : 数据总长度
    * return 			   : 0--success;
    非0--error code
    ***************************************************/
    static int SM3_Final(unsigned char *hash, unsigned int hash_len, SM3_state *ctx, unsigned int data_len);
};

#endif // SM3_HASH_H