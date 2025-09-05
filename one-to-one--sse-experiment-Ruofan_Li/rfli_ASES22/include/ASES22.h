#pragma once
#include <string>
#include <iostream>
#include <map>
#include <vector>
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <unordered_set>
#include "BCP.h"
#include "database.h"

using namespace std;
using namespace NTL;

class ASES22
{
private:
    long security_para = 128;

    BCP bcp; //这个加密类在本类被初始化的时候同时被初始化

    ZZ p; //模数p，这个模数应当比BCP加密中的模数N要小

    Mat<ZZ_Cipher> index_I;

    vector<string> words; //用于存放全部关键字

public:
    ASES22(/* args */);

    void Setup();

    /**
     * @brief 这里根据论文中的逻辑，把后向索引转换为index_I
     *
     */
    Mat<ZZ_Cipher> Index_I_Gen(string path);

    /**
     * @brief data user给了data owner所要查询的关键字集合，然后data owner对这些关键字
     * 加密，输出一个陷门Tr。需要注意的是这里的data owner需要对所有的关键字进行加密（包括
     * data user查询的和未查询的）
     *
     * @param queries data user查询的关键字集合
     *
     * @return Vec<ZZ_Cipher> 陷门Tr，大小等于全体关键字的集合大小
     */
    Vec<ZZ_Cipher> TGen(vector<string> queries);

    /**
     * @brief 这是由Cloud Server C1和Auxiliary Server完成的操作，服务器在得到Date owner
     * 发送过来的Search Token之后，输出一个加密的多项式
     *
     * @param Tr 由TGen函数生成的陷门
     * @param index_I 由Index_I_Gen函数生成的加密多项式矩阵
     * @return Vec<ZZ_Cipher> 返回给Data User的加密多项式
     */
    Vec<ZZ_Cipher> Search(const Vec<ZZ_Cipher> &Tr, const Mat<ZZ_Cipher> &index_I);

    /**
     * @brief 交给data user的解密函数，遍历定义域U来找到对应的id号
     * 
     * @param enc_poly Search函数返回的加密多项式
     * @return vector<string> 最终的结果，id号
     */
    vector<string> Decrypt(Vec<ZZ_Cipher> enc_poly);

    string numberToString(ZZ num);
};
