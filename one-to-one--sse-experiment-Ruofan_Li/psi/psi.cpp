#include "../include/psi.h"
// labeled psi相应流程预留
/**
 * @brief 运行labeled PSI协议(直接模拟客户端和服务器,不模拟对应交互)
 *
 * @param intersection 计算出来的交集信息
 * @param server_set 服务器的全体数据集(即加密后的edb)
 * @param search_token 客户端的查询token
 */
void get_intersection(map<string, vector<string> > &intersection, map<string, vector<string> > server_set, string search_token)
{
}

/**
 * @brief 解密当前全体label
 *
 * @param label 解密返回的id号
 * @param intersection labeled PSI交集
 * @param dec_key 解密密钥
 */
void decrypt_label(vector<string> &label, map<string, vector<string> > intersection, string dec_key)
{
    map<string, vector<string> >::iterator it = intersection.begin();
    label = it->second;
    for (int i = 0; i < label.size(); ++i)
    {
        SM4::sm4_decrypt(label[i], label[i], dec_key, "123456789012345", 1);
    }
}