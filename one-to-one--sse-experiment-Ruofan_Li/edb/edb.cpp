#include "../include/edb.h"

/**
 * @brief 生成加密数据库edb
 *
 * @param edb 加密数据库
 * @param DB_invert 反向索引数据库
 * @param key 用于加密每个关键词对应的密钥(计算H(word)^key(mod N))
 * @param prf_key 计算关键词对应的伪随机函数值(H(word)^prf_key(mod N)）
 * @param N 公开参数
 */
void edb_gen(map<string, vector<string> > &edb, map<string, vector<string> > DB_invert, string key, string prf_key, string N)
{
    //解密如果存在相应的密文token，则验证成功
    string token(64, 'A');
    long count = 0;
    vector<string> id_list;
    map<string, vector<string> >::iterator it = DB_invert.begin();
    //初始化公开参数N,密钥key,伪随机函数密钥prf_key
    if (key.substr(0, 1) != "0x")
        key = "0x" + key;
    if (prf_key.substr(0, 1) != "0x")
        prf_key = "0x" + prf_key;
    if (N.substr(0, 1) != "0x")
        N = "0x" + N;
    // pass
    //  cout<<key<<endl<<prf_key<<endl<<N<<endl;
    mpz_t prf_key_t, key_t, N_t;
    mpz_init_set_str(prf_key_t, prf_key.c_str(), 0);
    mpz_init_set_str(key_t, key.c_str(), 0);
    mpz_init_set_str(N_t, N.c_str(), 0);
    // pass
    //  gmp_printf("%Zd,%Zd,%Zd",prf_key_t,key_t,N_t);
    mpz_t prf, hash;
    mpz_init(prf);
    mpz_init(hash);
    //计算伪随机函数和相应的hash值
    string prf_temp, hash_temp;
    //加密数据库
    while (it != DB_invert.end())
    {
        string word = it->first;
        id_list = it->second;
        //计算H(word)^prf_key
        SM3::sm3(prf_temp, word);
        mpz_set_str(prf, prf_temp.c_str(), 0);
        mpz_powm(prf, prf, prf_key_t, N_t);
        prf_temp = mpz_get_str(NULL, 16, prf);
        //计算H(word)^key,暂时预留
        SM3::sm3(hash_temp, word);
        mpz_set_str(hash, hash_temp.c_str(), 0);
        mpz_powm(hash, hash, key_t, N_t);
        hash_temp = mpz_get_str(NULL, 16, hash);
        SM3::sm3(hash_temp, hash_temp);
        hash_temp = hash_temp.substr(2, 17);
        //计算每个id号的密文
        for (int i = 0; i < id_list.size(); ++i)
        {
            //拼接id+token+随机数,形成新的密文
            id_list[i] = id_list[i] + token + to_string(count);
            ++count;
            SM4::sm4_encrypt(id_list[i], id_list[i], hash_temp, "123456789012345", 1);
        }

        //将word和id_list对应并输出
        edb[prf_temp] = id_list;
        id_list.clear();
        ++it;
    }
}

/**
 * @brief 写入加密数据库
 *
 * @param path 输出路径
 * @param edb 需要备份的加密数据库
 * @return int 成功返回1,失败返回0
 */
int write_edb(string &path, map<string, vector<string> > edb)
{
    ofstream out(path);
    map<string, vector<string> >::iterator it;
    it = edb.begin();
    vector<string> temp;
    int i;
    while (it != edb.end())
    {
        out << it->first << ":";
        temp = it->second;
        for (i = 0; i < temp.size() - 1; ++i)
        {
            out << temp[i] << "|";
        }
        out << temp[i];
        out << endl;
        temp.clear();
        ++it;
    }
    out.close();
}

/**
 * @brief 读取加密数据库
 *
 * @param edb 需要读取的加密数据库
 * @param path 加密数据库路径
 * @return int 成功返回1,失败返回0
 */
int read_edb(map<string, vector<string> > &edb, string path)
{
    int i;
    string str;
    map<string, vector<string> > EDB;
    string word, temp;
    vector<string> id;
    ifstream in(path);
    int count = 0;
    while (getline(in, temp))
    {
        i = temp.find_first_of(':');
        word = temp.substr(0, i);
        temp = temp.substr(i + 1, temp.size());
        id = get_id(temp);
        edb[word] = id;
        id.clear();
    }

    in.close();
}
