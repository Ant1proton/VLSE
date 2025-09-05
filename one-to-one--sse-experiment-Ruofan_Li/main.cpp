#include <iostream>
#include <map>
#include <string>
#include <vector>
#include "include/database.h"
#include "include/edb.h"
#include "include/tool.h"
using namespace std;
int main()
{
    string front_path = "../database/word_id_pair_front_index1";
    string inverted_path = "../database/word_id_pair_inverted_index1";
    map<string, vector<string> > edb;
    map<string, vector<string> > invert_DB = DB_build_by_inverted(inverted_path);
    edb_gen(edb, invert_DB, "123456789", "12345678", "abcdefabcdef");
    string path = "../encrypt_db/edb1";
    write_edb(path, edb);
    edb.clear();
    read_edb(edb, path);
    string query = "spoke";
    string token, dkey;
    //生成search token
    gen_search_token(token, query, "12345678", "abcdefabcdef");
    cout << token << endl;
    //生成解密私钥
    gen_decrypt_key(dkey, query, "123456789", "abcdefabcdef");
    //解密当前id号
    vector<string> cipher = edb[token];
    vector<string> plain;
    cout << dkey << endl;
    decrypt_id(plain, cipher, dkey);
    for (int i = 0; i < plain.size(); ++i)
    {
        cout << plain[i] << endl;
    }
    return 0;
}