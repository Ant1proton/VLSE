#include "util.h"
#include "Pub_para.h"
#include "database.h"
#include <sys/stat.h> // 添加头文件
#include <chrono> // 添加头文件
#include <cryptlib.h>
#include <osrng.h> // 包含 AutoSeededRandomPool 的头文件
#include <sha.h> // Crypto++ 的 SHA-256 头文件
#include "Vacuum-Filter/vacuum_zz.h"
#include<random>
using namespace std;
using namespace NTL;
using namespace CryptoPP;

Pub_para PUB_PARA;
const static string DATASET_PATH = "/Users/chenyuwei/Desktop/one-to-one--sse-experiment-Ruofan_Li/rf_SELPSI/data/data14_10";
const static int SEARCH_KEYWORDS_NUM = 50;  // 设置要查询的关键词数量
const static int FP_LENGTH = 30;  // 指纹长度(bits)，可以根据需要调整
const static int FILE_NUM = 10;
const static int KEY_LEN = 16;
const static int MAX_BINS_SIZE = (int)(16384*2);
const static double FALSE_POSITIVE = 1e-6; // 假阳性率
const static int MAX_RELOCATIONS = 1500; // 最大重定位次数
Vec<ZZ> cuckoo_bins;     //布谷鸟哈希桶cout << "N = " << PUB_PARA.N << endl;
bool vis[MAX_BINS_SIZE]; //判定哈希桶当中是否有元素
VacuumFilterZZ<FP_LENGTH> vf;

ZZ CryptographicHash(const ZZ& input) {
    // 将 ZZ 转换为字节数组
    SecByteBlock input_bytes(NumBytes(input));
    BytesFromZZ(input_bytes, input, input_bytes.size());

    // 使用 SHA-256 计算哈希值
    CryptoPP::SHA256 hash;
    SecByteBlock hash_output(hash.DigestSize());
    hash.Update(input_bytes, input_bytes.size());
    hash.Final(hash_output);

    // 截断为 128 位
    SecByteBlock truncated_hash_output(16);
    memcpy(truncated_hash_output, hash_output, 16);

    // 将截断后的哈希值转换为 ZZ 类型
    ZZ hash_ZZ = ZZFromBytes(truncated_hash_output, truncated_hash_output.size());
    return hash_ZZ;
}

ZZ HashFunction1(const ZZ& input) {
    // 添加前缀或后缀以区分
    ZZ modified_input = input + ZZ(1); // 添加一个固定值
    return CryptographicHash(modified_input);
}

ZZ HashFunction2(const ZZ& input) {
    // 添加前缀或后缀以区分
    ZZ modified_input = input + ZZ(2); // 添加另一个固定值
    return CryptographicHash(modified_input);
}

size_t GetZZSize(const ZZ& value) {
   return NumBytes(value); // 返回 `ZZ` 类型的实际字节数
}

ZZ Get_search_token_from_string(string search_word, ZZ alpha)
{
   // 关键字转为二进制数据
   SecByteBlock search_word_byte((byte *)search_word.c_str(), search_word.size());
   PUB_PARA.siphash.Update(search_word_byte, search_word_byte.size());
   
   // 关键字的哈希值
   SecByteBlock hashed_search_word_byte(KEY_LEN);
   PUB_PARA.siphash.Final(hashed_search_word_byte);
   
   // byte* 格式转换为 ZZ，需要注意不能越界
   ZZ hashed_search_word_ZZ(ZZFromBytes(hashed_search_word_byte, hashed_search_word_byte.size()) % PUB_PARA.N);
   
   // 关键字哈希值的 alpha 次幂
   ZZ search_token(PowerMod(hashed_search_word_ZZ, alpha, PUB_PARA.N));
   return search_token;
}

ZZ Get_sym_key_from_string(string search_word, ZZ beta)
{
   // 关键字转为二进制数据
   SecByteBlock search_word_byte((byte *)search_word.c_str(), search_word.size());
   PUB_PARA.siphash.Update(search_word_byte, search_word_byte.size());
   
   // 关键字的哈希值
   SecByteBlock hashed_search_word_byte(KEY_LEN);
   PUB_PARA.siphash.Final(hashed_search_word_byte);
   
   // byte* 格式转换为 ZZ，需要注意不能越界
   ZZ hashed_search_word_ZZ(ZZFromBytes(hashed_search_word_byte, hashed_search_word_byte.size()) % PUB_PARA.N);
   
   // 关键字哈希值的 beta 次幂
   ZZ sym_key(PowerMod(hashed_search_word_ZZ, beta, PUB_PARA.N));
   return sym_key;
}

ZZ Get_search_token_from_string(ZZ search_word_ZZ, ZZ alpha)
{
   // 关键字哈希值的 alpha 次幂
   ZZ search_token(PowerMod(search_word_ZZ, alpha, PUB_PARA.N));
   return search_token;
}

ZZ Get_sym_key_from_string(ZZ search_word_ZZ, ZZ beta)
{
   
   ZZ sym_key(PowerMod(search_word_ZZ, beta, PUB_PARA.N));
   return sym_key;
}

void Gene_encrypted_data(string file_path)
{
    cout << endl;
    cout << "------------------加密数据开始----------------" << endl;
    cout << "读取文件：" << file_path << endl;
    map<string, vector<string>> inverted_DB = DB_build_by_inverted(file_path);
    ofstream outfile("../data/erypted_data.txt");
    if (!outfile.is_open())
    {
        cout << "error" << endl;
        return;
    }
    cout << "文件读取完成，生成加密数据库当中..." << endl;

    int DB_size = inverted_DB.size();
    int cur = 0;


    for (auto each : inverted_DB)
    {
        // 调用函数时传递 PUB_PARA.alpha 和 PUB_PARA.beta
        ZZ temp = Get_search_token_from_string(each.first, PUB_PARA.beta);
        ZZ token= HashFunction1(temp);
        ZZ sym_key = HashFunction2(temp);
        outfile << token;

        // 用关键字哈希值的 beta 次幂生成 aes 加解密密钥
        SecByteBlock aesKey(KEY_LEN);
        BytesFromZZ(aesKey, sym_key, KEY_LEN);

        for (auto label_str : each.second)
        {
            // 加密每一个关键字对应的 label
            trim(label_str);
            erasePending(label_str);
            SecByteBlock label((byte *)label_str.c_str(), label_str.size());
            SecByteBlock label_enc = PUB_PARA.aes_Enc(aesKey, label);
            

            outfile << "\t";
            // 注意，SecByteBlock 一定要转换为 ZZ 然后再存储
            ZZ label_enc_ZZ = ZZFromBytes(label_enc, label_enc.size());
           // cout << "label size: " << GetZZSize(label_enc_ZZ) << endl;
            outfile << label_enc_ZZ;
        }
        outfile << "\n";
        printf("\033[32m%.2lf%%\r\033[0m", (++cur) * 100.0 / DB_size);
    }
    cout << endl;
    outfile.close();
    cout << "加密数据库生成完成，文件存放于\"../data/erypted_data.txt\"" << endl;
}

// token的第k个哈希值在布谷鸟哈希桶当中的位置
int Get_hash_position(ZZ token, int k)
{
   if (k >= PUB_PARA.NUM_OF_CUCKOO_HASH || k < 0)
   {
      cout << "k is out of range" << endl;
      return -1;
   }
   SecByteBlock temp(KEY_LEN);
   BytesFromZZ(temp, token, KEY_LEN);
   PUB_PARA.hash_list[k].Update(temp, temp.size());
   SecByteBlock hashcode(KEY_LEN);
   PUB_PARA.hash_list[k].Final(hashcode);

   ZZ pos;
   pos = ZZFromBytes(hashcode, hashcode.size()) % ZZ(MAX_BINS_SIZE);

   return to_int(pos);
}

bool Cuckoo_hash(ZZ target) {
    for (int relocation_count = 0; relocation_count < MAX_RELOCATIONS; ++relocation_count) {
        for (int i = 0; i < PUB_PARA.NUM_OF_CUCKOO_HASH; ++i) {
            int pos = Get_hash_position(target, i);
            if (!vis[pos]) {
                vis[pos] = true;
                cuckoo_bins[pos] = target;
                return true; // 插入成功
            }
        }

        // 如果当前位置被占用，则踢出当前元素并重新插入
        int pos = Get_hash_position(target, rand() % PUB_PARA.NUM_OF_CUCKOO_HASH);
        swap(target, cuckoo_bins[pos]);
    }

    // 如果到达这里，说明插入失败
    cout << "警告: 布谷鸟哈希失败，无法插入 " << target << endl;
    return false;
}

SecByteBlock GenerateRandomBlock(size_t size) {
    SecByteBlock block(size);
    AutoSeededRandomPool rng; // 使用 Crypto++ 的随机数生成器
    rng.GenerateBlock(block, size);
    return block;
}

void FillEmptyCuckooHashSlots(size_t label_size, map<ZZ, Vec<ZZ>>& encrypted_data) {
    for (int i = 0; i < MAX_BINS_SIZE; ++i) {
        if (!vis[i]) {
            // 生成随机数据填充空余位置
            SecByteBlock random_data = GenerateRandomBlock(label_size);
            ZZ random_data_ZZ = ZZFromBytes(random_data, random_data.size());
            cuckoo_bins[i] = random_data_ZZ;
            vis[i] = true;

            // 生成对应的随机标签并添加到 encrypted_data 中
            Vec<ZZ> temp_vec;
            for (int j = 0; j < 1; // 为每个随机串生成 1 个随机标签密文
            ++j) {
                SecByteBlock random_label = GenerateRandomBlock(label_size);
                temp_vec.append(ZZFromBytes(random_label, random_label.size()));
            }
            encrypted_data[random_data_ZZ] = temp_vec;
        }
    }
}

void DebugCuckooHash(const map<ZZ, Vec<ZZ>>& encrypted_data) {
    cout << "布谷鸟哈希桶状态：" << endl;
    for (int i = 0; i < MAX_BINS_SIZE; ++i) {
        if (vis[i]) {
            cout << "桶[" << i << "] = " << cuckoo_bins[i] << endl;
        } else {
            cout << "桶[" << i << "] = 空" << endl;
        }
    }

    cout << "加密数据映射表：" << endl;
    for (const auto& pair : encrypted_data) {
        cout << "Token: " << pair.first << " -> Labels: ";
        for (const auto& label : pair.second) {
            cout << label << " ";
        }
        cout << endl;
    }
}

map<ZZ, Vec<ZZ>> Read_EDB_file(string file_path)
{
   cout << endl;
   cout << "------------读取加密数据库-------------" << endl;
   ifstream infile(file_path);
   cout << "读取文件：" << file_path << endl;
   map<ZZ, Vec<ZZ>> encrypted_data;
   if (!infile.is_open())
   {
      cout << "文件\"" << file_path << "\"打开失败" << endl;
      return encrypted_data;
   }

   //先构建映射表存储加密过后的数据

   cout << "构建映射表..." << endl;
   string str;
   while (getline(infile, str))
   {
      vector<string> each_line = split(str, "\t");
      ZZ token;
      conv(token, each_line[0].c_str());

      Vec<ZZ> temp;
      for (int i = 1; i < each_line.size(); i++)
      {
         temp.append(to_ZZ(each_line[i].c_str()));
      }

      encrypted_data[token] = temp;
   }
   cout << "文件读入完成，映射表已构建" << endl;
   cout << "-----------------------------------" << endl;
   cout << endl;
   return encrypted_data;
}

// 在 main 函数前添加
vector<string> GetRandomKeywords(const string& file_path, int num_keywords) {
    map<string, vector<string>> inverted_DB = DB_build_by_inverted(file_path);
    vector<string> all_keywords;
    
    // 收集所有关键词
    for (const auto& pair : inverted_DB) {
        all_keywords.push_back(pair.first);
    }
    
    // 随机打乱关键词
    random_device rd;
    mt19937 gen(rd());
    shuffle(all_keywords.begin(), all_keywords.end(), gen);
    
    // 选择指定数量的关键词
    vector<string> selected_keywords;
    for (int i = 0; i < min(num_keywords, (int)all_keywords.size()); i++) {
        selected_keywords.push_back(all_keywords[i]);
    }
    
    return selected_keywords;
}

void TestVacuumFilter() {
    cout << "\n开始测试 VacuumFilter...\n" << endl;

    // 初始化 VacuumFilter
    VacuumFilterZZ<FP_LENGTH> test_vf;
    test_vf.Init(MAX_BINS_SIZE, FALSE_POSITIVE);

    // 插入测试数据
    vector<ZZ> test_tokens;
    for (int i = 0; i < 1000; ++i) {
        ZZ token = RandomBits_ZZ(FP_LENGTH); // 生成随机 token
        test_tokens.push_back(token);
        if (!test_vf.Insert(token)) {
            cout << "错误: 无法插入 token " << token << " 到 VacuumFilter 中。" << endl;
        }
    }

    // 测试查询
    int found_count = 0;
    for (const auto& token : test_tokens) {
        if (test_vf.Lookup(token)) {
            found_count++;
        } else {
            cout << "警告: 无法在 VacuumFilter 中找到 token " << token << endl;
        }
    }

    // 输出测试结果
    cout << "\nVacuumFilter 测试完成。" << endl;
    cout << "插入的 token 数量: " << test_tokens.size() << endl;
    cout << "查询成功的 token 数量: " << found_count << endl;
    cout << "查询成功率: " << fixed << setprecision(2) << (found_count * 100.0 / test_tokens.size()) << "%" << endl;
}

int main() {
    vf.Init(MAX_BINS_SIZE, FALSE_POSITIVE); 
    auto start_time1 = chrono::high_resolution_clock::now(); // 开始计时
    Gene_encrypted_data(DATASET_PATH);
    auto end_time1 = chrono::high_resolution_clock::now(); // 结束计时
    // 使用微秒计时,然后除以1000转换为毫秒
    double elapsed_time1 = chrono::duration_cast<chrono::microseconds>(end_time1 - start_time1).count() / 1000.0;
    cout << "密文集合生成时间：" << fixed << setprecision(3) << elapsed_time1 << " 毫秒" << endl;

    // 读取数据，并且将数据映射到布谷鸟哈希桶当中
    map<ZZ, Vec<ZZ>> encrypted_data = Read_EDB_file("../data/erypted_data.txt");

    cuckoo_bins.SetLength(MAX_BINS_SIZE); // 设置哈希桶长度
    fill(vis, vis + MAX_BINS_SIZE, 0);    // 初始化哈希桶为空

    // 把 token 映射到VF当中
    for (auto each_data : encrypted_data) {
        if (!vf.Insert(each_data.first)) {
            cout << "错误: 无法插入 token " << each_data.first << endl;
        }
    }

    // 填充空余位置
   // FillEmptyCuckooHashSlots(KEY_LEN, encrypted_data);

    // 替换原有的查询代码
    // 获取随机关键词
    vector<string> search_keywords = GetRandomKeywords(DATASET_PATH, SEARCH_KEYWORDS_NUM);

    cout << "\n开始查询 " << SEARCH_KEYWORDS_NUM << " 个随机关键词...\n" << endl;

    double total_search_time = 0.0;
    int found_count = 0;

    for (int i = 0; i < search_keywords.size(); i++) {
        cout << "\n查询第 " << (i+1) << " 个关键词: " << search_keywords[i] << endl;
        
        auto start_time = chrono::high_resolution_clock::now();
        
        // 生成查询 token 和对称密钥
        ZZ search_temp = Get_search_token_from_string(search_keywords[i], PUB_PARA.alpha);
        search_temp = Get_search_token_from_string(search_temp, PUB_PARA.beta);
        search_temp = Get_search_token_from_string(search_temp, PUB_PARA.alpha_inv);
        ZZ search_token = HashFunction1(search_temp);
        ZZ sym_key = HashFunction2(search_temp);
        
        vector<SecByteBlock> labels;
        bool found = vf.Lookup(search_token);
        if (found) {
            found_count++;
            Vec<ZZ> encrypted_labels = encrypted_data[search_token];
            for (ZZ each : encrypted_labels) {
                SecByteBlock temp(KEY_LEN);
                BytesFromZZ(temp, each, temp.size());
                
                SecByteBlock sym_key_byte(KEY_LEN);
                BytesFromZZ(sym_key_byte, sym_key, sym_key_byte.size());
                temp = PUB_PARA.aes_Dec(sym_key_byte, temp);
                labels.push_back(temp);
            }
        }
        
        auto end_time = chrono::high_resolution_clock::now();
        double elapsed_time = chrono::duration_cast<chrono::microseconds>(end_time - start_time).count() / 1000.0;
        total_search_time += elapsed_time;
        if (i==49||i==4||i==9||i==19||i==29||i==39||i==0)
        {
          cout << "\n查询" << (i+1) << " 个关键词的耗时：" << total_search_time << endl;
        }
        // 输出查询结果
        //cout << "查询时间：" << fixed << setprecision(3) << elapsed_time << " 毫秒" << endl;
       if (found) {
            cout << "\033[32m---------------查询结果----------------" << endl;
            for (auto each_label : labels) {
                for (auto each_byte : each_label) {
                    cout << each_byte;
                }
                cout << endl;
            }
            cout << "--------------------------------------\033[0m" << endl;
        } else {
            
            cout << "未找到关键字对应的标签。" << endl;
        }
    }

    // 输出统计信息
    cout << "\n查询统计:" << endl;
    cout << "总查询时间: " << fixed << setprecision(3) << total_search_time << " 毫秒" << endl;
    cout << "平均查询时间: " << fixed << setprecision(3) << total_search_time / SEARCH_KEYWORDS_NUM << " 毫秒" << endl;
    cout << "查询成功率: " << fixed << setprecision(2) << (found_count * 100.0 / SEARCH_KEYWORDS_NUM) << "%" << endl;

    // 填充空余位置
    //FillEmptyCuckooHashSlots(KEY_LEN, encrypted_data);

    int label_size = KEY_LEN;

    // VF空间计算 (bits -> bytes -> MB)
    double bits_per_fp = FP_LENGTH;
    double total_bits = MAX_BINS_SIZE * bits_per_fp;
    double vacuum_size_in_mb = total_bits / (8.0 * 1024.0 * 1024.0);
    
    // 标签空间计算 (bytes -> MB)
    double bytes_per_label = label_size;
    double total_label_bytes = bytes_per_label * FILE_NUM * MAX_BINS_SIZE;
    double label_size_in_mb = total_label_bytes / (1024.0 * 1024.0);
    
    double total_size_in_mb = vacuum_size_in_mb + label_size_in_mb;
    cout<<"文件数目"<<FILE_NUM<<endl;
    cout << "布谷鸟哈希桶大小：" << MAX_BINS_SIZE << endl;
    cout << "VF指纹长度: " << FP_LENGTH << " bits" << endl;
    cout << "VF部分大小：" << fixed << setprecision(2) << vacuum_size_in_mb << " MB" << endl;
    cout << "标签部分大小：" << fixed << setprecision(2) << label_size_in_mb << " MB" << endl;
    cout << "密文集合总大小：" << fixed << setprecision(2) << total_size_in_mb << " MB" << endl;

    // 调用测试 VacuumFilter 的函数
    TestVacuumFilter();

    return 0;
}