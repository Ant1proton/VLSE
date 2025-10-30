#include "util.h"
#include "Pub_para.h"
#include "database.h"
#include <sys/stat.h> // 添加头文件
#include <chrono> // 添加头文件
#include <vector>
#include <string>
#include <random>
#include <chrono>
#include <fstream>
#include <sstream>
#include <map>
#include <NTL/ZZ.h>
#include <cryptlib.h>
#include <osrng.h> // 包含 AutoSeededRandomPool 的头文件
#include <sha.h> // Crypto++ 的 SHA-256 头文件
#include <filters.h> // Crypto++ filters.h
#include <secblock.h>
// 移除旧的 VacuumFilter 头文件
// #include "Vacuum-Filter/ModifiedCuckooFilter/src/vacuumfilter3072_64.h"
#include <random>
#include <iostream> // Added for cout, cin, cerr
#include <ratio>    // Added for chrono duration casting
#include <stdint.h> // Added for uint64_t and __uint128_t

// 引入 VacuumFilter 的头文件
#include "Vacuum-Filter/vacuum.h" // 确保这里引入的是修改后的 vacuum.h
#include "Vacuum-Filter/hashutil.h" // 确保这里引入的是正确的 hashutil.h

using namespace std;
using namespace NTL;
using namespace CryptoPP;

// 宏定义可调指纹长度，与 DoubleVacuumFilter 匹配
#define FP_LEN_HI 11
#define FP_LEN_LO 11

// 请修改此路径到您实际的数据文件位置
 const static string DATASET_PATH = "/Users/chenyuwei/Desktop/one-to-one--sse-experiment-Ruofan_Li/rf_SELPSI/data/word_id_pair_inverted_index10";
const static int SEARCH_KEYWORDS_NUM = 1;
// 移除旧的 FP_LENGTH 定义，指纹长度由 DoubleVacuumFilter 的 FP_LEN_HI + FP_LEN_LO 决定
// const static int FP_LENGTH = 26;
const static int MAX_LABEL_NUM = 20; // 数据集中每个ID最多可能有的标签数量
const static int KEY_LEN = 16;
// 移除旧的 MAX_BINS_SIZE 定义，过滤器尺寸由 DoubleVacuumFilter 内部计算
// const static int MAX_BINS_SIZE = 81920;
const static int MAX_RELOCATIONS = 50000; // Increased relocation for DoubleVacuumFilter
// 移除旧的 vis 数组
// bool vis[MAX_BINS_SIZE]; //判定哈希桶当中是否有元素
// 移除旧的 VacuumFilter 声明
// VacuumFilter3072<FP_LENGTH> vf(MAX_BINS_SIZE);

Pub_para PUB_PARA;
// 添加全局的输出运算符重载，确保放在namespace声明之后
std::ostream& operator<<(std::ostream& os, const __uint128_t& value) {
    if (value == 0) {
        return os << "0";
    }
    
    std::string result;
    __uint128_t temp = value;
    
    while (temp > 0) {
        result = char('0' + temp % 10) + result;
        temp /= 10;
    }
    
    return os << result;
}
// Helper function to convert ZZ to __uint128_t
__uint128_t ZZ_to_uint128(const ZZ& z) {
    // 如果ZZ为0，直接返回0
    if (z == 0) return 0;
    
    // 获取字节数，限制最大为16字节（128位）
    size_t bytes_needed = NumBytes(z);
    
    if (bytes_needed > 16) {
        cerr << "警告: ZZ值超过128位 (" << bytes_needed << " 字节), 截断到最低128位." << endl;
        bytes_needed = 16;
    }
    
    // 创建临时缓冲区并初始化为0
    unsigned char buffer[16] = {0};
    
    // 从ZZ获取字节（NTL按小端格式存储）
    BytesFromZZ(buffer, z, bytes_needed);
    
    // 按小端序构建__uint128_t
    __uint128_t res = 0;
    for (size_t i = 0; i < bytes_needed; i++) {
        res |= ((__uint128_t)buffer[i]) << (i * 8);
    }
    
    return res;
}

// 拆分128位token为两个64位
inline void split_token(__uint128_t token, uint64_t &hi, uint64_t &lo) {
    hi = static_cast<uint64_t>(token >> 64);
    lo = static_cast<uint64_t>(token & 0xFFFFFFFFFFFFFFFFULL);
}

// Helper function to convert string to __uint128_t (Not used in this integration, but kept for completeness if needed later)
/*
__uint128_t string_to_uint128(const string& s) {
    __uint128_t res = 0;
    for (char c : s) {
        res = res * 10 + (c - '0');
    }
    return res;
}
*/

// DoubleVacuumFilter 类的定义，使用 VacuumFilterNS::VacuumFilter
template <size_t FP_HI, size_t FP_LO>
class DoubleVacuumFilter {
public:
    VacuumFilterNS::VacuumFilter<uint64_t, FP_HI> vf_hi; // 使用命名空间
    VacuumFilterNS::VacuumFilter<uint64_t, FP_LO> vf_lo; // 使用命名空间

    DoubleVacuumFilter(size_t max_keys) {
        // Initialize the VacuumFilter instances using their init method
        // Assuming 4 slots per bucket and MAX_RELOCATIONS max kick steps
        vf_hi.init(max_keys, 4, MAX_RELOCATIONS);
        vf_lo.init(max_keys, 4, MAX_RELOCATIONS);
    }

    bool Add(const __uint128_t &token) {
        uint64_t hi, lo;
        split_token(token, hi, lo);
        // Insertion requires successful insertion into *both* filters
        return vf_hi.insert(hi) && vf_lo.insert(lo);
    }

    bool Contain(const __uint128_t &token) const {
        uint64_t hi, lo;
        split_token(token, hi, lo);
        // Containment requires presence in *both* filters
        return vf_hi.lookup(hi) && vf_lo.lookup(lo);
    }

    bool Delete(const __uint128_t &token) {
        uint64_t hi, lo;
        split_token(token, hi, lo);
        // Deletion requires successful deletion from *both* filters
        return vf_hi.del(hi) && vf_lo.del(lo);
    }
};


ZZ HexStringToZZ(const string &hex_str) {
    ZZ result(0);
    for (char c : hex_str) {
        result *= 16;
        if (c >= '0' && c <= '9') result += c - '0';
        else if (c >= 'a' && c <= 'f') result += c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') result += c - 'A' + 10;
        else throw runtime_error("Invalid hex character in: " + string(1, c));
    }
    return result;
}


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

ZZ GetHashedZZFromString(string search_word) {
    SHA256 hash;
    SecByteBlock digest(SHA256::DIGESTSIZE);
    hash.Update((byte*)search_word.data(), search_word.size());
    hash.Final(digest);

    return ZZFromBytes(digest, digest.size()) % PUB_PARA.N;
}

ZZ Get_search_token_from_string2(string search_word, ZZ alpha) {
    ZZ hashed_ZZ = GetHashedZZFromString(search_word);  // 用 SHA256 代替 SipHash
    ZZ search_token = PowerMod(hashed_ZZ, alpha, PUB_PARA.N);
    return search_token;
}

ZZ Get_search_token_from_string1(ZZ search_word_ZZ, ZZ alpha)
{
   // 关键字哈希值的 alpha 次幂
   ZZ search_token=(PowerMod(search_word_ZZ, alpha, PUB_PARA.N));
   return search_token;
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

// 检测token碰撞率的函数
void DetectTokenCollisions(const string& filepath) {
    cout << "\n===== Token碰撞率分析 =====" << endl;

    // 读取加密数据库
    ifstream infile(filepath);
    if (!infile.is_open()) {
        cerr << "无法打开文件: " << filepath << endl;
        return;
    }

    // 存储所有token
    vector<ZZ> all_tokens;
    map<ZZ, int> token_counts; // 记录每个token出现次数
    map<ZZ, vector<string>> colliding_keywords; // 记录发生碰撞的token对应的原始关键词

    string line;
    while (getline(infile, line)) {
        // 每行的第一项是token
        size_t tab_pos = line.find('\t');
        if (tab_pos != string::npos) {
            string token_str = line.substr(0, tab_pos);
            ZZ token;
            conv(token, token_str.c_str());

            all_tokens.push_back(token);
            token_counts[token]++;
        }
    }

    infile.close();

    // 计算碰撞统计
    int total_tokens = all_tokens.size();
    int unique_token_count = token_counts.size();
    int collision_count = total_tokens - unique_token_count;
    double collision_rate = (total_tokens > 0) ? (double)collision_count / total_tokens * 100.0 : 0.0;

    cout << "总token数量: " << total_tokens << endl;
    cout << "唯一token数量: " << unique_token_count << endl;
    cout << "发生碰撞的token数量: " << collision_count << endl;
    cout << "碰撞率: " << fixed << setprecision(6) << collision_rate << "%" << endl;

    // 统计碰撞分布
    map<int, int> collision_distribution; // <出现次数, 有多少个token出现这么多次>
    for (const auto& pair : token_counts) {
        collision_distribution[pair.second]++;
    }

    cout << "\n碰撞分布统计:" << endl;
    for (const auto& pair : collision_distribution) {
        if (pair.first > 1) {
            cout << "出现 " << pair.first << " 次的token数量: " << pair.second << endl;
        }
    }

    // 如果有碰撞，展示一些碰撞的例子
    if (collision_count > 0) {
        cout << "\n碰撞token示例:" << endl;
        int examples_shown = 0;
        for (const auto& pair : token_counts) {
            if (pair.second > 1) {
                cout << "Token " << pair.first << " 出现了 " << pair.second << " 次" << endl;
                examples_shown++;

                // Mostra no máximo 5 exemplos
                if (examples_shown >= 5) break;
            }
        }
    }

    cout << "===== 碰撞分析结束 =====" << endl;
}

// 限制每个ID的标签数量
map<string, vector<string>> LimitLabelsPerKeyword(const map<string, vector<string>>& original_db, int max_labels) {
    map<string, vector<string>> limited_db;

    for (const auto& entry : original_db) {
        vector<string> limited_labels;
        // 只保留指定数量的标签
        for (int i = 0; i < min(max_labels, (int)entry.second.size()); i++) {
            limited_labels.push_back(entry.second[i]);
        }
        limited_db[entry.first] = limited_labels;
    }

    return limited_db;
}

void Gene_encrypted_data(string file_path, int labels_per_id)
{
    cout << endl;
    cout << "------------------加密数据开始----------------" << endl;
    cout << "读取文件：" << file_path << endl;
    cout << "每个ID的标签数量限制：" << labels_per_id << endl;

    // 先读取完整数据库
    map<string, vector<string>> full_inverted_DB = DB_build_by_inverted(file_path);

    // 限制每个ID的标签数量
    map<string, vector<string>> inverted_DB = LimitLabelsPerKeyword(full_inverted_DB, labels_per_id);

    ofstream outfile("../data/encrypted_data.txt");
    if (!outfile.is_open())
    {
        cout << "error" << endl;
        return;
    }
    cout << "文件读取完成，生成加密数据库当中..." << endl;

    int DB_size = inverted_DB.size();
    int cur = 0;
    //cout<<"程序开始前的beta；"<<PUB_PARA.beta<<endl;

    for (auto each : inverted_DB)
    {
        // 调用函数时传递 PUB_PARA.alpha 和 PUB_PARA.beta
        ZZ temp = Get_search_token_from_string2(each.first, PUB_PARA.beta);
        cout<<"数据库元素："<<each.first<<"的"<<"temp:"<<temp<<endl;
        ZZ token= HashFunction1(temp);
        ZZ sym_key = HashFunction2(temp);
        outfile << token;
       cout<<"数据库元素："<<each.first<<"的"<<"token:"<<token<<endl;

        // Use the beta power of the keyword hash to generate the aes encryption/decryption key
        SecByteBlock aesKey(KEY_LEN);
        BytesFromZZ(aesKey, sym_key, KEY_LEN);
        cout<<"encrypting label..."<<endl;
        for (auto label_str : each.second)
        {
            // encrypt each keyword's corresponding label
            trim(label_str);
            erasePending(label_str);
            SecByteBlock label((byte *)label_str.c_str(), label_str.size());
            SecByteBlock label_enc = PUB_PARA.aes_Enc(aesKey, label);


            outfile << "\t";
            // Note: SecByteBlock must be converted to ZZ before storing
            ZZ label_enc_ZZ = ZZFromBytes(label_enc, label_enc.size());
           // cout << "label size: " << GetZZSize(label_enc_ZZ) << endl;
            outfile << label_enc_ZZ;
            //cout<<"ഡാറ്റ"<<each.first<<":"<<"യുടെ ലേബൽ_enc_ZZ"<<label_enc_ZZ<<endl;
        }
        outfile << "\n";
        printf("\033[32m%.2lf%%\r\033[0m", (++cur) * 100.0 / DB_size);
    }
    cout << endl;
    outfile.close();
    cout << "Encrypted database generated, file saved to \"../data/encrypted_data.txt\"" << endl;
}




SecByteBlock GenerateRandomBlock(size_t size) {
    SecByteBlock block(size);
    AutoSeededRandomPool rng; // Use Crypto++ random number generator
    rng.GenerateBlock(block, size);
    return block;
}


map<ZZ, Vec<ZZ>> Read_EDB_file(string file_path)
{
   cout << endl;
   cout << "------------Reading Encrypted Database-------------" << endl;
   ifstream infile(file_path);
   cout << "Reading file：" << file_path << endl;
   map<ZZ, Vec<ZZ>> encrypted_data;
   if (!infile.is_open())
   {
      cout << "Failed to open file\"" << file_path << "\"" << endl;
      return encrypted_data;
   }
   cout << "Building mapping table..." << endl;
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
   cout << "File read complete, mapping table built" << endl;
   cout << "-----------------------------------" << endl;
   cout << endl;
   return encrypted_data;
}

vector<string> GetRandomKeywords(const string& file_path, int num_keywords) {
    map<string, vector<string>> inverted_DB = DB_build_by_inverted(file_path);
    vector<string> all_keywords;

    // Collect all keywords
    for (const auto& pair : inverted_DB) {
        all_keywords.push_back(pair.first);
    }

    // Randomly shuffle keywords
    random_device rd;
    mt19937 gen(rd());
    shuffle(all_keywords.begin(), all_keywords.end(), gen);

    // Select the specified number of keywords
    vector<string> selected_keywords;
    for (int i = 0; i < min(num_keywords, (int)all_keywords.size()); i++) {
        selected_keywords.push_back(all_keywords[i]);
    }
    return selected_keywords;
}


// Run a single test
void RunTest(int labels_per_id) {
    cout << "\n\n====================================================" << endl;
    cout << "Starting test with " << labels_per_id << " labels per ID" << endl;
    cout << "====================================================" << endl;

    // Start timing
    auto start_time1 = chrono::high_resolution_clock::now();
    Gene_encrypted_data(DATASET_PATH, labels_per_id);
    auto end_time1 = chrono::high_resolution_clock::now();

    // Output ciphertext collection generation time
    double elapsed_time1 = chrono::duration_cast<chrono::microseconds>(end_time1 - start_time1).count() / 1000.0;
    cout << "Ciphertext collection generation time：" << fixed << setprecision(3) << elapsed_time1 << " ms" << endl;

    // Read encrypted database
    map<ZZ, Vec<ZZ>> encrypted_data = Read_EDB_file("../data/encrypted_data.txt");

    // Convert ZZ tokens to __uint128_t and store
    vector<__uint128_t> tokens_to_insert;
    for(const auto& pair : encrypted_data) {
        // Assume ZZ can be safely converted to __uint128_t. Handle if ZZ exceeds 128 bits.
         if (NumBits(pair.first) > 128) {
             cerr << "Warning: Token exceeds 128 bits and cannot be stored in __uint128_t." << endl;
             continue;
         }
        tokens_to_insert.push_back(ZZ_to_uint128(pair.first));
    }

    int n = tokens_to_insert.size();

    // Declare and initialize DoubleVacuumFilter
    DoubleVacuumFilter<FP_LEN_HI, FP_LEN_LO> dvf(n);

    // Insert tokens into DoubleVacuumFilter
    int insert_fail = 0;
    auto insert_start = chrono::high_resolution_clock::now();

    for (const auto& token : tokens_to_insert) {
        cout<<"插入成功的token："<<token<<endl;
        if (!dvf.Add(token)) {
            cout<<"插入失败的token："<<token<<endl; // 调试信息，插入成功后可以注释掉
            insert_fail++;
        }
    }

    auto insert_end = chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed_insert = insert_end - insert_start;

    cout << "Insertion statistics:" << endl;
    cout << "Total tokens: " << tokens_to_insert.size() << endl;
    cout << "Insertion failed: " << insert_fail << endl;
    cout << "Insertion success rate: " << fixed << setprecision(2)
         << ((tokens_to_insert.size() - insert_fail) * 100.0 / tokens_to_insert.size()) << "%" << endl;
    cout << "Total insertion time: " << fixed << setprecision(3) << elapsed_insert.count() * 1000.0 << " ms" << endl; // Convert to ms
    if (tokens_to_insert.size() > 0) {
        cout << "Average insertion time per token: " << fixed << setprecision(6)
             << (elapsed_insert.count() * 1000.0 / tokens_to_insert.size()) << " ms" << endl; // Convert to ms
    }


    // Get random keywords
    vector<string> search_keywords = GetRandomKeywords(DATASET_PATH, SEARCH_KEYWORDS_NUM);
    cout << "\nStarting query for " << SEARCH_KEYWORDS_NUM << " random keywords...\n" << endl;

    // Query operation
    double total_search_time = 0.0;
    int found_count = 0;
    vector<double> checkpoint_times = {0, 0, 0, 0, 0}; // Store total time for 1, 10, 20, 30, 40 keywords

    for (int i = 0; i < search_keywords.size(); i++) {
        auto start_time = chrono::high_resolution_clock::now();

        // Generate query token and symmetric key
        ZZ search_temp = Get_search_token_from_string2(search_keywords[i], PUB_PARA.alpha);
        search_temp = Get_search_token_from_string1(search_temp, PUB_PARA.beta);
        search_temp = Get_search_token_from_string1(search_temp, PUB_PARA.alpha_inv);
        ZZ search_token_zz = HashFunction1(search_temp);
        ZZ sym_key = HashFunction2(search_temp);
         cout<<"查询时元素"<<search_keywords[i] << "的search_temp: " << search_temp << endl; // 调试信息，可以注释掉
          cout<<"查询时元素"<<search_keywords[i] << "的search_token_zz: " << search_token_zz << endl; // 调试信息，可以注释掉
        // Convert ZZ token to __uint128_t for DoubleVacuumFilter lookup
        __uint128_t search_token_u128 = ZZ_to_uint128(search_token_zz);
        cout<<"转换成128查询元素："<<search_keywords[i]<<"!!!!的token是："<<search_token_u128<<endl;
        vector<SecByteBlock> labels;
        bool found = dvf.Contain(search_token_u128);
        // cout<<"found:"<<found<<endl; // 调试信息，可以注释掉
        if (found) {
            found_count++;
            // Retrieve and decrypt labels only if the token is found in the filter
            auto it = encrypted_data.find(search_token_zz);
            if (it != encrypted_data.end()) {
                 Vec<ZZ> encrypted_labels = it->second;
                 for (ZZ each : encrypted_labels) {
                     SecByteBlock temp(KEY_LEN);
                     BytesFromZZ(temp, each, temp.size());

                     SecByteBlock sym_key_byte(KEY_LEN);
                     BytesFromZZ(sym_key_byte, sym_key, sym_key_byte.size());
                     temp = PUB_PARA.aes_Dec(sym_key_byte, temp);
                     labels.push_back(temp);
                 }
            } else {
                 // This case should ideally not happen if insertion was successful,
                 // but it's good practice to handle missing keys in the map.
                 cerr << "Error: Token found in filter but not in encrypted_data map." << endl;
            }
        }

        auto end_time = chrono::high_resolution_clock::now();
        double elapsed_time = chrono::duration_cast<chrono::microseconds>(end_time - start_time).count() / 1000.0;
        total_search_time += elapsed_time;

        if (found) {
            cout << "Query successful, found " << labels.size() << " 个元素。" << endl;
        } else {
            cout << "No labels found for the keyword." << endl;
        }

        // Record query time at specific keyword counts
        if (i == 0) checkpoint_times[0] = total_search_time;  // 1 keyword
        if (i == 9) checkpoint_times[1] = total_search_time;  // 10 keywords
        if (i == 19) checkpoint_times[2] = total_search_time; // 20 keywords
        // Adjust indices if SEARCH_KEYWORDS_NUM is less than 40
        if (SEARCH_KEYWORDS_NUM > 20) checkpoint_times[3] = total_search_time; // 30 keywords
        if (SEARCH_KEYWORDS_NUM > 30) checkpoint_times[4] = total_search_time; // 40 keywords
    }

    // Output total query time for specific keyword counts
    cout << "\nTotal query time for different keyword counts:" << endl;
    cout << "1 keyword: " << fixed << setprecision(3) << checkpoint_times[0] << " ms" << endl;
    cout << "10 keywords: " << fixed << setprecision(3) << checkpoint_times[1] << " ms" << endl;
    cout << "20 keywords: " << fixed << setprecision(3) << checkpoint_times[2] << " ms" << endl;
    // Adjust indices if SEARCH_KEYWORDS_NUM is less than 40
    if (SEARCH_KEYWORDS_NUM > 20) cout << "30 keywords: " << fixed << setprecision(3) << checkpoint_times[3] << " ms" << endl;
    if (SEARCH_KEYWORDS_NUM > 30) cout << "40 keywords: " << fixed << setprecision(3) << checkpoint_times[4] << " ms" << endl;


    // Calculate ciphertext size
    double vf_hi_size_in_mb = (double)dvf.vf_hi.memory_consumption / (1024.0 * 1024.0);
    double vf_lo_size_in_mb = (double)dvf.vf_lo.memory_consumption / (1024.0 * 1024.0);

    // Estimate label data size based on the actual number of tokens and average labels per ID
    // This is an estimation. A more accurate calculation would sum the actual byte size of each Vec<ZZ>
    double estimated_label_size_in_mb = (double)encrypted_data.size() * labels_per_id * KEY_LEN / (1024.0 * 1024.0);


    double total_size_in_mb = vf_hi_size_in_mb + vf_lo_size_in_mb + estimated_label_size_in_mb;


    cout << "\nCiphertext collection size statistics:" << endl;
    cout << "Labels per ID: " << labels_per_id << endl;
    cout << "VF HI size: " << fixed << setprecision(2) << vf_hi_size_in_mb << " MB" << endl;
    cout << "VF LO size: " << fixed << setprecision(2) << vf_lo_size_in_mb << " MB" << endl;
    cout << "Estimated label data size: " << fixed << setprecision(2) << estimated_label_size_in_mb << " MB" << endl;
    cout << "Total ciphertext collection size (estimated): " << fixed << setprecision(2) << total_size_in_mb << " MB" << endl;


    // Output statistics
    cout << "\nQuery statistics:" << endl;
    cout << "Total query time: " << fixed << setprecision(3) << total_search_time << " ms" << endl;
    cout << "Average query time: " << fixed << setprecision(3) << total_search_time / SEARCH_KEYWORDS_NUM << " ms" << endl;
    cout << "Query success rate: " << fixed << setprecision(2) << (found_count * 100.0 / SEARCH_KEYWORDS_NUM) << "%" << endl;
    cout << "DoubleVacuumFilter fingerprint length: FP_HI=" << FP_LEN_HI << " bits, FP_LO=" << FP_LEN_LO << " bits (Total " << FP_LEN_HI + FP_LEN_LO << " bits)" << endl;
}

int main() {
    PUB_PARA.beta = conv<ZZ>("47676318137538369727214414118984042636057735934898873328264027803085274899392");
    PUB_PARA.beta1 = conv<ZZ>("20984771316314472289297972305987079205225297921858495109350827762359756644626");
    PUB_PARA.alpha1 = conv<ZZ>("89937141617663735915351339569653166415837297575408018408051320513022216101007");
    PUB_PARA.alpha_inv1 = conv<ZZ>("2663012280045998906000749410424301594809233938858588550332869340082756287006866475251380684642023807568253026783973621913560108807413193673328824310421020432316535350291422330005944459366059771402739858699138105448843213408431934768883955585033227681328567017629268134475144828436062106837095794691892006449645164145244841591539943919722960303328334775873927934259824161503769685911574463637879444801025830073960113675372102237399827153191607913650080935749590900110104162919121708798644807375081624566713038046968218887414954876974537616188884273281322171256130377435809250593004343701611249860934986236335825017139725656659629120511651595891869264769867403673036406206109301609209743031336408322253023228788949327372282382041890298951180857166664048700540240649894261086482949548234207496172577756742003729482831245357203260831467179197836230252890146198289394038172621120465137046493665790287133094771415689973061474709879");
    PUB_PARA.alpha = conv<ZZ>("56899084826686085705689450652576527896920957644206970942974318929903760835733");
    PUB_PARA.alpha_inv = conv<ZZ>("1980442776286556236868470568034035227390070169148065051468423986682902927732307225013380072587769611290541886840925494109500589317435480314150259945975049322198379252091570033040628396962294234744262068873992785787920890396938063122075326264923741605460665154898220886087747691680843643023543265741179215649325076824207742431207524163408417716978332938904224428554169748192186870633656097681735905162898430766138755710693760984144253001850347210813650751351849424070674904473129363413782507823006445997846946028113154785182559871195705063748689782995072573873124715636602275856507399677009302339409380736311535985059132464359676035416386682357119915766734267591949337060493008276592734564807444334437925203718558149459510581596969498003090206306743082745038861884986370719825192946088178472427239908908649837631810308786380252337980820009747711501665282352445068043294314860890017215335688213927510811370572018531697860581549");
    PUB_PARA.N = conv<ZZ>("4294583258558056192923703766393959116688381789171653365953160993564471860979820850238493242175677808382399806630093888465939485882664537648621736064645259930756623911730863386933107195488830006538624232730782748458029309749374825553737211455997084185753848758816963331338844629629248219697315241640404373168471968456184728902336482116647651129409335745145337167109401240130153808406744468167592320112109395492847321216653366179244117543266780884400550644321334482636804271333331035019915613952605420878706747165084475456389940555001692984535228337794856717018136573792036252672265775180225934685847881326988749037286611427141641025206878963987999654442968352964593869784352330104497594353434138689574727623224199005565895856552579945338751230570853251552237712548584028290825892265479837724351707251592932053811329283984624939044934280643377406250785790984182091428701411147442624917636568645208390917798558884307099500857911");

    //cout << "请输入最大标签数量: ";
    int max_labels;
    //cin >> max_labels;
    //max_labels = min(max_labels, MAX_LABEL_NUM); // Ensure not to exceed max value
     max_labels = MAX_LABEL_NUM;
    // Test with different numbers of labels
    //vector<int> label_counts = {1, 5, 10, 15, 20};
    vector<int> label_counts = {1};
    for (int labels : label_counts) {
        // Only test up to the specified max number of labels
        if (labels <= max_labels) {
            RunTest(labels);
        }
    }
    // DetectTokenCollisions("../data/encrypted_data.txt"); // This function uses ZZ tokens, might need adaptation for __uint128_t
    cout << "\nAll tests finished!" << endl;
    return 0;
}