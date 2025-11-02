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
#include <unordered_set> // 添加头文件
#include <functional> // 添加头文件

// 引入 VacuumFilter 的头文件
#include "Vacuum-Filter/vacuum.h" // 确保这里引入的是修改后的 vacuum.h
#include "Vacuum-Filter/hashutil.h" // 确保这里引入的是正确的 hashutil.h

using namespace std;
using namespace NTL;
using namespace CryptoPP;

// 宏定义可调指纹长度，用于三重VacuumFilter实现43位指纹
#define FP_LEN_1 15  // 第一个VF：15位指纹
#define FP_LEN_2 15  // 第二个VF：15位指纹  
#define FP_LEN_3 13  // 第三个VF：13位指纹

// 请修改此路径到您实际的数据文件位置
 const static string DATASET_PATH = "data/data14_20";
const static int SEARCH_KEYWORDS_NUM = 50;

const static int MAX_LABEL_NUM = 20; // 数据集中每个ID最多可能有的标签数量
const static int KEY_LEN = 16;

const static int MAX_RELOCATIONS = 50000; // Increased relocation for DoubleVacuumFilter

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

// 将128位token分解为3个64位，用于3个独立的VF
inline void split_token_triple(const __uint128_t &token, uint64_t &part1, uint64_t &part2, uint64_t &part3) {
    // 方法：直接分割高64位和低64位，然后通过变换生成第三个
    uint64_t hi = static_cast<uint64_t>(token >> 64);
    uint64_t lo = static_cast<uint64_t>(token & 0xFFFFFFFFFFFFFFFFULL);
    
    part1 = hi;                                    // 原始高64位
    part2 = lo;                                    // 原始低64位  
    part3 = hi ^ lo;                               // 高低异或作为第三个独立值
}



// 三重VacuumFilter类 - 43位指纹（15+15+13）
template <size_t FP1, size_t FP2, size_t FP3>
class TripleVacuumFilter {
public:
    VacuumFilterNS::VacuumFilter<uint64_t, FP1> vf1;
    VacuumFilterNS::VacuumFilter<uint64_t, FP2> vf2;
    VacuumFilterNS::VacuumFilter<uint64_t, FP3> vf3;
    
    // 添加缓冲区以处理插入失败的情况
    std::unordered_set<__uint128_t> buffer;
    size_t buffer_capacity;
    size_t max_keys;

    TripleVacuumFilter(size_t max_keys) : max_keys(max_keys) {
        // 初始化三个VF实例
        vf1.init(max_keys, 4, MAX_RELOCATIONS);
        vf2.init(max_keys, 4, MAX_RELOCATIONS);
        vf3.init(max_keys, 4, MAX_RELOCATIONS);
        
        // 设置缓冲区容量为过滤器大小的1%
        buffer_capacity = std::max(static_cast<size_t>(1), max_keys / 100);
    }

    bool Add(const __uint128_t &token) {
        uint64_t part1, part2, part3;
        split_token_triple(token, part1, part2, part3);
        
        // 必须所有三个VF都插入成功
        if (vf1.insert(part1) && vf2.insert(part2) && vf3.insert(part3)) {
            return true;
        }
        
        // 如果主过滤器插入失败，尝试缓冲区
        if (buffer.size() < buffer_capacity) {
            buffer.insert(token);
            return true;
        }
        
        return false;
    }

    bool Contain(const __uint128_t &token) const {
        // 首先检查主过滤器
        uint64_t part1, part2, part3;
        split_token_triple(token, part1, part2, part3);
        
        // 必须所有三个VF都查询到
        if (vf1.lookup(part1) && vf2.lookup(part2) && vf3.lookup(part3)) {
            return true;
        }
        
        // 如果不在主过滤器中，检查缓冲区
        return buffer.find(token) != buffer.end();
    }

    bool Delete(const __uint128_t &token) {
        // 先检查缓冲区
        auto it = buffer.find(token);
        if (it != buffer.end()) {
            buffer.erase(it);
            return true;
        }
        
        // 如果不在缓冲区中，尝试从主过滤器中删除
        uint64_t part1, part2, part3;
        split_token_triple(token, part1, part2, part3);
        return vf1.del(part1) && vf2.del(part2) && vf3.del(part3);
    }
    
    // 获取内存使用情况
    size_t GetTotalMemoryConsumption() const {
        return vf1.memory_consumption + vf2.memory_consumption + vf3.memory_consumption + 
               buffer.size() * sizeof(__uint128_t);
    }
    
    // 获取缓冲区状态
    size_t GetBufferSize() const {
        return buffer.size();
    }
    
    size_t GetBufferCapacity() const {
        return buffer_capacity;
    }
};





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

    ofstream outfile("data/encrypted_data.txt");
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
        //cout<<"数据库元素："<<each.first<<"的"<<"temp:"<<temp<<endl;
        ZZ token= HashFunction1(temp);
        ZZ sym_key = HashFunction2(temp);
        outfile << token;
       //cout<<"数据库元素："<<each.first<<"的"<<"token:"<<token<<endl;

        // Use the beta power of the keyword hash to generate the aes encryption/decryption key
        SecByteBlock aesKey(KEY_LEN);
        BytesFromZZ(aesKey, sym_key, KEY_LEN);
        //cout<<"encrypting label..."<<endl;
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
            outfile << label_enc_ZZ;
            //cout<<"ഡാറ്റ"<<each.first<<":"<<"യുടെ ലേബൽ_enc_ZZ"<<label_enc_ZZ<<endl;
        }
        outfile << "\n";
        printf("\033[32m%.2lf%%\r\033[0m", (++cur) * 100.0 / DB_size);
    }
    cout << endl;
    outfile.close();
    cout << "Encrypted database generated, file saved to \"data/encrypted_data.txt\"" << endl;
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
    map<ZZ, Vec<ZZ>> encrypted_data = Read_EDB_file("data/encrypted_data.txt");

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

    // Declare and initialize TripleVacuumFilter
    TripleVacuumFilter<FP_LEN_1, FP_LEN_2, FP_LEN_3> tvf(n);

    // Insert tokens into TripleVacuumFilter
    int insert_fail = 0;
    auto insert_start = chrono::high_resolution_clock::now();

    for (const auto& token : tokens_to_insert) {
        //cout<<"插入成功的token："<<token<<endl;
        if (!tvf.Add(token)) {
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
    double total_token_gen_time = 0.0;      // Token生成时间
    double total_vf_search_time = 0.0;      // VacuumFilter查找时间
    double total_decrypt_time = 0.0;        // 解密时间
    int found_count = 0;
    vector<double> checkpoint_times = {0, 0, 0, 0, 0}; // Store total time for 1, 10, 20, 30, 40 keywords

    for (int i = 0; i < search_keywords.size(); i++) {
        auto query_start = chrono::high_resolution_clock::now();

        // ============ 1. Token生成阶段 ============
        auto token_gen_start = chrono::high_resolution_clock::now();
        
        // Generate query token and symmetric key
        ZZ search_temp = Get_search_token_from_string2(search_keywords[i], PUB_PARA.alpha);
        search_temp = Get_search_token_from_string1(search_temp, PUB_PARA.beta);
        search_temp = Get_search_token_from_string1(search_temp, PUB_PARA.alpha_inv);
        ZZ search_token_zz = HashFunction1(search_temp);
        ZZ sym_key = HashFunction2(search_temp);
        // cout<<"查询时元素"<<search_keywords[i] << "的search_temp: " << search_temp << endl; // 调试信息，可以注释掉
        //  cout<<"查询时元素"<<search_keywords[i] << "的search_token_zz: " << search_token_zz << endl; // 调试信息，可以注释掉
        // Convert ZZ token to __uint128_t for TripleVacuumFilter lookup
        __uint128_t search_token_u128 = ZZ_to_uint128(search_token_zz);
        //cout<<"转换成128查询元素："<<search_keywords[i]<<"!!!!的token是："<<search_token_u128<<endl;
        
        auto token_gen_end = chrono::high_resolution_clock::now();
        double token_gen_time = chrono::duration_cast<chrono::microseconds>(token_gen_end - token_gen_start).count() / 1000.0;
        total_token_gen_time += token_gen_time;

        // ============ 2. VacuumFilter查找阶段 ============
        auto vf_search_start = chrono::high_resolution_clock::now();
        
        vector<SecByteBlock> labels;
        bool found = tvf.Contain(search_token_u128);
        
        auto vf_search_end = chrono::high_resolution_clock::now();
        double vf_search_time = chrono::duration_cast<chrono::microseconds>(vf_search_end - vf_search_start).count() / 1000.0;
        total_vf_search_time += vf_search_time;

        // ============ 3. 解密阶段 ============
        auto decrypt_start = chrono::high_resolution_clock::now();
        
        // cout<<"found:"<<found<<endl; 
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
        
        auto decrypt_end = chrono::high_resolution_clock::now();
        double decrypt_time = chrono::duration_cast<chrono::microseconds>(decrypt_end - decrypt_start).count() / 1000.0;
        total_decrypt_time += decrypt_time;

        auto query_end = chrono::high_resolution_clock::now();
        double elapsed_time = chrono::duration_cast<chrono::microseconds>(query_end - query_start).count() / 1000.0;
        total_search_time += elapsed_time;
        /*
        if (found) {
            cout << "Query successful, found " << labels.size() << " 个元素。" << endl;
        } else {
            cout << "No labels found for the keyword." << endl;
        }
*/
        // Record query time at specific keyword counts
        if (i == 9) checkpoint_times[0] = total_search_time;  
        if (i == 19) checkpoint_times[1] = total_search_time;  
        if (i == 29) checkpoint_times[2] = total_search_time; 
        if (i == 39) checkpoint_times[3] = total_search_time; 
        if (i == 49) checkpoint_times[4] = total_search_time; 
    }

    // Output total query time for specific keyword counts
    cout << "\nTotal query time for different keyword counts:" << endl;
    cout << "10 keyword: " << fixed << setprecision(3) << checkpoint_times[0] << " ms" << endl;
    cout << "20 keywords: " << fixed << setprecision(3) << checkpoint_times[1] << " ms" << endl;
    cout << "30 keywords: " << fixed << setprecision(3) << checkpoint_times[2] << " ms" << endl;
    cout << "40 keywords: " << fixed << setprecision(3) << checkpoint_times[3] << " ms" << endl;
    cout << "50 keywords: " << fixed << setprecision(3) << checkpoint_times[4] << " ms" << endl;


    // Calculate ciphertext size
    //double vf_hi_size_in_mb = (double)dvf.vf_hi.memory_consumption / (1024.0 * 1024.0)+(double)(dvf.GetBufferCapacity() * sizeof(__uint128_t)) / (1024*1024);
    //double vf_lo_size_in_mb = (double)dvf.vf_lo.memory_consumption / (1024.0 * 1024.0)+(double)(dvf.GetBufferCapacity() * sizeof(__uint128_t)) / (1024*1024);

    // Estimate label data size based on the actual number of tokens and average labels per ID
    // This is an estimation. A more accurate calculation would sum the actual byte size of each Vec<ZZ>
    double estimated_label_size_in_mb = (double)encrypted_data.size() * labels_per_id * KEY_LEN / (1024.0 * 1024.0);

    double total_size_in_mb = (double)tvf.GetTotalMemoryConsumption() / (1024.0 * 1024.0) + estimated_label_size_in_mb;


    cout << "\nCiphertext collection size statistics:" << endl;
    cout << "Labels per ID: " << labels_per_id << endl;
    //cout << "VF HI size: " << fixed << setprecision(2) << vf_hi_size_in_mb << " MB" << endl;
    //cout << "VF LO size: " << fixed << setprecision(2) << vf_lo_size_in_mb << " MB" << endl;
    cout << "Estimated label data size: " << fixed << setprecision(2) << estimated_label_size_in_mb << " MB" << endl;
    cout << "Total ciphertext collection size (包括缓冲区): " << fixed << setprecision(2) << total_size_in_mb << " MB" << endl;
    //cout << "Buffer size: " << fixed << setprecision(2)
    // << (double)(dvf.GetBufferCapacity() * sizeof(__uint128_t)) / (1024*1024) << " MB" << endl;
 
/*
    // Output statistics
    cout << "\nQuery statistics:" << endl;
    cout << "Total query time: " << fixed << setprecision(3) << total_search_time << " ms" << endl;
    cout << "  - Token generation time: " << fixed << setprecision(3) << total_token_gen_time << " ms (" 
         << fixed << setprecision(1) << (total_token_gen_time * 100.0 / total_search_time) << "%)" << endl;
    cout << "  - VacuumFilter search time: " << fixed << setprecision(3) << total_vf_search_time << " ms (" 
         << fixed << setprecision(1) << (total_vf_search_time * 100.0 / total_search_time) << "%)" << endl;
    cout << "  - Decryption time: " << fixed << setprecision(3) << total_decrypt_time << " ms (" 
         << fixed << setprecision(1) << (total_decrypt_time * 100.0 / total_search_time) << "%)" << endl;
    cout << "Average query time: " << fixed << setprecision(3) << total_search_time / SEARCH_KEYWORDS_NUM << " ms" << endl;
    cout << "  - Avg token generation: " << fixed << setprecision(3) << total_token_gen_time / SEARCH_KEYWORDS_NUM << " ms" << endl;
    cout << "  - Avg VF search: " << fixed << setprecision(3) << total_vf_search_time / SEARCH_KEYWORDS_NUM << " ms" << endl;
    cout << "  - Avg decryption: " << fixed << setprecision(3) << total_decrypt_time / SEARCH_KEYWORDS_NUM << " ms" << endl;
    cout << "Query success rate: " << fixed << setprecision(2) << (found_count * 100.0 / SEARCH_KEYWORDS_NUM) << "%" << endl;
    cout << "TripleVacuumFilter fingerprint length: FP1=" << FP_LEN_1 << " bits, FP2=" << FP_LEN_2 << " bits, FP3=" << FP_LEN_3 << " bits (Total " << FP_LEN_1 + FP_LEN_2 + FP_LEN_3 << " bits)" << endl;

    // 在随机查询结束后添加

    // 全量查询测试：验证所有插入成功的元素都能被检索到
    cout << "\n\n==== 开始全量查询验证 ====" << endl;
    cout << "对所有成功插入的" << (tokens_to_insert.size() - insert_fail) << "个token进行查询..." << endl;

    int verify_total = 0;
    int verify_success = 0;
    auto verify_start = chrono::high_resolution_clock::now();

    // 创建一个集合存储所有插入成功的token（包括缓冲区的元素）
    std::unordered_set<__uint128_t> inserted_tokens;
    for (const auto& token : tokens_to_insert) {
        if (tvf.Contain(token)) {
            inserted_tokens.insert(token);
            verify_total++;
        }
    }

    // 对每个已插入的token进行查询验证
    for (const auto& token : inserted_tokens) {
        if (tvf.Contain(token)) {
            verify_success++;
        }
    }

    auto verify_end = chrono::high_resolution_clock::now();
    std::chrono::duration<double> verify_time = verify_end - verify_start;

    cout << "全量查询统计:" << endl;
    cout << "总查询token数: " << verify_total << endl;
    cout << "成功查询数: " << verify_success << endl;
    cout << "查询成功率: " << fixed << setprecision(2)
         << (verify_success * 100.0 / verify_total) << "%" << endl;
    cout << "全量查询时间: " << fixed << setprecision(3) << verify_time.count() * 1000.0 << " ms" << endl;
    cout << "平均每次查询时间: " << fixed << setprecision(6)
         << (verify_time.count() * 1000.0 / verify_total) << " ms" << endl;

    // 检查缓冲区使用情况
    cout << "\n缓冲区统计:" << endl;
    cout<<"过滤器的大小"<<(tvf.max_keys / 0.96 / 4)<<endl;
    cout << "缓冲区容量: " << tvf.GetBufferCapacity() << endl;
    cout << "缓冲区使用: " << tvf.GetBufferSize() << endl;
    cout << "缓冲区使用率: " << fixed << setprecision(2)
         << (tvf.GetBufferSize() * 100.0 / tvf.GetBufferCapacity()) << "%" << endl;
    cout << "==== 全量查询验证结束 ====" << endl;
    */
}

int main() {
  PUB_PARA.N = conv<ZZ>(
"58096059953699580627919159656392014021766122269029005337029008827797361778909908"
"61472094774477339581147373410185646378328043729800750470098210924487866935059164"
"37158816804754094398164451663275506750162643455639819318662899007124866081936120"
"51197936939854332970361182329144101718768075364573912778570118498974102075191053"
"33355801121109356897459426271845471397952675959440793493071628394122780510124618"
"48823260246464987685045886124578424092925842628769970531258450962541951346360515"
"54280171657144653630940216092905610840258936625612225732020828657978218652709911"
"45082200656978177192827024538990239969175546190770645685893438011714430426409338"
"67631474357115453714203157300427642870143303638180170530865983075119035294602548"
"20599313065710047273624796884155747025969464577702841484359891296328539183921179"
"97472632693078113129886487399347796982772784615865232621289656944284216824611318"
"709764535152507354116344703769998514148343807"
);

// 2) 定义模数 m = p-1，用于求逆
ZZ m = PUB_PARA.N - 1;

// 3) 选 128-bit 熵的 α/α1（可固定硬编码），再在线求逆，保证与当前 N 一致
PUB_PARA.alpha  = conv<ZZ>("255023429925611980797629633666035845595"); // 128-bit
PUB_PARA.alpha1 = conv<ZZ>("187590031298033243259109771525067458753"); // 128-bit
/*
// 4) 严格校验互素并求逆（NTL 自带 InvMod / GCD）
if (GCD(PUB_PARA.alpha,  m) != 1) { throw std::runtime_error("alpha not coprime to p-1"); }
if (GCD(PUB_PARA.alpha1, m) != 1) { throw std::runtime_error("alpha1 not coprime to p-1"); }

PUB_PARA.alpha_inv  = InvMod(PUB_PARA.alpha,  m);
PUB_PARA.alpha_inv1 = InvMod(PUB_PARA.alpha1, m);
*/
PUB_PARA.alpha_inv  = conv<ZZ>("1801988273738030135186273617726785853632037622421220356939845018047723743208654551088845986430691609645296275126021979226817305200194826868012624085037407987795298168099626227902681914122159112833074144175509465424759223046620923145294997782129441507536788913835488246717882912678925428727798988029755346572579967411180769945411183112752491434682062615113656137754427751189088666557792349213920329578245760739215171493678660651193272357182340305249302852694637311791375021575754756480488091068760845662080599514832099820716275869400747089829480155746701813629467646339410670585432500522268423248702434892217736735547694463879298412753968198444399242968002579447658608350922044086197518371038920727118065479933000130028869331171443600582085347320043818637050816844907503913956601814819247606477548125505492797894079625184140074145327265681882039067887661458154105824605991463315548581842968635222090787722365457219031397001667");
PUB_PARA.alpha_inv1 = conv<ZZ>("636039636199095482177520407666130111287074054087436897307376415017521192638745473391279197999196477511321044271408596842979955538503217919093615932637088447320934280256093514595553502484009054373729591932757786547325667901546058257741891244223929490038322558314103107256906196044521072381937633214295184773030271631155115953631193820635540830347546563841505777167409001643814811239096424171501875242308519026481992425824709482477713764983856776395862876862078780669770360589686567159384665946069989414040894998979075196496552923806534890392704330772495390539339249828090499720452076112678647823181232389528170209166399985142667228328882412502155431007700085606289165241683167125588698050965903820009122335071486242099895216287303003501904604407958421359899127963080277351774999457045097163763972925487410303793247511745779400286853268391234017955904275907020670921347459663327478921180391040646667255734094497128451216208747");
// 5) 你的 beta/beta1 保持不变即可（无需可逆）
PUB_PARA.beta  = conv<ZZ>("123456789012345678901234567890123456789");
PUB_PARA.beta1 = conv<ZZ>("987654321098765432109876543210987654321");
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
    cout << "\nAll tests finished!" << endl;
    return 0;
}
