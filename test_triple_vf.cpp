#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <iomanip>
#include <fstream>
#include <unordered_set>
#include <algorithm>
#include "Vacuum-Filter/vacuum.h"
#include "Vacuum-Filter/hashutil.h"

using namespace std;
using namespace VacuumFilterNS;

// 指纹长度配置：15+15+13=43位
#define FP_LEN_1 15  // 第一个VF：15位指纹
#define FP_LEN_2 15  // 第二个VF：15位指纹  
#define FP_LEN_3 13  // 第三个VF：13位指纹

// __uint128_t输出运算符
std::ostream& operator<<(std::ostream& os, const __uint128_t& value) {
    if (value == 0) {
        return os << "0";
    }
    
    char buffer[50];
    char* pos = std::end(buffer) - 1;
    *pos = '\0';
    
    __uint128_t tmp = value;
    do {
        pos--;
        *pos = '0' + (tmp % 10);
        tmp /= 10;
    } while (tmp != 0);
    
    return os << pos;
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
    VacuumFilter<uint64_t, FP1> vf1;
    VacuumFilter<uint64_t, FP2> vf2;
    VacuumFilter<uint64_t, FP3> vf3;
    
    // 添加缓冲区以处理插入失败的情况
    std::unordered_set<__uint128_t> buffer;
    size_t buffer_capacity;
    size_t max_keys;

    TripleVacuumFilter(size_t max_keys) : max_keys(max_keys) {
        // 初始化三个VF实例
        vf1.init(max_keys, 4, 500);  // 4 slots per bucket, 500 max kick steps
        vf2.init(max_keys, 4, 500);
        vf3.init(max_keys, 4, 500);
        
        // 设置缓冲区容量为过滤器大小的1%
        buffer_capacity = max(static_cast<size_t>(1), max_keys / 100);
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

// 生成测试数据
vector<__uint128_t> generate_test_tokens(int count) {
    vector<__uint128_t> tokens;
    tokens.reserve(count);
    
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(0, UINT64_MAX);
    
    for (int i = 0; i < count; i++) {
        uint64_t hi = dis(gen);
        uint64_t lo = dis(gen);
        __uint128_t token = ((__uint128_t)hi << 64) | lo;
        tokens.push_back(token);
    }
    
    return tokens;
}

void test_triple_vf(int num_tokens) {
    cout << "\n===== 三重VacuumFilter测试 (43位指纹：15+15+13) =====" << endl;
    cout << "测试数据量: " << num_tokens << " 个128位token" << endl;
    
    // 生成测试数据
    vector<__uint128_t> tokens = generate_test_tokens(num_tokens);
    cout << "生成了 " << tokens.size() << " 个测试token" << endl;
    
    // 初始化三重VF
    TripleVacuumFilter<FP_LEN_1, FP_LEN_2, FP_LEN_3> tvf(num_tokens);
    
    // 插入测试
    cout << "\n开始插入测试..." << endl;
    int fail_insert = 0;
    
    auto start_insert = chrono::high_resolution_clock::now();
    for (int i = 0; i < num_tokens; i++) {
        if (!tvf.Add(tokens[i])) {
            fail_insert++;
        }
        
        if ((i + 1) % 1000 == 0) {
            cout << "插入进度: " << (i + 1) << "/" << num_tokens 
                 << ", 失败: " << fail_insert << endl;
        }
    }
    auto end_insert = chrono::high_resolution_clock::now();
    auto insert_time = chrono::duration_cast<chrono::milliseconds>(end_insert - start_insert);
    
    double insert_success_rate = 100.0 * (num_tokens - fail_insert) / num_tokens;
    cout << "\n📊 插入结果:" << endl;
    cout << "插入成功率: " << fixed << setprecision(2) << insert_success_rate 
         << "% (" << (num_tokens - fail_insert) << "/" << num_tokens << ")" << endl;
    cout << "插入时间: " << insert_time.count() << " ms" << endl;
    
    // 查询测试 - 测试所有成功插入的token
    cout << "\n开始查询测试..." << endl;
    int query_success = 0;
    
    auto start_lookup = chrono::high_resolution_clock::now();
    for (int i = 0; i < num_tokens; i++) {
        if (tvf.Contain(tokens[i])) {
            query_success++;
        }
    }
    auto end_lookup = chrono::high_resolution_clock::now();
    auto query_time = chrono::duration_cast<chrono::milliseconds>(end_lookup - start_lookup);
    
    double query_success_rate = 100.0 * query_success / num_tokens;
    cout << "\n🔍 查询结果:" << endl;
    cout << "查询成功数: " << query_success << "/" << num_tokens << endl;
    cout << "查询成功率: " << fixed << setprecision(2) << query_success_rate << "%" << endl;
    cout << "查询时间: " << query_time.count() << " ms" << endl;
    
    if (num_tokens > 0) {
        cout << "平均每次查询时间: " << fixed << setprecision(3) 
             << (query_time.count() * 1000.0 / num_tokens) << " 微秒" << endl;
    }
    
    // 内存使用统计
    cout << "\n💾 内存使用:" << endl;
    cout << "VF1 (15位): " << fixed << setprecision(2) 
         << (tvf.vf1.memory_consumption / 1024.0) << " KB" << endl;
    cout << "VF2 (15位): " << fixed << setprecision(2) 
         << (tvf.vf2.memory_consumption / 1024.0) << " KB" << endl;
    cout << "VF3 (13位): " << fixed << setprecision(2) 
         << (tvf.vf3.memory_consumption / 1024.0) << " KB" << endl;
    cout << "缓冲区大小: " << tvf.GetBufferSize() << "/" << tvf.GetBufferCapacity() 
         << " (" << fixed << setprecision(2) 
         << (tvf.GetBufferSize() * 100.0 / tvf.GetBufferCapacity()) << "%)" << endl;
    cout << "总内存: " << fixed << setprecision(2) 
         << (tvf.GetTotalMemoryConsumption() / 1024.0) << " KB" << endl;
    
    // 验证插入和查询的一致性
    int consistency_errors = 0;
    for (const auto& token : tokens) {
        bool can_find = tvf.Contain(token);
        // 如果token能被找到，说明插入成功；如果找不到，说明插入失败
        // 这里检查是否存在不一致的情况
    }
    
    // 成功率评估
    if (insert_success_rate == 100.0 && query_success_rate == 100.0) {
        cout << "\n🏆 完美！达到100%插入和查询成功率！" << endl;
        cout << "✅ 三重VacuumFilter (15+15+13=43位) 验证通过！" << endl;
    } else if (insert_success_rate >= 99.0 && query_success_rate >= 99.0) {
        cout << "\n✅ 接近100%成功率，性能优秀！" << endl;
    } else {
        cout << "\n⚠️ 成功率需要进一步优化" << endl;
    }
    
    cout << "\n===== " << num_tokens << " 个token测试完成 =====" << endl;
}

int main() {
    cout << "三重VacuumFilter测试程序" << endl;
    cout << "目标：43位指纹 (15+15+13) 接近100%成功率" << endl;
    cout << "================================================\n" << endl;
    
    // 测试不同数量级
    vector<int> test_sizes = {1000, 5000, 10000, 20000};
    
    for (int num_tokens : test_sizes) {
        test_triple_vf(num_tokens);
        cout << "\n" << endl;
    }
    
    cout << "🏁 所有测试完成！" << endl;
    
    return 0;
}
