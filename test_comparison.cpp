#include <iostream>
#include <vector>
#include <random>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <cassert>  // 添加断言头文件

// NTL headers must come before vacuum headers to avoid macro conflicts
#include </opt/homebrew/include/NTL/ZZ.h>
#include "./Vacuum-Filter/vacuum.h"
#include "./Vacuum-Filter/vacuum_zz.h"

using namespace std;
using namespace NTL;

void test_original_vacuum_filter() {
    cout << "\n测试原始 VacuumFilter 实现...\n" << endl;
    
    // 使用与当前测试相同的参数
    const int n = 70000;
    const int fingerprint_bits = 16;  // 改为 16 bits
    
    cout << "测试参数：" << endl;
    cout << "元素数量: " << n << endl;
    cout << "指纹长度: " << fingerprint_bits << " bits" << endl;
    
    // 初始化过滤器
    VacuumFilter<uint16_t, fingerprint_bits> vf;
    vf.init(n * 1.2, 8, 1000); // 使用原始论文推荐的参数

    // 生成测试数据
    vector<uint64_t> test_elements;
    mt19937_64 gen(12821);
    for (int i = 0; i < n; i++) {
        test_elements.push_back(gen());
    }

    // 插入测试
    int insert_fail_count = 0;
    for (const auto& element : test_elements) {
        if (!vf.insert(element)) {
            insert_fail_count++;
        }
    }

    // 查找测试
    int lookup_fail_count = 0;
    for (const auto& element : test_elements) {
        if (!vf.lookup(element)) {
            lookup_fail_count++;
        }
    }

    // 输出统计信息
    cout << "\n测试结果:" << endl;
    cout << "Load factor = " << vf.get_load_factor() << endl;
    cout << "插入总数: " << n << endl;
    cout << "插入失败: " << insert_fail_count << endl;
    cout << "查找失败: " << lookup_fail_count << endl;
    cout << "插入成功率: " << fixed << setprecision(2) 
         << ((n - insert_fail_count) * 100.0 / n) << "%" << endl;
    cout << "查找成功率: " << fixed << setprecision(2)
         << ((n - lookup_fail_count) * 100.0 / n) << "%" << endl;
    cout << "Bits per key = " << vf.get_bits_per_item() << endl;
}

void test_vacuum_filter_zz() {
    cout << "\n测试 VacuumFilterZZ 实现...\n" << endl;
    
    const int n = 70000;
    const int fingerprint_bits = 128;
    const int max_bins = 81920 * 2;
    const double false_positive = 1e-20;
    
    cout << "测试参数：" << endl;
    cout << "元素数量: " << n << endl;
    cout << "指纹长度: " << fingerprint_bits << " bits" << endl;
    cout << "过滤器大小: " << max_bins << endl;
    cout << "目标假阳性率: " << false_positive << endl;

    // 初始化过滤器
    VacuumFilterZZ<fingerprint_bits> vf;
    vf.Init(max_bins, false_positive);

    // 生成测试数据
    vector<ZZ> test_elements;
    for (int i = 0; i < n; i++) {
        test_elements.push_back(RandomBits_ZZ(3072));
    }

    // 插入测试
    int insert_fail_count = 0;
    for (const auto& element : test_elements) {
        if (!vf.Insert(element)) {
            insert_fail_count++;
        }
    }

    // 查找测试
    int lookup_fail_count = 0;
    for (const auto& element : test_elements) {
        if (!vf.Lookup(element)) {
            lookup_fail_count++;
        }
    }

    // 输出统计信息
    cout << "\n测试结果:" << endl;
    cout << "插入总数: " << n << endl;
    cout << "插入失败: " << insert_fail_count << endl;
    cout << "查找失败: " << lookup_fail_count << endl;
    cout << "插入成功率: " << fixed << setprecision(2) 
         << ((n - insert_fail_count) * 100.0 / n) << "%" << endl;
    cout << "查找成功率: " << fixed << setprecision(2)
         << ((n - lookup_fail_count) * 100.0 / n) << "%" << endl;
}

int main() {
    // 测试原始实现
    test_original_vacuum_filter();
    
    // 测试当前实现
    test_vacuum_filter_zz();
    
    return 0;
}
