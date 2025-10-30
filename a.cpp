#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <iomanip>
#include <cstdint>
#include <cassert>

#include "vacuum.h"
#include "hashutil.h"

// Define fingerprint lengths
#define FP_LEN_HI 5
#define FP_LEN_LO 5

using namespace std;
using namespace VacuumFilterNS;

// Helper for splitting 128-bit token
inline void split_token(__uint128_t token, uint64_t &hi, uint64_t &lo) {
    hi = static_cast<uint64_t>(token >> 64);
    lo = static_cast<uint64_t>(token & 0xFFFFFFFFFFFFFFFFULL);
}

// DoubleVacuumFilter implementation from test.cpp
template <size_t FP_HI, size_t FP_LO>
class DoubleVacuumFilter {
public:
    VacuumFilterNS::VacuumFilter<uint64_t, FP_HI> vf_hi;
    VacuumFilterNS::VacuumFilter<uint64_t, FP_LO> vf_lo;

    DoubleVacuumFilter(size_t max_keys) {
        vf_hi.init(max_keys, 4, 500);
        vf_lo.init(max_keys, 4, 500);
    }

    bool Add(const __uint128_t &token) {
        uint64_t hi, lo;
        split_token(token, hi, lo);
        return vf_hi.insert(hi) && vf_lo.insert(lo);
    }

    bool Contain(const __uint128_t &token) const {
        uint64_t hi, lo;
        split_token(token, hi, lo);
        return vf_hi.lookup(hi) && vf_lo.lookup(lo);
    }

    bool Delete(const __uint128_t &token) {
        uint64_t hi, lo;
        split_token(token, hi, lo);
        return vf_hi.del(hi) && vf_lo.del(lo);
    }
};

// Test standard VacuumFilter with 64-bit keys
void test_basic_vacuum_filter() {
    cout << "\n===== Testing Basic VacuumFilter =====" << endl;
    
    // Test with different data sizes
    vector<int> test_sizes = {1000, 10000, 100000};
    
    for (int n : test_sizes) {
        cout << "\nTesting with " << n << " elements:" << endl;
        
        // Initialize filter with a small buffer
        VacuumFilter<uint64_t, 16> vf;
        vf.init(n * 1.2, 4, 500);
        
        // Generate test data
        vector<uint64_t> test_data;
        mt19937_64 rng(42);  // Fixed seed for reproducibility
        for (int i = 0; i < n; i++) {
            test_data.push_back(rng());
        }
        
        // Insert elements
        int insert_failures = 0;
        auto start_insert = chrono::high_resolution_clock::now();
        for (const auto& item : test_data) {
            if (!vf.insert(item)) {
                insert_failures++;
            }
        }
        auto end_insert = chrono::high_resolution_clock::now();
        chrono::duration<double> insert_time = end_insert - start_insert;
        
        // Query elements
        int query_failures = 0;
        auto start_query = chrono::high_resolution_clock::now();
        for (const auto& item : test_data) {
            if (!vf.lookup(item)) {
                query_failures++;
            }
        }
        auto end_query = chrono::high_resolution_clock::now();
        chrono::duration<double> query_time = end_query - start_query;
        
        // Calculate success rates
        double insert_success_rate = (n - insert_failures) * 100.0 / n;
        double query_success_rate = (n - query_failures) * 100.0 / n;
        
        // Print results
        cout << "Insertion: " << (n - insert_failures) << "/" << n 
             << " success (" << fixed << setprecision(2) << insert_success_rate << "%)" << endl;
        cout << "Query: " << (n - query_failures) << "/" << n 
             << " success (" << fixed << setprecision(2) << query_success_rate << "%)" << endl;
        cout << "Insertion time: " << insert_time.count() << " seconds" << endl;
        cout << "Query time: " << query_time.count() << " seconds" << endl;
        cout << "Load factor: " << vf.get_load_factor() << endl;
    }
}

// Test DoubleVacuumFilter with 128-bit keys
void test_double_vacuum_filter() {
    cout << "\n===== Testing DoubleVacuumFilter =====" << endl;
    
    // Test with different data sizes
    vector<int> test_sizes = {1000, 10000, 50000};
    
    for (int n : test_sizes) {
        cout << "\nTesting with " << n << " elements:" << endl;
        
        // Initialize filter
        DoubleVacuumFilter<FP_LEN_HI, FP_LEN_LO> dvf(n * 1.2);
        
        // Generate test data
        vector<__uint128_t> test_data;
        mt19937_64 rng(42);  // Fixed seed for reproducibility
        for (int i = 0; i < n; i++) {
            uint64_t hi = rng();
            uint64_t lo = rng();
            __uint128_t token = (__uint128_t(hi) << 64) | lo;
            test_data.push_back(token);
        }
        
        // Insert elements
        int insert_failures = 0;
        auto start_insert = chrono::high_resolution_clock::now();
        for (const auto& item : test_data) {
            if (!dvf.Add(item)) {
                insert_failures++;
            }
        }
        auto end_insert = chrono::high_resolution_clock::now();
        chrono::duration<double> insert_time = end_insert - start_insert;
        
        // Query elements
        int query_failures = 0;
        auto start_query = chrono::high_resolution_clock::now();
        for (const auto& item : test_data) {
            if (!dvf.Contain(item)) {
                query_failures++;
            }
        }
        auto end_query = chrono::high_resolution_clock::now();
        chrono::duration<double> query_time = end_query - start_query;
        
        // Calculate success rates
        double insert_success_rate = (n - insert_failures) * 100.0 / n;
        double query_success_rate = (n - query_failures) * 100.0 / n;
        
        // Print results
        cout << "Insertion: " << (n - insert_failures) << "/" << n 
             << " success (" << fixed << setprecision(2) << insert_success_rate << "%)" << endl;
        cout << "Query: " << (n - query_failures) << "/" << n 
             << " success (" << fixed << setprecision(2) << query_success_rate << "%)" << endl;
        cout << "Insertion time: " << insert_time.count() << " seconds" << endl;
        cout << "Query time: " << query_time.count() << " seconds" << endl;
    }
}

// Test scalability with fingerprint length
void test_fingerprint_lengths() {
    cout << "\n===== Testing Different Fingerprint Lengths =====" << endl;
    
    const int n = 10000;
    vector<int> fp_lengths = {8, 12, 16};
    
    cout << "Testing with " << n << " elements:" << endl;
    
    for (int fp_len : fp_lengths) {
        cout << "\nFingerprint length: " << fp_len << " bits" << endl;
        
        // We need to use a template approach here based on the fingerprint length
        if (fp_len == 8) {
            VacuumFilter<uint64_t, 8> vf;
            vf.init(n * 1.2, 4, 500);
            // Same testing logic...
            cout << "Success rates would be calculated here..." << endl;
        } 
        else if (fp_len == 12) {
            VacuumFilter<uint64_t, 12> vf;
            vf.init(n * 1.2, 4, 500);
            // Same testing logic...
            cout << "Success rates would be calculated here..." << endl;
        }
        else if (fp_len == 16) {
            VacuumFilter<uint64_t, 16> vf;
            vf.init(n * 1.2, 4, 500);
            // Same testing logic...
            cout << "Success rates would be calculated here..." << endl;
        }
    }
}

int main() {
    // Set cout formatting
    cout << fixed << setprecision(4);
    
    // Run all tests
    test_basic_vacuum_filter();
    test_double_vacuum_filter();
    
    return 0;
}