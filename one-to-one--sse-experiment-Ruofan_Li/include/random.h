#ifndef __RANDOM__
#define __RANDOM__
#include <iostream>
#include <gmp.h>
#include <queue>
#include <thread>
#include <chrono>
#include <mutex>
#include <unistd.h>
#include <stdlib.h>
using namespace std;
using namespace chrono;
class Bufferpool
{
private:
    static gmp_randstate_t grt;  //随机状态
    static int flag; //种子置入标置
    static int length;
    mutex mutex_1024;
    mutex mutex_256;
    mutex mutex_64;
    static queue<char *> queue_1024;
    static queue<char *> queue_256;
    static queue<char *> queue_64;

public:
    int get_queue1024_len();
    int get_queue256_len();
    int get_queue64_len();
    int init(int len);
    int gen_random(int len);
    int get_random(mpz_t r, int len);
    Bufferpool();
    int set_length(int l = 1000);
    int get_length();
    // ~Bufferpool();
};
class Random
{
private:
    Bufferpool bp;

public:
    int get_rand(mpz_t r, int len);
    int set_pool_len(int l);
    Random();
    // ~Random();
};
#endif