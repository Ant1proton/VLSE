#ifndef _SYSTEM_
#define _SYSTEM_
#include <gmpxx.h>
#include <string>
using namespace std;

//存储公开参数
class system
{
public:
    mpz_t N_t;
    string N;
    int lambda;
    system();
};

#endif