#ifndef _PRF_
#define _PRF
#include <gmpxx.h>
#include "sm3.h"
// hash=sm3(m||key)
int sm3_hash_with_key(string &hash, string m, string key);

// hash=sm3(m||i)(mod N)
int sm3_hash_mod(int location, string m, int i, long N);
#endif