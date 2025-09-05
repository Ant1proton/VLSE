#include "../include/prf.h"

// hash=sm3(m||key)
int sm3_hash_with_key(string &hash, string m, string key)
{
    return SM3::sm3(hash, m + key);
}

// hash=sm3(m||i)(mod N)
int sm3_hash_mod(int location, string m, int i, long N)
{
    string hash;
    int flag = SM3::sm3(hash, m + to_string(i));
    if (hash.substr(0, 1) != "0x")
        hash = "0x" + hash;
    mpz_t hash_t, N_t;
    mpz_init_set_str(hash_t, hash.c_str(), 0);
    mpz_init_set_si(N_t, N);
    mpz_mod(hash_t, hash_t, N_t);
    location = atoi(mpz_get_str(NULL, 10, hash_t));
    return flag;
}