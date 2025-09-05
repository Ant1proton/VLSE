#pragma once
#include <NTL/ZZ.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZ_p.h>

using namespace std;
using namespace NTL;

typedef pair<ZZ, ZZ> ZZ_Cipher;

class BCP
{
private:
    long security_para = 128;
    ZZ N, p, q, q_, p_, g, k;
    Vec<ZZ> pp;  // N, k, g
    Vec<ZZ> msk; // p_, q_
    ZZ_p pk, sk;

public:
    BCP();
    BCP(long security_para);

    ZZ_p get_pk() { return pk; }

    ZZ get_modulus() { return N; }

    ZZ_p get_sk() { return sk; }

    Vec<ZZ> get_pp() { return pp; }

    Vec<ZZ> get_msk() { return msk; }

    void init();

    void Setup();

    void KeyGen(Vec<ZZ> &pp);

    void Enc(ZZ_p &A, ZZ_p &B, const ZZ &m, const ZZ_p &pk);
    void Enc(ZZ &A, ZZ &B, const ZZ &m);
    void Enc(ZZ_Cipher &C, const ZZ &m);
    ZZ_Cipher Enc(const ZZ &m);

    void Dec1(ZZ &m, const ZZ &A, const ZZ &B, const ZZ_p &sk);
    void Dec1(ZZ &m, const ZZ &A, const ZZ &B);
    void Dec1(ZZ &m, const ZZ_Cipher &C);
    ZZ Dec1(const ZZ_Cipher &C);

    void Dec2(ZZ &m, const ZZ &A, const ZZ &B, const ZZ_p &pk, const Vec<ZZ> &msk);
    void Dec2(ZZ &m, const ZZ &A, const ZZ &B);
    void Dec2(ZZ &m, const ZZ_Cipher &C);
    ZZ Dec2(const ZZ_Cipher &C);

    void homo_add(ZZ_Cipher &res, const ZZ_Cipher &C1, const ZZ_Cipher &C2);
    ZZ_Cipher homo_add(const ZZ_Cipher &C1, const ZZ_Cipher &C2);

    void const_mul(ZZ_Cipher &res, const ZZ &num, const ZZ_Cipher &C);
    ZZ_Cipher const_mul(const ZZ &num, const ZZ_Cipher &C);

    void homo_mul(ZZ_Cipher &res, const ZZ_Cipher &C1, const ZZ_Cipher &C2);
    ZZ_Cipher homo_mul(const ZZ_Cipher &C1, const ZZ_Cipher &C2);

    static void sample();
    static void sample1();
    static void sample2();
};
