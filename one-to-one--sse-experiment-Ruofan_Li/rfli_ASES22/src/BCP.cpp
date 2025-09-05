#include "BCP.h"
BCP::BCP()
{
    init();
}
BCP::BCP(long security_para)
{
    this->security_para = security_para;
    init();
}

void BCP::init()
{
    Setup();
    KeyGen(pp);
}

void BCP::Setup()
{
    p_ = GenGermainPrime_ZZ(security_para / 2 - 1);
    q_ = GenGermainPrime_ZZ(security_para / 2 - 1);
    p = 2 * p_ + 1;
    q = 2 * q_ + 1;
    N = p * q;
    ZZ temp;
    while (true)
    {
        g = RandomBnd(N * N);
        temp = PowerMod(g, (p_ * q_), (N * N));
        k = (temp - 1) / N;
        if ((temp == 1 + k * N))
            break;
    }

    pp.append(N);
    pp.append(k);
    pp.append(g);

    msk.append(p_);
    msk.append(q_);
}

void BCP::KeyGen(Vec<ZZ> &pp)
{
    ZZ_pPush Push(N * N);
    sk = random_ZZ_p();
    pk = power(to_ZZ_p(pp[2]), rep(sk));
}

void BCP::Enc(ZZ_p &A, ZZ_p &B, const ZZ &m, const ZZ_p &pk)
{
    if ((m) >= N)
    {
        cout << "m is too large" << endl;
        return;
    }
    ZZ_pPush Push(N * N);
    ZZ_p r;
    r = random_ZZ_p();
    A = power(to_ZZ_p(pp[2]), rep(r));
    B = power(pk, rep(r)) * (1 + to_ZZ_p(m * N));
}
void BCP::Enc(ZZ &A, ZZ &B, const ZZ &m)
{
    ZZ_p A_, B_;
    Enc(A_, B_, m, pk);
    A = rep(A_);
    B = rep(B_);
}
void BCP::Enc(ZZ_Cipher &C, const ZZ &m)
{
    Enc(C.first, C.second, m);
}
ZZ_Cipher BCP::Enc(const ZZ &m)
{
    ZZ_Cipher C;
    Enc(C, m);
    return C;
}

void BCP::Dec1(ZZ &m, const ZZ &A, const ZZ &B, const ZZ_p &sk)
{
    ZZ_pPush Push(N * N);
    ZZ_p a;
    a = sk;
    ZZ_p A_, B_;
    A_ = to_ZZ_p(A);
    B_ = to_ZZ_p(B);
    ZZ_p res;
    res = B_ / power(A_, rep(a)) - 1;
    m = rep(res);
    m /= N;
}
void BCP::Dec1(ZZ &m, const ZZ &A, const ZZ &B)
{
    ZZ_pPush Push(N * N);
    Dec1(m, (A), (B), sk);
}
void BCP::Dec1(ZZ &m, const ZZ_Cipher &C)
{
    Dec1(m, C.first, C.second);
}
ZZ BCP::Dec1(const ZZ_Cipher &C)
{
    ZZ res;
    Dec1(res, C);
    return res;
}

void BCP::Dec2(ZZ &m, const ZZ &A, const ZZ &B, const ZZ_p &pk, const Vec<ZZ> &msk)
{
    ZZ a, r;
    ZZ k_inv;
    k_inv = InvMod(k, N);

    ZZ h;
    h = rep(pk);
    a = PowerMod(h, msk[0] * msk[1], N * N);
    r = PowerMod(A, msk[0] * msk[1], N * N);
    a = SubMod(a, ZZ(1), N * N);
    r = SubMod(r, ZZ(1), N * N);
    a /= N;
    r /= N;

    a = MulMod(a, k_inv, N);
    r = MulMod(r, k_inv, N);

    ZZ gamma;
    gamma = MulMod(a, r, N);

    m = PowerMod(g, gamma, N * N);
    m = InvMod(m, N * N);
    m = MulMod(m, B, N * N);
    m = PowerMod(m, msk[0] * msk[1], N * N);
    m = SubMod(m, ZZ(1), N * N);
    m /= N;

    ZZ pi;
    pi = InvMod(msk[0] * msk[1], N);

    m = MulMod(m, pi, N);
}
void BCP::Dec2(ZZ &m, const ZZ &A, const ZZ &B)
{
    Dec2(m, A, B, pk, msk);
}
void BCP::Dec2(ZZ &m, const ZZ_Cipher &C)
{
    Dec2(m, C.first, C.second);
}
ZZ BCP::Dec2(const ZZ_Cipher &C)
{
    ZZ res;
    Dec2(res, C);
    return res;
}

void BCP::homo_add(ZZ_Cipher &res, const ZZ_Cipher &C1, const ZZ_Cipher &C2)
{
    res.first = MulMod(C1.first, C2.first, N * N);
    res.second = MulMod(C1.second, C2.second, N * N);
}
ZZ_Cipher BCP::homo_add(const ZZ_Cipher &C1, const ZZ_Cipher &C2)
{
    ZZ_Cipher res;
    homo_add(res, C1, C2);
    return res;
}

void BCP::const_mul(ZZ_Cipher &res, const ZZ &num, const ZZ_Cipher &C)
{
    res.first = PowerMod(C.first, num, N * N);
    res.second = PowerMod(C.second, num, N * N);
}
ZZ_Cipher BCP::const_mul(const ZZ &num, const ZZ_Cipher &C)
{
    ZZ_Cipher res;
    const_mul(res, num, C);
    return res;
}
void BCP::homo_mul(ZZ_Cipher &res, const ZZ_Cipher &C1, const ZZ_Cipher &C2)
{
    //以下为step1，Cloud server C1的工作
    ZZ tao1, tao2;
    tao1 = RandomBnd(N);
    tao2 = RandomBnd(N);
    ZZ_Cipher Z1 = homo_add(C1, Enc(-tao1));
    ZZ_Cipher Z2 = homo_add(C2, Enc(-tao2));

    //以下为step2，Auxiliary server C2的工作
    ZZ m1_ = Dec2(Z1);
    ZZ m2_ = Dec2(Z2);
    ZZ_Cipher C_ = Enc(MulMod(m1_, m2_, N)); 

    //以下为step3，Cloud server C1的工作
    ZZ_Cipher T = Enc(MulMod(-tao1, tao2, N));
    ZZ &A = res.first;
    A = C_.first;
    A = MulMod(A, PowerMod(C1.first, tao2, N * N), N * N);
    A = MulMod(A, PowerMod(C2.first, tao1, N * N), N * N);
    A = MulMod(A, T.first, N * N);
    ZZ &B = res.second;
    B = C_.second;
    B = MulMod(B, PowerMod(C1.second, tao2, N * N), N * N);
    B = MulMod(B, PowerMod(C2.second, tao1, N * N), N * N);
    B = MulMod(B, T.second, N * N);
}
ZZ_Cipher BCP::homo_mul(const ZZ_Cipher &C1, const ZZ_Cipher &C2)
{
    ZZ_Cipher res;
    homo_mul(res, C1, C2);
    return res;
}

void BCP::sample()
{
    BCP bcp;
    ZZ msg;
    conv(msg, "123456");
    ZZ_Cipher C;
    C = bcp.Enc(msg);
    cout << bcp.Dec1(C) << endl;
    cout << bcp.Dec2(C) << endl;
}

void BCP::sample1()
{
    BCP bcp;
    ZZ msg1, msg2;
    msg1 = 12;
    msg2 = 3;
    ZZ_Cipher C1, C2;
    C1 = bcp.Enc(msg1);
    C2 = bcp.Enc(msg2);
    ZZ_Cipher res;
    res = bcp.const_mul(msg2, C1);
    cout << bcp.Dec1(res) << endl;
}

void BCP::sample2()
{
    BCP bcp;
    ZZ msg1, msg2;
    msg1 = 3;
    msg2 = 9;
    ZZ_Cipher C1, C2;
    C1 = bcp.Enc(msg1);
    C2 = bcp.Enc(msg2);
    ZZ_Cipher res;
    res = bcp.homo_mul(C1, C2);
    cout << bcp.Dec1(res) << endl;
}