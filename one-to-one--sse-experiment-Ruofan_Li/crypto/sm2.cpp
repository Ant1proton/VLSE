#include "sm2.h"

void EccCrypto::KDF(unsigned char *data, unsigned int data_len, unsigned int key_len, unsigned char *key)
{
    unsigned int multiple = 0;
    unsigned int remainder = 0;
    unsigned int ct = 0x1;
    unsigned int i;
    unsigned char temp[388];
    multiple = key_len / 32;
    remainder = key_len % 32;
    for (i = 0; i < data_len; i++)
        temp[i] = data[i];
    for (i = 0; i < multiple; i++)
    {
        *(temp + data_len) = (unsigned char)(ct >> 24);
        *(temp + data_len + 1) = (unsigned char)(ct >> 16);
        *(temp + data_len + 2) = (unsigned char)(ct >> 8);
        *(temp + data_len + 3) = (unsigned char)(ct);
        SM3::SM3_HASH(temp, data_len + 4, data_len + 4, key + 32 * i, 32, 0);
        ct++;
    }
    if (remainder != 0)
    {
        *(temp + data_len) = (unsigned char)(ct >> 24);
        *(temp + data_len + 1) = (unsigned char)(ct >> 16);
        *(temp + data_len + 2) = (unsigned char)(ct >> 8);
        *(temp + data_len + 3) = (unsigned char)(ct);
        SM3::SM3_HASH(temp, data_len + 4, data_len + 4, key + 32 * multiple, remainder, 0);
    }
}

int EccCrypto::EccMakeKey(unsigned char *sk, unsigned int sk_len, unsigned char *pk, unsigned int pk_len, int type)
{
    int i, j;
    unsigned int prikey[DIG_LEN] = {0};
    unsigned int x;
    affpoint pubkey;

    if (sk_len != 4 * DIG_LEN)
    {
        return (-1);
    }

    for (i = 0, j = 0; i < DIG_LEN; i++, j += 4)
    {
        prikey[DIG_LEN - 1 - i] = (((unsigned int)(sk[j]) << 24) | ((unsigned int)(sk[j + 1]) << 16) | ((unsigned int)(sk[j + 2]) << 8) | ((unsigned int)(sk[j + 3])));
    }

    basepointmul(&pubkey, prikey);

    x = 0;
    for (i = 0; i < DIG_LEN; i++)
    {
        x |= (pubkey.x[i] | pubkey.y[i]);
    }
    if (x == 0)
    {
        return (-1);
    }

    for (i = 0, j = 0; i < DIG_LEN; i++, j += 4)
    {
        pk[j] = (unsigned char)((pubkey.x[DIG_LEN - 1 - i] >> 24) & 0xff);
        pk[j + 1] = (unsigned char)((pubkey.x[DIG_LEN - 1 - i] >> 16) & 0xff);
        pk[j + 2] = (unsigned char)((pubkey.x[DIG_LEN - 1 - i] >> 8) & 0xff);
        pk[j + 3] = (unsigned char)((pubkey.x[DIG_LEN - 1 - i]) & 0xff);

        pk[j + 4 * DIG_LEN] = (unsigned char)((pubkey.y[DIG_LEN - 1 - i] >> 24) & 0xff);
        pk[j + 1 + 4 * DIG_LEN] = (unsigned char)((pubkey.y[DIG_LEN - 1 - i] >> 16) & 0xff);
        pk[j + 2 + 4 * DIG_LEN] = (unsigned char)((pubkey.y[DIG_LEN - 1 - i] >> 8) & 0xff);
        pk[j + 3 + 4 * DIG_LEN] = (unsigned char)((pubkey.y[DIG_LEN - 1 - i]) & 0xff);
    }

    //*pk_len = 8 * DIG_LEN;

    return 0;
}

int EccCrypto::EccSign(const unsigned char *hash, unsigned int hash_len,
                       unsigned char *random, unsigned int random_len,
                       unsigned char *sk, unsigned int sk_len,
                       unsigned char *sign, unsigned int sign_len)
{
    int i, j;
    unsigned int prikey[DIG_LEN] = {0};
    unsigned int rand[DIG_LEN] = {0};
    unsigned int e[DIG_LEN] = {0};
    unsigned int r[DIG_LEN] = {0};
    unsigned int s[DIG_LEN] = {0};
    unsigned int y[DIG_LEN] = {0};
    unsigned int h[DIG_LEN] = {0};
    unsigned int l[DIG_LEN] = {0};
    unsigned int m[DIG_LEN] = {0x1};
    unsigned int z[DIG_LEN] = {0x1};
    affpoint kg;
    unsigned int x;

    if (hash_len != 4 * DIG_LEN)
    {
        return (-1);
    }
    if (random_len != 4 * DIG_LEN)
    {
        return (-1);
    }
    if (sk_len != 4 * DIG_LEN)
    {
        return (-1);
    }

    for (i = 0, j = 0; i < DIG_LEN; i++, j += 4)
    {
        prikey[DIG_LEN - 1 - i] = (((unsigned int)(sk[j]) << 24) | ((unsigned int)(sk[j + 1]) << 16) | ((unsigned int)(sk[j + 2]) << 8) | ((unsigned int)(sk[j + 3])));
    }
    x = 0;
    for (i = 0; i < DIG_LEN; i++)
    {
        x |= prikey[i];
    }
    if (x == 0)
    {
        return (-1);
    }
    x = compare(prikey, (small *)N);
    if (x == 1)
    {
        return (-1);
    }
    for (i = 0, j = 0; i < DIG_LEN; i++, j += 4)
    {
        rand[DIG_LEN - 1 - i] = (((unsigned int)(random[j]) << 24) | ((unsigned int)(random[j + 1]) << 16) | ((unsigned int)(random[j + 2]) << 8) | ((unsigned int)(random[j + 3])));
    }
    x = 0;
    for (i = 0; i < DIG_LEN; i++)
    {
        x |= rand[i];
    }
    if (x == 0)
    {
        return (-1);
    }
    x = compare(rand, (small *)N);
    if (x == 1)
    {
        return (-1);
    }

    for (i = 0, j = 0; i < DIG_LEN; i++, j += 4)
    {
        e[DIG_LEN - 1 - i] = (((unsigned int)(hash[j]) << 24) | ((unsigned int)(hash[j + 1]) << 16) | ((unsigned int)(hash[j + 2]) << 8) | ((unsigned int)(hash[j + 3])));
    }

    basepointmul(&kg, rand);

    for (i = 0; i < DIG_LEN; i++)
    {
        r[i] = kg.x[i];
    }
    modadd(r, e, r, (small *)N);

    x = 0;
    for (i = 0; i < DIG_LEN; i++)
    {
        x |= r[i];
    }
    if (x == 0)
    {
        return (-1);
    }
    modadd(z, r, rand, (small *)N);
    x = 0;
    for (i = 0; i < DIG_LEN; i++)
    {
        x |= z[i];
    }
    if (x == 0)
    {
        return (-1);
    }

    modadd(y, m, prikey, (small *)N);
    modinv(h, y, (small *)N);
    mulmodorder(y, r, prikey);
    modsub(l, rand, y, (small *)N);
    mulmodorder(s, h, l);

    x = 0;
    for (i = 0; i < DIG_LEN; i++)
    {
        x |= s[i];
    }
    if (x == 0)
    {
        return (-1);
    }

    for (i = 0, j = 0; i < DIG_LEN; i++, j += 4)
    {
        sign[j] = (unsigned char)((r[DIG_LEN - 1 - i] >> 24) & 0xff);
        sign[j + 1] = (unsigned char)((r[DIG_LEN - 1 - i] >> 16) & 0xff);
        sign[j + 2] = (unsigned char)((r[DIG_LEN - 1 - i] >> 8) & 0xff);
        sign[j + 3] = (unsigned char)((r[DIG_LEN - 1 - i]) & 0xff);

        sign[j + 4 * DIG_LEN] = (unsigned char)((s[DIG_LEN - 1 - i] >> 24) & 0xff);
        sign[j + 1 + 4 * DIG_LEN] = (unsigned char)((s[DIG_LEN - 1 - i] >> 16) & 0xff);
        sign[j + 2 + 4 * DIG_LEN] = (unsigned char)((s[DIG_LEN - 1 - i] >> 8) & 0xff);
        sign[j + 3 + 4 * DIG_LEN] = (unsigned char)((s[DIG_LEN - 1 - i]) & 0xff);
    }

    sign_len = 8 * DIG_LEN;

    return 0;
}

int EccCrypto::EccVerify(const unsigned char *hash, unsigned int hash_len,
                         unsigned char *pk, unsigned int pk_len,
                         unsigned char *sign, unsigned int sign_len)
{
    int i, j;
    unsigned int t[DIG_LEN] = {0};
    unsigned int r[DIG_LEN] = {0};
    unsigned int s[DIG_LEN] = {0};
    unsigned int e[DIG_LEN] = {0};
    unsigned int R[DIG_LEN] = {0};
    affpoint p1, p2, p3;
    unsigned int x;

    if (hash_len != 4 * DIG_LEN)
    {
        return (-1);
    }
    if (pk_len != 8 * DIG_LEN)
    {
        return (-1);
    }
    if (sign_len != 8 * DIG_LEN)
    {
        return (-1);
    }

    for (i = 0, j = 0; i < DIG_LEN; i++, j += 4)
    {
        p1.x[DIG_LEN - 1 - i] = (((unsigned int)(pk[j]) << 24) | ((unsigned int)(pk[j + 1]) << 16) | ((unsigned int)(pk[j + 2]) << 8) | ((unsigned int)(pk[j + 3])));
        p1.y[DIG_LEN - 1 - i] = (((unsigned int)(pk[j + 4 * DIG_LEN]) << 24) | ((unsigned int)(pk[j + 1 + 4 * DIG_LEN]) << 16) | ((unsigned int)(pk[j + 2 + 4 * DIG_LEN]) << 8) | ((unsigned int)(pk[j + 3 + 4 * DIG_LEN])));
    }

    for (i = 0, j = 0; i < DIG_LEN; i++, j += 4)
    {
        r[DIG_LEN - 1 - i] = (((unsigned int)(sign[j]) << 24) | ((unsigned int)(sign[j + 1]) << 16) | ((unsigned int)(sign[j + 2]) << 8) | ((unsigned int)(sign[j + 3])));
        s[DIG_LEN - 1 - i] = (((unsigned int)(sign[j + 4 * DIG_LEN]) << 24) | ((unsigned int)(sign[j + 1 + 4 * DIG_LEN]) << 16) | ((unsigned int)(sign[j + 2 + 4 * DIG_LEN]) << 8) | ((unsigned int)(sign[j + 3 + 4 * DIG_LEN])));
    }

    for (i = 0, j = 0; i < DIG_LEN; i++, j += 4)
    {
        e[DIG_LEN - 1 - i] = (((unsigned int)(hash[j]) << 24) | ((unsigned int)(hash[j + 1]) << 16) | ((unsigned int)(hash[j + 2]) << 8) | ((unsigned int)(hash[j + 3])));
    }

    x = 0;
    for (i = 0; i < DIG_LEN; i++)
    {
        x |= r[i];
    }
    if (x == 0)
    {
        return (-1);
    }
    x = compare(r, (small *)N);
    if (x == 1)
    {
        return (-1);
    }

    x = 0;
    for (i = 0; i < DIG_LEN; i++)
    {
        x |= s[i];
    }
    if (x == 0)
    {
        return (-1);
    }
    x = compare(s, (small *)N);
    if (x == 1)
    {
        return (-1);
    }

    modadd(t, r, s, (small *)N);

    x = 0;
    for (i = 0; i < DIG_LEN; i++)
    {
        x |= t[i];
    }
    if (x == 0)
    {
        return (-1);
    }

    basepointmul(&p2, s);
    pointmul(&p3, &p1, t);
    pointadd(&p1, &p2, &p3);

    modadd(R, p1.x, e, (small *)N);

    x = 0;
    for (i = 0; i < DIG_LEN; i++)
    {
        x |= (R[i] ^ r[i]);
    }
    if (x != 0)
    {
        return (-1);
    }

    return 0;
}

int EccCrypto::EccEncrypt(unsigned char *plain, unsigned int plain_len,
                          unsigned char *random, unsigned int random_len,
                          unsigned char *pk, unsigned int pk_len,
                          unsigned char *cipher, unsigned int cipher_len)
{
    int i, j, multiple, remainder;
    unsigned int y, rand[DIG_LEN] = {0};
    affpoint p;
    unsigned char x[8 * DIG_LEN], t[96];

    if (random_len != 4 * DIG_LEN)
        return (-1);

    if (pk_len != 8 * DIG_LEN)
        return (-1);

    for (i = 0, j = 0; i < DIG_LEN; i++, j += 4)
    {
        rand[DIG_LEN - 1 - i] = (((unsigned int)(random[j]) << 24) | ((unsigned int)(random[j + 1]) << 16) | ((unsigned int)(random[j + 2]) << 8) | ((unsigned int)(random[j + 3])));
    }

    y = 0;

    for (i = 0; i < DIG_LEN; i++)
        y |= rand[i];

    if (y == 0)
        return (-1);

    y = compare(rand, (small *)N);

    if (y == 1)
        return (-1);

    basepointmul(&p, rand);

    y = 0;

    for (i = 0; i < DIG_LEN; i++)
        y |= (p.x[i] | p.y[i]);

    if (y == 0)
        return (-1);

    for (i = 0, j = 0; i < DIG_LEN; i++, j += 4)
    {
        cipher[j] = (unsigned char)((p.x[DIG_LEN - 1 - i] >> 24) & 0xff);
        cipher[j + 1] = (unsigned char)((p.x[DIG_LEN - 1 - i] >> 16) & 0xff);
        cipher[j + 2] = (unsigned char)((p.x[DIG_LEN - 1 - i] >> 8) & 0xff);
        cipher[j + 3] = (unsigned char)((p.x[DIG_LEN - 1 - i]) & 0xff);

        cipher[j + 4 * DIG_LEN] = (unsigned char)((p.y[DIG_LEN - 1 - i] >> 24) & 0xff);
        cipher[j + 1 + 4 * DIG_LEN] = (unsigned char)((p.y[DIG_LEN - 1 - i] >> 16) & 0xff);
        cipher[j + 2 + 4 * DIG_LEN] = (unsigned char)((p.y[DIG_LEN - 1 - i] >> 8) & 0xff);
        cipher[j + 3 + 4 * DIG_LEN] = (unsigned char)((p.y[DIG_LEN - 1 - i]) & 0xff);
    }

    for (i = 0, j = 0; i < DIG_LEN; i++, j += 4)
    {
        p.x[DIG_LEN - 1 - i] = (((unsigned int)(pk[j]) << 24) | ((unsigned int)(pk[j + 1]) << 16) | ((unsigned int)(pk[j + 2]) << 8) | ((unsigned int)(pk[j + 3])));
        p.y[DIG_LEN - 1 - i] = (((unsigned int)(pk[j + 4 * DIG_LEN]) << 24) | ((unsigned int)(pk[j + 1 + 4 * DIG_LEN]) << 16) | ((unsigned int)(pk[j + 2 + 4 * DIG_LEN]) << 8) | ((unsigned int)(pk[j + 3 + 4 * DIG_LEN])));
    }
    pointmul(&p, &p, rand);
    for (i = 0, j = 0; i < DIG_LEN; i++, j += 4)
    {
        x[j] = (unsigned char)((p.x[DIG_LEN - 1 - i] >> 24) & 0xff);
        x[j + 1] = (unsigned char)((p.x[DIG_LEN - 1 - i] >> 16) & 0xff);
        x[j + 2] = (unsigned char)((p.x[DIG_LEN - 1 - i] >> 8) & 0xff);
        x[j + 3] = (unsigned char)((p.x[DIG_LEN - 1 - i]) & 0xff);

        x[j + 4 * DIG_LEN] = (unsigned char)((p.y[DIG_LEN - 1 - i] >> 24) & 0xff);
        x[j + 1 + 4 * DIG_LEN] = (unsigned char)((p.y[DIG_LEN - 1 - i] >> 16) & 0xff);
        x[j + 2 + 4 * DIG_LEN] = (unsigned char)((p.y[DIG_LEN - 1 - i] >> 8) & 0xff);
        x[j + 3 + 4 * DIG_LEN] = (unsigned char)((p.y[DIG_LEN - 1 - i]) & 0xff);
    }

    // 加密
    KDF(x, pk_len, plain_len, cipher + 8 * DIG_LEN);

    y = 0;
    for (i = 0; i < (int)plain_len; i++)
        y |= cipher[8 * DIG_LEN + i];

    if (y == 0)
        return (-1);

    for (i = 0; i < (int)plain_len; i++)
        cipher[8 * DIG_LEN + i] ^= plain[i];

    if (plain_len < 33)
    {
        for (i = 0; i < 32; i++)
            t[i] = x[i];
        for (i = 0; i < (int)plain_len; i++)
            t[32 + i] = plain[i];
        for (i = 32 + plain_len; i < (int)(pk_len + plain_len); i++)
            t[i] = x[i - plain_len];
        SM3::SM3_HASH(t, pk_len + plain_len, pk_len + plain_len, cipher + pk_len + plain_len, 32, 0);
    }
    else
    {
        for (i = 0; i < 32; i++)
            t[i] = x[i];
        for (i = 0; i < 32; i++)
            t[32 + i] = plain[i];
        SM3::SM3_HASH(t, 64, 64 + plain_len, cipher + 8 * DIG_LEN + plain_len, 32, 1);
        multiple = (plain_len - 32) / 64;
        remainder = (plain_len - 32) % 64;
        if (multiple != 0)
            SM3::SM3_HASH(plain + 32, 64 * multiple, 64 + plain_len, cipher + 8 * DIG_LEN + plain_len, 32, 2);
        for (i = 0; i < remainder; i++)
            t[i] = plain[32 + 64 * multiple + i];
        for (i = remainder; i < 32 + remainder; i++)
            t[i] = x[i + 32 - remainder];
        SM3::SM3_HASH(t, 32 + remainder, pk_len + plain_len, cipher + pk_len + plain_len, 32, 3);
    }
    cipher_len = 8 * DIG_LEN + plain_len + 32;

    return 0;
}

int EccCrypto::EccDecrypt(unsigned char *cipher, unsigned int cipher_len,
                          unsigned char *sk, unsigned int sk_len,
                          unsigned char *plain, unsigned int plain_len)
{
    int i, j, multiple, remainder;
    unsigned int prikey[DIG_LEN] = {0};
    affpoint p;
    unsigned char y, u[32];
    unsigned char x[8 * DIG_LEN], t[96];

    // 判断密文是否有效，无效则返回错误
    if ((int)cipher_len < 8 * DIG_LEN + 32)
    {
        return (-1);
    }
    // 判断私钥是否有效，无效则返回错误
    if (sk_len != 4 * DIG_LEN)
    {
        return (-1);
    }

    for (i = 0, j = 0; i < DIG_LEN; i++, j += 4)
    {
        p.x[DIG_LEN - 1 - i] = (((unsigned int)(cipher[j]) << 24) | ((unsigned int)(cipher[j + 1]) << 16) | ((unsigned int)(cipher[j + 2]) << 8) | ((unsigned int)(cipher[j + 3])));
        p.y[DIG_LEN - 1 - i] = (((unsigned int)(cipher[j + 4 * DIG_LEN]) << 24) | ((unsigned int)(cipher[j + 1 + 4 * DIG_LEN]) << 16) | ((unsigned int)(cipher[j + 2 + 4 * DIG_LEN]) << 8) | ((unsigned int)(cipher[j + 3 + 4 * DIG_LEN])));
    }
    // 判断C1是否是曲线上的点，不是则返回错误
    if (pointVerify(&p) == -1)
        return (-1);

    for (i = 0, j = 0; i < DIG_LEN; i++, j += 4)
        prikey[DIG_LEN - 1 - i] = (((unsigned int)(sk[j]) << 24) | ((unsigned int)(sk[j + 1]) << 16) | ((unsigned int)(sk[j + 2]) << 8) | ((unsigned int)(sk[j + 3])));

    y = 0;
    for (i = 0; i < DIG_LEN; i++)
    {
        y |= prikey[i];
    }
    if (y == 0)
    {
        return (-1);
    }
    y = compare(prikey, (small *)N);
    if (y == 1)
    {
        return (-1);
    }
    pointmul(&p, &p, prikey);

    y = 0;
    for (i = 0; i < DIG_LEN; i++)
    {
        y |= (p.x[i] | p.y[i]);
    }
    if (y == 0)
    {
        return (-1);
    }

    for (i = 0, j = 0; i < DIG_LEN; i++, j += 4)
    {
        x[j] = (unsigned char)((p.x[DIG_LEN - 1 - i] >> 24) & 0xff);
        x[j + 1] = (unsigned char)((p.x[DIG_LEN - 1 - i] >> 16) & 0xff);
        x[j + 2] = (unsigned char)((p.x[DIG_LEN - 1 - i] >> 8) & 0xff);
        x[j + 3] = (unsigned char)((p.x[DIG_LEN - 1 - i]) & 0xff);

        x[j + 4 * DIG_LEN] = (unsigned char)((p.y[DIG_LEN - 1 - i] >> 24) & 0xff);
        x[j + 1 + 4 * DIG_LEN] = (unsigned char)((p.y[DIG_LEN - 1 - i] >> 16) & 0xff);
        x[j + 2 + 4 * DIG_LEN] = (unsigned char)((p.y[DIG_LEN - 1 - i] >> 8) & 0xff);
        x[j + 3 + 4 * DIG_LEN] = (unsigned char)((p.y[DIG_LEN - 1 - i]) & 0xff);
    }

    // 解密
    KDF(x, 64, cipher_len - 96, plain);

    y = 0;
    for (i = 0; i < (int)cipher_len - 96; i++)
    {
        y |= plain[i];
    }
    if (y == 0)
    {
        return (-1);
    }
    for (i = 0; i < (int)cipher_len - 96; i++)
    {
        plain[i] ^= cipher[64 + i];
    }
    plain_len = cipher_len - 96;

    if ((int)(plain_len) < 33)
    {
        for (i = 0; i < 32; i++)
            t[i] = x[i];
        for (i = 0; i < (int)(plain_len); i++)
            t[32 + i] = plain[i];
        for (i = 32 + (plain_len); i < (int)(64 + (plain_len)); i++)
            t[i] = x[i - (plain_len)];
        SM3::SM3_HASH(t, 64 + (plain_len), 64 + (plain_len), u, 32, 0);
    }
    else
    {
        for (i = 0; i < 32; i++)
            t[i] = x[i];
        for (i = 0; i < 32; i++)
            t[32 + i] = plain[i];
        SM3::SM3_HASH(t, 64, 64 + (plain_len), u, 32, 1);
        multiple = ((plain_len)-32) / 64;
        remainder = ((plain_len)-32) % 64;
        if (multiple != 0)
            SM3::SM3_HASH(plain + 32, 64 * multiple, 64 + (plain_len), u, 32, 2);
        for (i = 0; i < remainder; i++)
            t[i] = plain[32 + 64 * multiple + i];
        for (i = remainder; i < 32 + remainder; i++)
            t[i] = x[i + 32 - remainder];
        SM3::SM3_HASH(t, 32 + remainder, 64 + (plain_len), u, 32, 3);
    }

    for (i = 0; i < 32; i++)
    {
        if (u[i] != *(cipher + cipher_len - 32 + i))
            return (-1);
    }
    return 0;
}

unsigned char *EccCrypto::Get_rand_sk(Random &r)
{
    mpz_t temp;
    r.get_rand(temp, 256);
    unsigned char *ra = new unsigned char[32];
    char *str = mpz_get_str(nullptr, 2, temp);
    char str_cpy[257];
    memset(str_cpy, 0, 257);
    strcpy(str_cpy, str);
    int idx = 0;
    for (int i = 0; i < 32; ++i)
    {
        int num = 0;
        for (int j = 0; j < 8; ++j)
        {
            if (str_cpy[idx] != 0)
                num = num * 2 + (str_cpy[idx] - '0');
            else
                num = num * 2 + 0;
            idx++;
        }
        ra[i] = num;
    }
    return ra;
}

int Sm2Executor::sm2_keygen(sm2_key &key, Random &r)
{
    unsigned char *pk = new unsigned char[64];
    memset(pk, 0, 64);
    unsigned char *sk = nullptr;
    sk = EccCrypto::Get_rand_sk(r); //生成随机的私钥,占32个字节
    int res = EccCrypto::EccMakeKey(sk, 32, pk, 64, 0);
    if (res != 0)
    {
        printf("密钥生成失败！\n");
        return -1;
    }
    string sk_str = convert_hex(sk, 32);
    string pk_str = convert_hex(pk, 64);
    key.pk = pk_str;
    key.sk = sk_str;
    return 0;
}

int Sm2Executor::sm2_encrypt(const string &m, const string &sm2_pk, string &cipher, Random &r)
{
    int plain_len = m.size(); //明文长度
    // pk = 查询函数(sm2_skey_pk_id);
    unsigned char *conv_pk = nullptr;
    conv_pk = stringtouchexs(sm2_pk);
    unsigned char *conv_m = stringtouc(m);
    unsigned char *ra = Sm2Executor::get_random(r); //生成加密所需的随机数
    // cout << "随机数是：" << convert_hex(ra, 32) << endl;
    unsigned char *cipher_temp = new unsigned char[plain_len + 96];
    memset(cipher_temp, 0, plain_len + 96);
    int res = EccCrypto::EccEncrypt(conv_m, plain_len, ra, 32, conv_pk, 64, cipher_temp, plain_len + 96);
    if (res != 0)
    {
        // printf("加密失败，请重新操作！\n");
        return -1;
    }
    cipher = convert_hex(cipher_temp, plain_len + 96);
    return 0;
}

int Sm2Executor::sm2_decrypt(const string &c, const string &sm2_sk, string &plain)
{
    int cipher_len = c.size() / 2;
    unsigned char *conv_sk;
    conv_sk = stringtouchexs(sm2_sk);
    unsigned char *conv_c = stringtouchexs(c);
    unsigned char *temp_plain = new unsigned char[cipher_len - 96];
    memset(temp_plain, 0, cipher_len - 96);
    int res = EccCrypto::EccDecrypt(conv_c, cipher_len, conv_sk, 32, temp_plain, cipher_len - 96);
    if (res != 0)
    {
        // printf("解密出错，输入的密文可能有误！\n");
        return -1;
    }
    plain = uctostring(temp_plain, cipher_len - 96);
    return 0;
}

int Sm2Executor::sm2_sign(const string &c, const string &sm2_key_sk, string &signature, Random &r)
{
    string digest = c;
    SM3::sm3(digest, digest); //哈希函数的输出固定32字节
    unsigned char *conv_digest = stringtouc(digest);
    unsigned char *conv_sk;
    conv_sk = stringtouchexs(sm2_key_sk);
    unsigned char *ra = Sm2Executor::get_random(r);
    unsigned char *sign = new unsigned char[64];
    memset(sign, 0, 64);
    int res = EccCrypto::EccSign(conv_digest, 32, ra, 32, conv_sk, 32, sign, 64);
    if (res != 0)
    {
        // printf("签名失败，请重试！");
        return -1;
    }
    signature = convert_hex(sign, 64);
    return 0;
}

int Sm2Executor::sm2_verify(const string &mess, const string &sig, const string &sm2_key_pk)
{
    if (sig.length() != 128)
    {
        return -1;
    }
    string digest = mess;
    SM3::sm3(digest, digest);
    unsigned char *conv_pk = nullptr;
    conv_pk = stringtouchexs(sm2_key_pk);
    unsigned char *conv_digest = stringtouc(digest);
    unsigned char *conv_sig = stringtouchexs(sig);
    int res = EccCrypto::EccVerify(conv_digest, 32, conv_pk, 64, conv_sig, 64);
    if (res != 0)
    {
        // printf("不通过验证！\n");
        return -1;
    }
    return 0;
}

/**
 * 通过依赖注入的方式注入一个随机数模块的实例对象，调用r的接口生成一个256位的随机数
 * @param r 随机数模块的一个对象，需要从外界注入
 * @return 返回一个32字节(256位)的随机数
 */
unsigned char *Sm2Executor::get_random(Random &r)
{
    mpz_t temp;
    r.get_rand(temp, 256);
    unsigned char *ra = new unsigned char[32];
    char *str = mpz_get_str(nullptr, 2, temp);
    char str_cpy[257];
    memset(str_cpy, 0, 257);
    strcpy(str_cpy, str);
    int idx = 0;
    for (int i = 0; i < 32; ++i)
    {
        int num = 0;
        for (int j = 0; j < 8; ++j)
        {
            if (str_cpy[idx] != 0)
                num = num * 2 + (str_cpy[idx] - '0');
            else
                num = num * 2 + 0;
            idx++;
        }
        ra[i] = num;
    }
    return ra;
}