#include "Pub_para.h"
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <stdexcept>
#include <iostream>
using namespace NTL;
using namespace CryptoPP;
using namespace std;

// —— 工具函数实现，与头文件声明一致 ——
ZZ Pub_para::HexToZZ(const std::string& hex) {
    ZZ z(0);
    for (char c : hex) {
        z *= 16;
        if (c >= '0' && c <= '9') z += (c - '0');
        else if (c >= 'A' && c <= 'F') z += (c - 'A' + 10);
        else if (c >= 'a' && c <= 'f') z += (c - 'a' + 10);
        else /* 忽略空白 */ ;
    }
    return z;
}

bool Pub_para::InSubgroup(const ZZ& X, const ZZ& p, const ZZ& q) {
    if (X <= 1 || X >= p-1) return false;
    return (PowerMod(X, q, p) == 1);  // X^q ≡ 1 (mod p)
}

Pub_para::Pub_para() {
    // 不做任何与群参数相关的计算，避免重复与性能浪费
    // 仅初始化 SipHash 哈希实例列表（如果项目仍然使用）
    hash_list.clear();
    SecByteBlock siphash_key((byte*)"123456123456123", KEY_LEN);
    siphash.SetKey(siphash_key, KEY_LEN);
    for (int i = 0; i < NUM_OF_CUCKOO_HASH; ++i) {
        SipHash<2,4,true> h;
        siphash_key[1] = (i + '0') & 0x7F;
        h.SetKey(siphash_key, KEY_LEN);
        hash_list.push_back(h);
    }
    // 提示：真正的群参数会在 main() 中被硬编码覆盖
#ifdef DEBUG
    cout << "[Pub_para] 构造完成（已精简，无DH参数生成）。等待 main() 设置 N / alpha / beta 等。" << endl;
#endif
}


SecByteBlock Pub_para::aes_Enc(const SecByteBlock &aesKey, const SecByteBlock &inBlock)
{
    SecByteBlock outBlock(AES::BLOCKSIZE);
    SecByteBlock temp(inBlock, KEY_LEN);
    if (aesKey.size() > 16)
    {
        cout << "aes加密密钥过大" << endl;   
        return outBlock;
    }
    if (inBlock.size() > 16)
    {
        cout << "\033[33m警告：aes加密数据过大  --->   ";

        for (auto each : inBlock)
        {
            cout << each;
        }
        cout << "\033[0m";
        cout << endl;
    }

    SecByteBlock xorBlock(AES::BLOCKSIZE);
    memset(xorBlock, 0, AES::BLOCKSIZE); //置零

    aesEncryptor.SetKey(aesKey, AES::DEFAULT_KEYLENGTH);
    aesEncryptor.ProcessAndXorBlock(temp, xorBlock, outBlock); //加密
    return outBlock;
}

SecByteBlock Pub_para::aes_Dec(const SecByteBlock &aesKey, const SecByteBlock &outBlock)
{
    SecByteBlock inBlock(AES::BLOCKSIZE);
    if (aesKey.size() > 16)
    {
        cout << "aes解密密钥过大" << endl;
        return inBlock;
    }
    if (outBlock.size() > 16)
    {
        cout << "aes解密数据过大" << endl;
        return inBlock;
    }
    SecByteBlock xorBlock(AES::BLOCKSIZE);
    memset(xorBlock, 0, AES::BLOCKSIZE); //置零
    aesDecryptor.SetKey(aesKey, AES::DEFAULT_KEYLENGTH);
    aesDecryptor.ProcessAndXorBlock(outBlock, xorBlock, inBlock);
    return inBlock;
}
