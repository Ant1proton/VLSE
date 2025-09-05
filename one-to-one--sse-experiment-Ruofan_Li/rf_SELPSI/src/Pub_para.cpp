#include "Pub_para.h"
#include <sstream> // 添加头文件

Pub_para::Pub_para()
{
    // 十六进制字符串 alpha
    string hex_alpha = "2B5A4188B3E71E91FA83005299AD6128E25DA72288111B7BD95B508B55D0561F";
    string hex_alpha1 ="8C068679351918768066DD1CAB5D8C137CF94279FA1FEDA897BA881BFF12E85B";
    // 十六进制字符串 alpha_inv
    string hex_alpha_inv = "16BDB9ABF33BE48209DDD37974F4B82F34F58F0279095644593DD23766E8A5090F56E1A36535465C2D9589E2CFB60E31BA396C83F86E5DE437EDFBB44DD7EFC2512B5C84811869BEFAE9B50F9F2D7D0AA89E677C67D7245168E5A08BC736486F633C1CFF81ECD89A190D2DF111F105369354B4E5F7F44322CF52E6A0F7C7BB0C4373821CBC76DBE3D2285A1CF4CBFFCA49CCFA87028EDD5B985C13AD0AA42E2ACC9D910C527027B5AF8BF046F7C22BC72390B529F385F659376B5FCEA759A0DD3E9509258476593B4539873AB44FAA9C7289B5D21A67C6B96E04CC0C6BBA69714ACD4937E74FAFAA83386A1CC085F0B5759160404E380D18079626A6CD4BB0636F25E3622C82DE2477DF1C2CED506CF9812AF1292C9EFC708A946FEEDC28291D";
    string hex_alpha_inv1 ="E57ACCA69F435DEF9ED703FADF51782F9CC2E32EABF1BD86DC20C94BB05802FA40D5E2DD2BEC8E1B840C51EB7B0FF3E94E6F35DA266B02E80509534343E65F7C8A4A9E62149533A179972CE07B30C5882E81E913FE753A1CD98EB80D405E963759B1BFDBF5E46CCE5004A99724214EC776CCB97C4E725A6C2F41093B49086F3D4ADB3E34D2D694B3CC08679809E607AEC4BB40B12093A77452A5872CB133DC27B5C2CC9850F0FEC7499E9711CFB37D5EB505B70D57FA9866C93A82146B83E5906DF9FBBEBADE9ADBD9CA5A03CFCE15F8C828F2B8AE1A1E710B4161BB015E7AF68625B6484351522DFF1CDDEE55C839F6A93EF3C8E90CCED56644D4D2D102C44B3B6CF8321D02AA5BF6BA00C497E57599B5884A7D34A4E55D4C39C3538DD1E9A3";
     // 将十六进制字符串 alpha 转换为 ZZ
       // 将十六进制字符串 alpha1 转换为 ZZ
       alpha1 = ZZ(0); // 初始化为 0
       for (char c : hex_alpha1)
       {
           alpha1 *= 16; // 左移 4 位（乘以 16）
           if (c >= '0' && c <= '9')
               alpha1 += c - '0';
           else if (c >= 'A' && c <= 'F')
               alpha1 += c - 'A' + 10;
           else if (c >= 'a' && c <= 'f')
               alpha1 += c - 'a' + 10;
           else
           {
               cout << "错误：无效的十六进制字符 " << c << endl;
               exit(1);
           }
       }
       //cout << "alpha1 = " << alpha1 << endl; // 输出 alpha1 的值，验证是否正确
   
       // 将十六进制字符串 alpha_inv1 转换为 ZZ
       alpha_inv1 = ZZ(0); // 初始化为 0
       for (char c : hex_alpha_inv1)
       {
           alpha_inv1 *= 16; // 左移 4 位（乘以 16）
           if (c >= '0' && c <= '9')
               alpha_inv1 += c - '0';
           else if (c >= 'A' && c <= 'F')
               alpha_inv1 += c - 'A' + 10;
           else if (c >= 'a' && c <= 'f')
               alpha_inv1 += c - 'a' + 10;
           else
           {
               cout << "错误：无效的十六进制字符 " << c << endl;
               exit(1);
           }
       }

    alpha = ZZ(0); // 初始化为 0
    for (char c : hex_alpha)
    {
        alpha *= 16; // 左移 4 位（乘以 16）
        if (c >= '0' && c <= '9')
            alpha += c - '0';
        else if (c >= 'A' && c <= 'F')
            alpha += c - 'A' + 10;
        else if (c >= 'a' && c <= 'f')
            alpha += c - 'a' + 10;
        else
        {
            cout << "错误：无效的十六进制字符 " << c << endl;
            exit(1);
        }
    }

    // 将十六进制字符串 alpha_inv 转换为 ZZ
    alpha_inv = ZZ(0); // 初始化为 0
    for (char c : hex_alpha_inv)
    {
        alpha_inv *= 16; // 左移 4 位（乘以 16）
        if (c >= '0' && c <= '9')
            alpha_inv += c - '0';
        else if (c >= 'A' && c <= 'F')
            alpha_inv += c - 'A' + 10;
        else if (c >= 'a' && c <= 'f')
            alpha_inv += c - 'a' + 10;
        else
        {
            cout << "错误：无效的十六进制字符 " << c << endl;
            exit(1);
        }
    }


    // 十六进制字符串 beta
    string hex_beta = "AE72C0F91B796BB458FFCE2CF5A53B485D16ABD7E1C97A0E89376E3C9E8C077F";
    string hex_beta1 = "152795D1898665178EA6B6B112FED09626B9726D22F33658D779315E54614283";
    // 十六进制字符串
    string hex_N = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

// 将十六进制字符串 beta1 转换为 ZZ
beta1 = ZZ(0); // 初始化为 0
for (char c : hex_beta1)
{
    beta1 *= 16; // 左移 4 位（乘以 16）
    if (c >= '0' && c <= '9')
        beta1 += c - '0';
    else if (c >= 'A' && c <= 'F')
        beta1 += c - 'A' + 10;
    else if (c >= 'a' && c <= 'f')
        beta1 += c - 'a' + 10;
    else
    {
        cout << "错误：无效的十六进制字符 " << c << endl;
        exit(1);
    }
}

    // 将十六进制字符串转换为 ZZ
    N = ZZ(0); // 初始化为 0
    for (char c : hex_N)
    {
        N *= 16; // 左移 4 位（乘以 16）
        if (c >= '0' && c <= '9')
            N += c - '0';
        else if (c >= 'A' && c <= 'F')
            N += c - 'A' + 10;
        else if (c >= 'a' && c <= 'f')
            N += c - 'a' + 10;
        else
        {
            cout << "错误：无效的十六进制字符 " << c << endl;
            exit(1);
        }
    }

    //cout << "N = " << N << endl; // 输出 N 的值，验证是否正确

    // 将十六进制字符串转换为 ZZ
    beta = ZZ(0); // 初始化为 0
    for (char c : hex_beta)
    {
        beta *= 16; // 左移 4 位（乘以 16）
        if (c >= '0' && c <= '9')
            beta += c - '0';
        else if (c >= 'A' && c <= 'F')
            beta += c - 'A' + 10;
        else if (c >= 'a' && c <= 'f')
            beta += c - 'a' + 10;
        else
        {
            cout << "错误：无效的十六进制字符 " << c << endl;
            exit(1);
        }
    }
    //cout << "beta = " << beta << endl; // 输出 beta 的值，验证是否正确
    SecByteBlock siphash_key((byte *)"123456123456123", KEY_LEN);
    siphash.SetKey(siphash_key, KEY_LEN);

    for (int i = 0; i < NUM_OF_CUCKOO_HASH; i++)
    {
        SipHash<2, 4, true> h;
        siphash_key[1] = (i + '0') % 128;
        h.SetKey(siphash_key, KEY_LEN);

        hash_list.push_back(h);
    }
    //cout << "初始化结束时beta = " << beta << endl; // 输出 beta 的值，验证是否正确

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
