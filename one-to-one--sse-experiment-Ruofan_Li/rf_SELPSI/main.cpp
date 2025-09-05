#include "util.h"
#include "Pub_para.h"
#include "database.h"
#include <sys/stat.h> // 添加头文件
#include <chrono> // 添加头文件
#include <cryptlib.h>
#include <osrng.h> // 包含 AutoSeededRandomPool 的头文件
#include <random> // 用于随机数生成
#include <sha.h>
#include <secblock.h>
#include <iomanip> // 用于格式化输出


using namespace std;
using namespace NTL;
using namespace CryptoPP;
//运行代码：到build文件路径下面先:cmake.
// 然后：make
// 然后：./main

const static int KEY_LEN = 16;//对称加密的密文长度16*8=128
const static int MAX_BINS_SIZE = (int)(131072/2/2/2*1.5);
const static int MAX_RELOCATIONS = 1500; // 最大重定位次数
const static int SEARCH_KEYWORDS_NUM = 40; // 设置查询关键词数量，增加到40以支持更多检查点
const static int MAX_LABEL_NUM = 1; // 数据集中每个ID最多可能有的标签数量
const static string DATASET_PATH = "/Users/chenyuwei/Desktop/one-to-one--sse-experiment-Ruofan_Li/rf_SELPSI/data/data14_20";
Vec<ZZ> cuckoo_bins;     //布谷鸟哈希桶
bool vis[MAX_BINS_SIZE]; //判定哈希桶当中是否有元素
Pub_para PUB_PARA;

// 函数声明
map<string, vector<string>> LimitLabelsPerKeyword(const map<string, vector<string>>& original_db, int max_labels);

size_t GetZZSize(const ZZ& value) {
   return NumBytes(value); // 返回 `ZZ` 类型的实际字节数
}

ZZ GetHashedZZFromString(string search_word) {
    SHA256 hash;
    SecByteBlock digest(SHA256::DIGESTSIZE);
    hash.Update((byte*)search_word.data(), search_word.size());
    hash.Final(digest);

    return ZZFromBytes(digest, digest.size()) % PUB_PARA.N;
}


// 在 main 函数前添加
vector<string> GetRandomKeywords(const string& file_path, int num_keywords) {
    map<string, vector<string>> inverted_DB = DB_build_by_inverted(file_path);
    vector<string> all_keywords;
    
    // 收集所有关键词
    for (const auto& pair : inverted_DB) {
        all_keywords.push_back(pair.first);
    }
    
    // 随机打乱关键词
    random_device rd;
    mt19937 gen(rd());
    shuffle(all_keywords.begin(), all_keywords.end(), gen);
    
    // 选择指定数量的关键词
    vector<string> selected_keywords;
    for (int i = 0; i < min(num_keywords, (int)all_keywords.size()); i++) {
        selected_keywords.push_back(all_keywords[i]);
    }
    
    return selected_keywords;
}
ZZ Get_search_token_from_string2(string search_word, ZZ alpha) {
    ZZ hashed_ZZ = GetHashedZZFromString(search_word);  // 用 SHA256 代替 SipHash
    ZZ search_token = PowerMod(hashed_ZZ, alpha, PUB_PARA.N);
    return search_token;
}

ZZ Get_sym_key_from_string2(string search_word, ZZ beta) {
    ZZ hashed_ZZ = GetHashedZZFromString(search_word);  // 用 SHA256 代替 SipHash
    ZZ sym_key = PowerMod(hashed_ZZ, beta, PUB_PARA.N);
    return sym_key;
}


ZZ Get_sym_key_from_string(string search_word, ZZ beta) {
    SecByteBlock hashed_search_word_byte(KEY_LEN);
    SecByteBlock search_word_byte((byte *)search_word.c_str(), search_word.size());

    // 重新构建一个新的SipHash对象，避免状态污染问题
    SecByteBlock siphash_key((byte *)"123456123456123", KEY_LEN);
    SipHash<2, 4, true> siphash(siphash_key, KEY_LEN);

    siphash.Update(search_word_byte, search_word_byte.size());
    siphash.Final(hashed_search_word_byte);

    ZZ hashed_search_word_ZZ(ZZFromBytes(hashed_search_word_byte, hashed_search_word_byte.size()) % PUB_PARA.N);
    ZZ sym_key = PowerMod(hashed_search_word_ZZ, beta, PUB_PARA.N);
    return sym_key;
}

ZZ Get_search_token_from_string(string search_word, ZZ alpha) {
    SecByteBlock hashed_search_word_byte(KEY_LEN);
    SecByteBlock search_word_byte((byte *)search_word.c_str(), search_word.size());

    // 重新构建一个新的SipHash对象，避免状态污染问题
    SecByteBlock siphash_key((byte *)"123456123456123", KEY_LEN);
    SipHash<2, 4, true> siphash(siphash_key, KEY_LEN);

    siphash.Update(search_word_byte, search_word_byte.size());
    siphash.Final(hashed_search_word_byte);

    ZZ hashed_search_word_ZZ(ZZFromBytes(hashed_search_word_byte, hashed_search_word_byte.size()) % PUB_PARA.N);
    ZZ search_token = PowerMod(hashed_search_word_ZZ, alpha, PUB_PARA.N);
    return search_token;
}


ZZ Get_search_token_from_string1(ZZ search_word_ZZ, ZZ alpha)
{
   // 关键字哈希值的 alpha 次幂
   ZZ search_token=(PowerMod(search_word_ZZ, alpha, PUB_PARA.N));
   return search_token;
}

ZZ Get_sym_key_from_string1(ZZ search_word_ZZ, ZZ beta)
{
   
   ZZ sym_key=(PowerMod(search_word_ZZ, beta, PUB_PARA.N));
   return sym_key;
}

void Gene_encrypted_data(string file_path, int labels_per_id)
{
    cout << endl;
    cout << "------------------加密数据开始----------------" << endl;
    cout << "读取文件：" << file_path << endl;
    cout << "每个ID的标签数量限制：" << labels_per_id << endl;
    
    // 先读取完整数据库
    map<string, vector<string>> full_inverted_DB = DB_build_by_inverted(file_path);
    
    // 限制每个ID的标签数量
    map<string, vector<string>> inverted_DB = LimitLabelsPerKeyword(full_inverted_DB, labels_per_id);
    
    ofstream outfile("../data/erypted_data.txt");
    if (!outfile.is_open())
    {
        cout << "error" << endl;
        return;
    }
    cout << "文件读取完成，生成加密数据库当中..." << endl;

    int DB_size = inverted_DB.size();
    int cur = 0;


    for (auto each : inverted_DB)
    {
        // 调用函数时传递 PUB_PARA.alpha 和 PUB_PARA.beta
        ZZ token = Get_search_token_from_string2(each.first, PUB_PARA.beta);
        //cout<<"server token: " << token << endl;
        //cout << "token size: " << GetZZSize(token) << endl;
        ZZ sym_key = Get_sym_key_from_string2(each.first, PUB_PARA.beta1);
        //cout<<"server sym_key: " << sym_key << endl;
        outfile << token;

        // 用关键字哈希值的 beta 次幂生成 aes 加解密密钥
        SecByteBlock aesKey(KEY_LEN);
        BytesFromZZ(aesKey, sym_key, KEY_LEN);

        for (auto label_str : each.second)
        {
            // 加密每一个关键字对应的 label
            trim(label_str);
            erasePending(label_str);
            SecByteBlock label((byte *)label_str.c_str(), label_str.size());
            SecByteBlock label_enc = PUB_PARA.aes_Enc(aesKey, label);
            

            outfile << "\t";
            // 注意，SecByteBlock 一定要转换为 ZZ 然后再存储
            ZZ label_enc_ZZ = ZZFromBytes(label_enc, label_enc.size());
           // cout << "label size: " << GetZZSize(label_enc_ZZ) << endl;
            outfile << label_enc_ZZ;
        }
        outfile << "\n";
        printf("\033[32m%.2lf%%\r\033[0m", (++cur) * 100.0 / DB_size);
    }
    cout << endl;
    outfile.close();
    cout << "加密数据库生成完成，文件存放于\"../data/erypted_data.txt\"" << endl;
}

// token的第k个哈希值在布谷鸟哈希桶当中的位置
int Get_hash_position(ZZ token, int k)
{
   if (k >= PUB_PARA.NUM_OF_CUCKOO_HASH || k < 0)
   {
      cout << "k is out of range" << endl;
      return -1;
   }
   SecByteBlock temp(KEY_LEN);
   BytesFromZZ(temp, token, KEY_LEN);
   PUB_PARA.hash_list[k].Update(temp, temp.size());
   SecByteBlock hashcode(KEY_LEN);
   PUB_PARA.hash_list[k].Final(hashcode);

   ZZ pos;
   pos = ZZFromBytes(hashcode, hashcode.size()) % ZZ(MAX_BINS_SIZE);

   return to_int(pos);
}

bool Cuckoo_hash(ZZ target) {
    for (int relocation_count = 0; relocation_count < MAX_RELOCATIONS; ++relocation_count) {
        for (int i = 0; i < PUB_PARA.NUM_OF_CUCKOO_HASH; ++i) {
            int pos = Get_hash_position(target, i);
            if (!vis[pos]) {
                vis[pos] = true;
                cuckoo_bins[pos] = target;
                return true; // 插入成功
            }
        }

        // 如果当前位置被占用，则踢出当前元素并重新插入
        int pos = Get_hash_position(target, rand() % PUB_PARA.NUM_OF_CUCKOO_HASH);
        swap(target, cuckoo_bins[pos]);
    }

    // 如果到达这里，说明插入失败
    cout << "警告: 布谷鸟哈希失败，无法插入 " << target << endl;
    return false;
}

SecByteBlock GenerateRandomBlock(size_t size) {
    SecByteBlock block(size);
    AutoSeededRandomPool rng; // 使用 Crypto++ 的随机数生成器
    rng.GenerateBlock(block, size);
    return block;
}

void FillEmptyCuckooHashSlots(size_t label_size, map<ZZ, Vec<ZZ>>& encrypted_data) {
    for (int i = 0; i < MAX_BINS_SIZE; ++i) {
        if (!vis[i]) {
            // 生成随机数据填充空余位置
            SecByteBlock random_data = GenerateRandomBlock(label_size);
            ZZ random_data_ZZ = ZZFromBytes(random_data, random_data.size());
            cuckoo_bins[i] = random_data_ZZ;
            vis[i] = true;

            // 生成对应的随机标签并添加到 encrypted_data 中
            Vec<ZZ> temp_vec;
            for (int j = 0; j < 1; // 为每个随机串生成 1 个随机标签密文
            ++j) {
                SecByteBlock random_label = GenerateRandomBlock(label_size);
                temp_vec.append(ZZFromBytes(random_label, random_label.size()));
            }
            encrypted_data[random_data_ZZ] = temp_vec;
        }
    }
}

void DebugCuckooHash(const map<ZZ, Vec<ZZ>>& encrypted_data) {
    cout << "布谷鸟哈希桶状态：" << endl;
    for (int i = 0; i < MAX_BINS_SIZE; ++i) {
        if (vis[i]) {
            cout << "桶[" << i << "] = " << cuckoo_bins[i] << endl;
        } else {
            cout << "桶[" << i << "] = 空" << endl;
        }
    }

    cout << "加密数据映射表：" << endl;
    for (const auto& pair : encrypted_data) {
        cout << "Token: " << pair.first << " -> Labels: ";
        for (const auto& label : pair.second) {
            cout << label << " ";
        }
        cout << endl;
    }
}

map<ZZ, Vec<ZZ>> Read_EDB_file(string file_path)
{
   cout << endl;
   cout << "------------读取加密数据库-------------" << endl;
   ifstream infile(file_path);
   cout << "读取文件：" << file_path << endl;
   map<ZZ, Vec<ZZ>> encrypted_data;
   if (!infile.is_open())
   {
      cout << "文件\"" << file_path << "\"打开失败" << endl;
      return encrypted_data;
   }

   //先构建映射表存储加密过后的数据

   cout << "构建映射表..." << endl;
   string str;
   while (getline(infile, str))
   {
      vector<string> each_line = split(str, "\t");
      ZZ token;
      conv(token, each_line[0].c_str());

      Vec<ZZ> temp;
      for (int i = 1; i < each_line.size(); i++)
      {
         temp.append(to_ZZ(each_line[i].c_str()));
      }

      encrypted_data[token] = temp;
   }
   cout << "文件读入完成，映射表已构建" << endl;
   cout << "-----------------------------------" << endl;
   cout << endl;
   return encrypted_data;
}

// 限制每个ID的标签数量
map<string, vector<string>> LimitLabelsPerKeyword(const map<string, vector<string>>& original_db, int max_labels) {
    map<string, vector<string>> limited_db;
    
    for (const auto& entry : original_db) {
        vector<string> limited_labels;
        // 只保留指定数量的标签
        for (int i = 0; i < min(max_labels, (int)entry.second.size()); i++) {
            limited_labels.push_back(entry.second[i]);
        }
        limited_db[entry.first] = limited_labels;
    }
    
    return limited_db;
}

// 执行单次测试
void RunTest(int labels_per_id) {
    cout << "\n\n====================================================" << endl;
    cout << "开始测试每个ID包含 " << labels_per_id << " 个标签的情况" << endl;
    cout << "====================================================" << endl;
    
    // 重置布谷鸟哈希相关的数据结构
    cuckoo_bins.SetLength(MAX_BINS_SIZE); // 设置哈希桶长度
    fill(vis, vis + MAX_BINS_SIZE, 0);    // 初始化哈希桶为空
    
    auto start_time1 = chrono::high_resolution_clock::now(); // 开始计时
    Gene_encrypted_data(DATASET_PATH, labels_per_id);
    auto end_time1 = chrono::high_resolution_clock::now(); // 结束计时
    double elapsed_time1 = chrono::duration_cast<chrono::microseconds>(end_time1 - start_time1).count();
    cout << "密文集合生成时间：" << fixed << setprecision(3) << elapsed_time1/ 1000.0 << " 毫秒" << endl; // 输出毫秒单位
    
    // 读取数据，并且将数据映射到布谷鸟哈希桶当中
    map<ZZ, Vec<ZZ>> encrypted_data = Read_EDB_file("../data/erypted_data.txt");
    
    size_t search_token_bit_size = 0; 
    // 把 token 映射到哈希桶当中
    for (auto each_data : encrypted_data) {
        if (!Cuckoo_hash(each_data.first)) {
            cout << "错误: 无法插入 token " << each_data.first << endl;
        }
    }

    // 查询功能
    vector<string> search_keywords = GetRandomKeywords(DATASET_PATH, SEARCH_KEYWORDS_NUM);

    cout << "\n开始查询 " << SEARCH_KEYWORDS_NUM << " 个随机关键词...\n" << endl;
    
    double total_search_time = 0.0;
    int found_count = 0;
    vector<double> checkpoint_times = {0, 0, 0, 0, 0}; // 存储 1, 10, 20, 30, 40 个关键词的总耗时
    
    for (int i = 0; i < search_keywords.size(); i++) {
        //cout << "\n查询第 " << (i+1) << " 个关键词: " << search_keywords[i] << endl;

        auto start_time = chrono::high_resolution_clock::now(); // 开始计时

        // 生成查询 token 和对称密钥
        ZZ search_token = Get_search_token_from_string2(search_keywords[i], PUB_PARA.alpha);
        search_token = Get_search_token_from_string1(search_token, PUB_PARA.beta);
        search_token = Get_search_token_from_string1(search_token, PUB_PARA.alpha_inv);
       // cout<<"search_token: " << search_token << endl;
        // 计算 search_token 的位数
        search_token_bit_size = NumBits(search_token);
        ZZ sym_key = Get_sym_key_from_string2(search_keywords[i], PUB_PARA.alpha1);
       // cout << "Step 1 (query): sym_key after alpha1 = " << sym_key << endl;

        sym_key = Get_sym_key_from_string1(sym_key, PUB_PARA.beta1);
       // cout << "Step 2 (query): sym_key after beta1 = " << sym_key << endl;

        sym_key = Get_sym_key_from_string1(sym_key, PUB_PARA.alpha_inv1);
        //cout << "Step 3 (query): sym_key after alpha_inv1 = " << sym_key << endl;
        vector<SecByteBlock> labels; // 存储解密后的标签
        bool found = false;

        // 在布谷鸟哈希表中查找 token
        for (int i = 0; i < PUB_PARA.NUM_OF_CUCKOO_HASH; i++) {
            int pos = Get_hash_position(search_token, i);

            if (cuckoo_bins[pos] == search_token) {
                found = true;
                found_count++;

                // 获取对应的标签密文
                Vec<ZZ> encrypted_labels = encrypted_data[search_token];
                for (ZZ each : encrypted_labels) {
                    // 解密标签密文
                    SecByteBlock temp(KEY_LEN);
                    BytesFromZZ(temp, each, temp.size());

                    SecByteBlock sym_key_byte(KEY_LEN);
                    BytesFromZZ(sym_key_byte, sym_key, sym_key_byte.size());
                    temp = PUB_PARA.aes_Dec(sym_key_byte, temp);
                    labels.push_back(temp);
                }
                break;
            }
        }

        auto end_time = chrono::high_resolution_clock::now(); // 结束计时
        double elapsed_time = chrono::duration_cast<chrono::microseconds>(end_time - start_time).count() / 1000.0;
        total_search_time += elapsed_time;
        
        // 输出查询结果
        if (found) {
            //cout << "\033[32m查询成功，找到 " << labels.size() << " 个标签。\033[0m" << endl;
        } else {
            cout << "未找到关键字对应的标签。" << endl;
        }

        // 记录特定关键词数量的查询时间
        if (i == 0) checkpoint_times[0] = total_search_time;  // 1个关键词
        if (i == 9) checkpoint_times[1] = total_search_time;  // 10个关键词
        if (i == 19) checkpoint_times[2] = total_search_time; // 20个关键词
        if (i == 29) checkpoint_times[3] = total_search_time; // 30个关键词
        if (i == 39) checkpoint_times[4] = total_search_time; // 40个关键词
    }
    
    // 输出特定关键词数量的查询总耗时
    cout << "\n不同关键词数量的查询总耗时:" << endl;
    cout << "1个关键词: " << fixed << setprecision(3) << checkpoint_times[0] << " 毫秒" << endl;
    cout << "10个关键词: " << fixed << setprecision(3) << checkpoint_times[1] << " 毫秒" << endl;
    cout << "20个关键词: " << fixed << setprecision(3) << checkpoint_times[2] << " 毫秒" << endl;
    cout << "30个关键词: " << fixed << setprecision(3) << checkpoint_times[3] << " 毫秒" << endl;
    cout << "40个关键词: " << fixed << setprecision(3) << checkpoint_times[4] << " 毫秒" << endl;

    // 转换为 MB 并输出
    double cuckoo_size_in_mb = (search_token_bit_size * MAX_BINS_SIZE) / (8.0 * 1024.0 * 1024.0); // 位数转字节再转 MB
    double label_size_in_mb = KEY_LEN * labels_per_id * MAX_BINS_SIZE / (1024.0 * 1024.0);
    double total_size_in_mb = cuckoo_size_in_mb + label_size_in_mb;
    
    cout << "\n密文集合大小统计:" << endl;
    cout << "每个ID的标签数: " << labels_per_id << endl;
    cout << "布谷鸟哈希桶大小：" << MAX_BINS_SIZE << endl;
    cout << "布谷鸟哈希部分大小：" << fixed << setprecision(2) << cuckoo_size_in_mb << " MB" << endl;
    cout << "标签部分大小：" << fixed << setprecision(2) << label_size_in_mb << " MB" << endl;
    cout << "密文集合总大小：" << fixed << setprecision(2) << total_size_in_mb << " MB" << endl;

    // 输出统计信息
    cout << "\n查询统计:" << endl;
    cout << "总查询时间: " << fixed << setprecision(3) << total_search_time << " 毫秒" << endl;
    cout << "平均查询时间: " << fixed << setprecision(3) << total_search_time / SEARCH_KEYWORDS_NUM << " 毫秒" << endl;
    cout << "查询成功率: " << fixed << setprecision(2) << (found_count * 100.0 / SEARCH_KEYWORDS_NUM) << "%" << endl;
}

int main() {
    PUB_PARA.beta = conv<ZZ>("47676318137538369727214414118984042636057735934898873328264027803085274899392");
    PUB_PARA.beta1 = conv<ZZ>("20984771316314472289297972305987079205225297921858495109350827762359756644626");
    PUB_PARA.alpha1 = conv<ZZ>("89937141617663735915351339569653166415837297575408018408051320513022216101007");
    PUB_PARA.alpha_inv1 = conv<ZZ>("2663012280045998906000749410424301594809233938858588550332869340082756287006866475251380684642023807568253026783973621913560108807413193673328824310421020432316535350291422330005944459366059771402739858699138105448843213408431934768883955585033227681328567017629268134475144828436062106837095794691892006449645164145244841591539943919722960303328334775873927934259824161503769685911574463637879444801025830073960113675372102237399827153191607913650080935749590900110104162919121708798644807375081624566713038046968218887414954876974537616188884273281322171256130377435809250593004343701611249860934986236335825017139725656659629120511651595891869264769867403673036406206109301609209743031336408322253023228788949327372282382041890298951180857166664048700540240649894261086482949548234207496172577756742003729482831245357203260831467179197836230252890146198289394038172621120465137046493665790287133094771415689973061474709879");
    PUB_PARA.alpha = conv<ZZ>("56899084826686085705689450652576527896920957644206970942974318929903760835733");
    PUB_PARA.alpha_inv = conv<ZZ>("1980442776286556236868470568034035227390070169148065051468423986682902927732307225013380072587769611290541886840925494109500589317435480314150259945975049322198379252091570033040628396962294234744262068873992785787920890396938063122075326264923741605460665154898220886087747691680843643023543265741179215649325076824207742431207524163408417716978332938904224428554169748192186870633656097681735905162898430766138755710693760984144253001850347210813650751351849424070674904473129363413782507823006445997846946028113154785182559871195705063748689782995072573873124715636602275856507399677009302339409380736311535985059132464359676035416386682357119915766734267591949337060493008276592734564807444334437925203718558149459510581596969498003090206306743082745038861884986370719825192946088178472427239908908649837631810308786380252337980820009747711501665282352445068043294314860890017215335688213927510811370572018531697860581549");
    PUB_PARA.N = conv<ZZ>("4294583258558056192923703766393959116688381789171653365953160993564471860979820850238493242175677808382399806630093888465939485882664537648621736064645259930756623911730863386933107195488830006538624232730782748458029309749374825553737211455997084185753848758816963331338844629629248219697315241640404373168471968456184728902336482116647651129409335745145337167109401240130153808406744468167592320112109395492847321216653366179244117543266780884400550644321334482636804271333331035019915613952605420878706747165084475456389940555001692984535228337794856717018136573792036252672265775180225934685847881326988749037286611427141641025206878963987999654442968352964593869784352330104497594353434138689574727623224199005565895856552579945338751230570853251552237712548584028290825892265479837724351707251592932053811329283984624939044934280643377406250785790984182091428701411147442624917636568645208390917798558884307099500857911");

    //cout << "请输入最大标签数量: ";
    int max_labels;
    //cin >> max_labels;
    //max_labels = min(max_labels, MAX_LABEL_NUM); // 确保不超过最大值
    max_labels = MAX_LABEL_NUM;
    
    // 测试不同标签数量的情况
    vector<int> label_counts = {1, 5, 10, 15, 20};
    
    for (int labels : label_counts) {
        // 只测试不超过指定最大值的标签数
        if (labels <= max_labels) {
            RunTest(labels);
        }
    }

    cout << "\n所有测试完成！" << endl;
    return 0;
}