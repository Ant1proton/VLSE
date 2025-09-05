#include "ASES22.h"

ASES22::ASES22() : bcp(security_para)
{
    Setup();
}

void ASES22::Setup()
{
    ZZ N;
    N = bcp.get_modulus();
    p = GenPrime_ZZ(security_para);
    while (p > N)
    {
        p = GenPrime_ZZ(security_para);
    }
}

Mat<ZZ_Cipher> ASES22::Index_I_Gen(string path)
{
    Mat<ZZ_Cipher> res; //存放结果的矩阵
    int L = 0;
    map<string, vector<string>> invert_DB = DB_build_by_inverted(path);
    vector<string> words; // words用来存放关键字

    //首先找到所有关键字中包含文件个数的最大值L
    for (map<string, vector<string>>::iterator it = invert_DB.begin(); it != invert_DB.end(); it++)
    {
        words.push_back(it->first);
        if (L < it->second.size())
            L = it->second.size();
    }

    //初始化结果矩阵的大小
    res.SetDims(words.size(), L + 1);

    //利用拉格朗日插值法生成多项式，根据NTL库中的interpolate函数生成

    ZZ_pPush Push(p); //根据论文的描述，全集U属于域Z_N

    int row = 0;
    for (auto it : invert_DB)
    {
        Vec<ZZ_p> Vec_a, Vec_b;

        //生成<a,b>对
        //前 DB(w) 个<a,b>对都是<id,0>的模式
        for (auto each : it.second)
        {
            ZZ_p temp;
            //需要将string类型转换为ZZ_p类型
            //这里需要对字符串进行处理，判断字符的范围是否在0到9之间

            int pos = 0;
            int len = each.size();
            while (pos < len)
            {
                if (len == 0)
                    break;
                if (!(each[pos] >= '0' && each[pos] <= '9'))
                {
                    each.erase(pos, 1);
                    len--;
                }
                else
                {
                    pos++;
                }
            }

            //如果这个字符串是一个“无效字符串”，即所有的字符都不在0到9之间，
            //或者是一个空字符串，那么视为id=0
            //理论上不应出现这种情形
            if (len == 0)
                conv(temp, 0);
            else
                conv(temp, each.c_str());

            Vec_a.append(temp);
            Vec_b.append(ZZ_p(0));
        }
        //这里需要额外生成一个<a,b>对，以满足拉格朗日插值法的要求
        //随机生成一个值作为a，使得多项式的结果b不为0
        ZZ_p temp_a;
        ZZ_p temp_b;
        do
        {
            temp_a = random_ZZ_p();
            temp_b = 1;
            for (auto each_a : Vec_a)
            {
                temp_b *= (temp_a - each_a);
            }
        } while (temp_b == 0);
        Vec_a.append(temp_a);
        Vec_b.append(temp_b);

        ZZ_pX poly;
        interpolate(poly, Vec_a, Vec_b);
        assert(it.second.size() == deg(poly)); //每一个关键字对应的id数目一定是多项式的次数

        ZZ_pX temp_pX;
        SetCoeff(temp_pX, L - it.second.size(), 1);

        poly = poly * temp_pX;

        assert(deg(poly) == L); //此时的多项式的次数必然等于L

        //接下来加密多项式系数，结果存放在矩阵res当中
        for (int degree = 0; degree <= L; degree++)
        {
            ZZ_Cipher cipher = bcp.Enc(rep(coeff(poly, degree)));
            res[row][degree] = cipher;
        }
        printf("row = %d complete\n", row);
        row++; //每次算出一整行之后行加1
    }
    printf("共计%d行, 已完成\n", words.size());

    cout << res.NumRows() << endl;
    cout << res.NumCols() << endl;

    this->words = words;
    return res;
}

Vec<ZZ_Cipher> ASES22::TGen(vector<string> queries)
{
    //将要查询的关键字收录到一个集合当中，这样能够加快查找对应元素的速度
    unordered_set<string> queries_set;
    for (auto query : queries)
    {
        queries_set.insert(query);
    }
    //遍历全部关键字，如果某一个关键字在需要查询的集合中，那么加密一个随机数r到陷门当中，
    //如果某一个关键字不在需要查询的集合中，加密0到陷门当中
    Vec<ZZ_Cipher> res;
    for (auto word : words)
    {
        ZZ r;
        if (queries_set.count(word))
        {
            r = RandomBnd(p);
        }
        else
        {
            r = 0;
        }
        res.append(bcp.Enc(r));
    }
    return res;
}

Vec<ZZ_Cipher> ASES22::Search(const Vec<ZZ_Cipher> &Tr, const Mat<ZZ_Cipher> &index_I)
{
    int num_rows = index_I.NumRows();
    int num_cols = index_I.NumCols();

    Mat<ZZ_Cipher> res_mat;                  //暂时存放结果矩阵
    res_mat.SetDims(num_rows, 2 * num_cols); //注意在与一个L阶多项式相乘之后，阶数应为2*L

    assert(Tr.length() == index_I.NumRows());

    //遍历陷门
    for (int row = 0; row < num_rows; row++)
    {
        Vec<ZZ_Cipher> poly;
        //每一个关键字对应的陷门点乘对应的多项式
        for (int col = 0; col < num_cols; col++)
        {
            poly.append(bcp.homo_mul(Tr[row], index_I[row][col]));
        }

        //随机生成一个L阶多项式，用它星乘上面得到的多项式
        Vec<ZZ> rand_poly;
        for (int col = 0; col < num_cols; col++)
        {
            rand_poly.append(RandomBnd(p));
        }

        // FIXME: 这个循环的效率有待提高
        // 主要的开销来源于未加密多项式与加密多项式的乘法
        // 探究是否可以用FFT来减小多项式的乘法开销
        for (int pos = 0; pos < 2 * num_cols; pos++)
        {
            ZZ_Cipher &target = res_mat[row][pos];
            target.first = 0;
            target.second = 0;
            for (int i = 0; i <= pos; i++)
            {
                int j = pos - i;
                ZZ_Cipher temp_C1;
                ZZ temp_ZZ;
                ZZ_Cipher temp_C2;
                temp_ZZ = i < num_cols ? rand_poly[i] : ZZ(0);
                // FIXME: 探究这里是不是可以用0来代替用bcp加密之后的0
                temp_C2 = j < num_cols ? poly[j] : bcp.Enc(ZZ(0));
                // temp_C2 = j < num_cols ? poly[j] : ZZ_Cipher{0, 0};
                temp_C1 = bcp.const_mul(temp_ZZ, temp_C2);

                target = bcp.homo_add(target, temp_C1);
            }
        }
        printf("row --------> %d complete\n", row);
    }

    Vec<ZZ_Cipher> res;
    //将所有得到的多项式相加，输出结果
    for (int col = 0; col < 2 * num_cols; col++)
    {
        ZZ_Cipher temp;
        temp.first = 0;
        temp.second = 0;
        for (int row = 0; row < num_rows; row++)
        {
            temp = bcp.homo_add(temp, res_mat[row][col]);
        }
        res.append(temp);
    }
    return res;
}

vector<string> ASES22::Decrypt(Vec<ZZ_Cipher> enc_poly)
{
    ZZ_pPush Push(p);
    //解密多项式系数得到多项式明文
    ZZ_pX poly;
    for (int i = 0; i < enc_poly.length(); i++)
    {
        SetCoeff(poly, i, to_ZZ_p(bcp.Dec2(enc_poly[i])));
    }

    //遍历全体定义域U找到id号
    Vec<ZZ_p> res;
    ZZ_p id;
    id = 0;
    while (rep(id) < 1000000) // FIXME: 这个全集不能太大，实测1,000,000就已经很大了
    {
        if (eval(poly, id) == 0)
        {
            res.append(id);
        }
        id += 1;
    }

    vector<string> str;
    for (auto each : res)
    {
        str.push_back(numberToString(rep(each)));
    }
    return str;
}

string ASES22::numberToString(ZZ num)
{
    long len = ceil(log(num) / log(128));
    char str[len];
    for (long i = len - 1; i >= 0; i--)
    {
        str[i] = conv<int>(num % 128);
        num /= 128;
    }

    return (string)str;
}