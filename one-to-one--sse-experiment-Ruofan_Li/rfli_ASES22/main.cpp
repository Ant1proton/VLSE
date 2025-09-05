#include "ASES22.h"

#include <ctime>

using namespace std;

int main()
{
    ASES22 ases;

    vector<string> queries;
    queries.push_back("don't");

    double start_time, end_time;
    cout << "------------------------------------------------------" << endl;
    start_time = clock();
    cout << "Index_I_Gen  ------------>  start" << endl;
    Mat<ZZ_Cipher> index_I;
    index_I = ases.Index_I_Gen("/Users/rfli/Desktop/Code/one-to-one--sse-experiment/database/small_inverted_index");
    cout << "Index_I_Gen ------------> end" << endl;
    end_time = clock();
    cout << "time = " << (end_time - start_time) / CLOCKS_PER_SEC << endl;
    cout << "------------------------------------------------------" << endl;

    cout << "------------------------------------------------------" << endl;
    start_time = clock();
    cout << "TGen ------------> start" << endl;
    Vec<ZZ_Cipher> Tr;
    Tr = ases.TGen(queries);
    cout << "TGen ------------> end" << endl;
    end_time = clock();
    cout << "time = " << (end_time - start_time) / CLOCKS_PER_SEC << endl;
    cout << "------------------------------------------------------" << endl;

    cout << "------------------------------------------------------" << endl;
    start_time = clock();
    cout << "Search ------------> start" << endl;
    Vec<ZZ_Cipher> enc_poly;
    enc_poly = ases.Search(Tr, index_I);
    cout << "Search ------------> end" << endl;
    end_time = clock();
    cout << "time = " << (end_time - start_time) / CLOCKS_PER_SEC << endl;
    cout << "------------------------------------------------------" << endl;

    cout << "------------------------------------------------------" << endl;
    start_time = clock();
    cout << "Decrypt ------------> start" << endl;
    vector<string> res;
    res = ases.Decrypt(enc_poly);
    cout << "Decrypt ------------> end" << endl;
    end_time = clock();
    cout << "time = " << (end_time - start_time) / CLOCKS_PER_SEC << endl;
    cout << "------------------------------------------------------" << endl;

    for (auto each : res)
    {
        cout << each << "\t";
    }
    cout << endl;
    return 0;
}