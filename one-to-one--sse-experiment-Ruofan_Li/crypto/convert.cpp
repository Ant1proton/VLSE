#include "../include/convert.h"
string convert_hex(unsigned char *md /*字符串*/, int nLen /*转义多少个字符*/)
{
    string strSha1 = "";
    char hex_chars[] = "0123456789abcdef";
    unsigned int c = 0;

    // 查看unsigned char占几个字节
    // 实际占1个字节，8位
    //int nByte = sizeof(unsigned char);

    for (int i = 0; i < nLen; i++)
    {
        // 查看md一个字节里的信息
        unsigned int x = 0;
        x = md[i];
        x = md[i] >> 4; // 右移，干掉4位，左边高位补0000

        c = (md[i] >> 4) & 0x0f;
        strSha1 += hex_chars[c];
        x = md[i] & 0x0f;
        strSha1 += hex_chars[x];
    }
    return strSha1;
}
unsigned char *stringtouchexs(string str)
{
    unsigned char *output = new unsigned char[str.size()/2];
    memset(output, 0, sizeof(output));
    int temp = 0;
    int len = 0;
    for (int i = 0; i < str.size(); i += 2) //每两位转换成十进制int,如 "10"=> 16(字符串为十六进制)
    {
        temp = 0;
        char tmp = str[i];
        int ll = isdigit(tmp) ? tmp - '0' : tmp - 'a' + 10;
        temp = temp * 16 + ll;
        tmp = str[i + 1];
        ll = isdigit(tmp) ? tmp - '0' : tmp - 'a' + 10;
        temp = temp * 16 + ll;
        output[len++] = (unsigned char)temp;
    }
    return output;
}
unsigned char *stringtouc(string str)
{
    unsigned char *s = new unsigned char[str.size()+1];
    string temp(str);
    int i;
    int len = temp.length();
    for (i = 0; i < len; ++i)
        s[i] = (unsigned char)temp[i];
    s[i] = '\0';
    return s;
}
string uctostring(unsigned char *c, int c_len)
{
    string str;
    for (int i = 0; i < c_len; ++i) {
        str.push_back(c[i]);
    }
    return str;
}
int GetTextLength(unsigned char *in_data)
{
    int len = strlen((char *)in_data);
    return len;
}
int Getlength(string str)
{
    int i=0;
    while(1)
    {
        if(16*i>=str.size())break;
        i++;
    }
    return i*16;
}