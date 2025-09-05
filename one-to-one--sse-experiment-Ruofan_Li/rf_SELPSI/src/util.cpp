#include "util.h"

vector<string> split(const string line, const string sep)
{
   vector<string> buf;
   int temp = 0;
   string::size_type pos = 0;
   while (true)
   {
      pos = line.find(sep, temp);
      if (pos == string::npos)
         break;
      buf.push_back(line.substr(temp, pos - temp));
      temp = pos + sep.length();
   }
   buf.push_back(line.substr(temp, line.length()));
   return buf;
}

string &trim(string &s)
{
   if (s.empty())
   {
      return s;
   }
   s.erase(0, s.find_first_not_of(" "));
   s.erase(s.find_last_not_of(" ") + 1);
   return s;
}

string &erasePending(string &str)
{
   int index = str.size() - 1;
   while (index != -1)
   {
      if (str[index] < '0' || str[index] > '9')
      {
         str.erase(index, 1);
         index--;
      }
      else
      {
         break;
      }
   }
   return str;
}
