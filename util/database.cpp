
// database.cpp

#include "/Users/chenyuwei/Desktop/paper_code/yb/rf_SELPSI/include/database.h"
#include <fstream>
#include <sstream>
#include <iostream>

std::map<std::string, std::vector<std::string>> DB_build_by_inverted(const std::string &path) {
    std::map<std::string, std::vector<std::string>> invert_DB;
    std::ifstream ifs(path);
    if (!ifs) {
        std::cerr << "Could not open file: " << path << std::endl;
        return invert_DB;
    }

    std::string line;
    while (std::getline(ifs, line)) {
        std::istringstream iss(line);
        std::string word, doc_id;
        if (iss >> word) {
            while (iss >> doc_id) {
                invert_DB[word].push_back(doc_id);
            }
        }
    }

    return invert_DB;
}
