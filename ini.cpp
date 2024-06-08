#include "ini.h"
#include "util.h"
#include "error_codes.h"
#include <cctype>
#include <cstdlib>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iostream>
#include <regex>
#include <cerrno>
#include <cstring>

using namespace std;

INIReader::INIReader(const string& filename) {
    std::cout << "INIReader constructor called with filename: " << filename << std::endl;
    m_error = parse(filename);
}

int INIReader::ParseError() const {
    return m_error;
}

string INIReader::Get(const string& section, const string& name, const string& default_value) const {
    string key = makeKey(section, name);
    return m_values.count(key) ? m_values.at(key) : default_value;
}

int INIReader::GetInteger(const string& section, const string& name, int default_value) const {
    string valstr = Get(section, name, "");
    const char* value = valstr.c_str();
    char* end;
    long n = strtol(value, &end, 0);
    return end > value ? n : default_value;
}

bool INIReader::GetBoolean(const string& section, const string& name, bool default_value) const {
    string valstr = Get(section, name, "");
    transform(valstr.begin(), valstr.end(), valstr.begin(), ::tolower);
    if (valstr == "true" || valstr == "yes" || valstr == "on" || valstr == "1")
        return true;
    else if (valstr == "false" || valstr == "no" || valstr == "off" || valstr == "0")
        return false;
    else
        return default_value;
}

vector<string> INIReader::GetSections() const {
    return vector<string>(m_sections.begin(), m_sections.end());
}

vector<string> INIReader::GetKeys(const string& section) const {
    vector<string> keys;
    string prefix = section + ".";
    for (const auto& kv : m_values) {
        if (kv.first.find(prefix) == 0) {
            keys.push_back(kv.first.substr(prefix.length()));
        }
    }
    return keys;
}

string INIReader::makeKey(const string& section, const string& name) {
    string key = section + "." + name;
    transform(key.begin(), key.end(), key.begin(), ::tolower);
    return key;
}

int INIReader::parse(const string& filename) {
    ifstream infile(filename.c_str());
    if (!infile) {
        std::cerr << "Error opening file: " << strerror(errno) << std::endl;
        m_error = ERROR_CANNOT_OPEN_FILE;
        throw runtime_error("Cannot open file: " + filename);
    }

    string line, section;
    int lineno = 0;
    while (getline(infile, line)) {
        lineno++;
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;
        if (line.front() == '[' && line.back() == ']') {
            section = line.substr(1, line.length() - 2);
            m_sections.insert(section);
        } else {
            istringstream isline(line);
            string name;
            if (getline(isline, name, '=') && name.length()) {
                string value;
                if (getline(isline, value)) {
                    m_values[makeKey(section, name)] = value;
                    if (section == "SCAN" && name == "path") {
                        if (!IsDirectory(value)) {
                            throw std::runtime_error("Invalid scan path: " + value);
                        }
                    }
                    if (section == "SCAN" && name == "scantype") {
                        int scanType = std::stoi(value);
                        if (scanType != 1 && scanType != 2) {
                            throw std::runtime_error("Invalid scan type: " + value);
                        }
                    }
                    if (section == "NOTIFICATION" && name == "emailaddress") {
                        const std::regex pattern(R"((\w+)(\.\w+)*@(\w+\.)+[A-Za-z]+)");
                        if (!std::regex_match(value, pattern)) {
                            throw std::runtime_error("Invalid email address: " + value);
                        }
                    }
                } else {
                    m_error = ERROR_INVALID_OPTION;
                    throw runtime_error(GetErrorMessage(m_error) + " at line " + to_string(lineno));
                }
            }
        }
    }
    m_error = SUCCESS_CODE;
    return m_error;
}

INIWriter::INIWriter(const string& filepath) : m_filename(filepath) {}

bool INIWriter::Write(const map<string, map<string, string>>& data) const {
    ofstream file(m_filename);
    if (!file.is_open()) {
        return false;
    }

    for (const auto& section : data) {
        file << "[" << section.first << "]\n";
        for (const auto& key : section.second) {
            file << key.first << "=" << key.second << "\n";
        }
        file << "\n";
    }

    file.close();
    return true;
}

bool INIWriter::DeleteSection(const string& section) {
    INIReader reader(m_filename);
    if (reader.ParseError() != 0) {
        return false;
    }

    map<string, map<string, string>> data;
    for (const auto& sec : reader.GetSections()) {
        if (sec != section) {
            map<string, string> sectionData;
            for (const auto& key : reader.GetKeys(sec)) {
                sectionData[key] = reader.Get(sec, key, "");
            }
            data[sec] = sectionData;
        }
    }

    return Write(data);
}

bool INIWriter::DeleteKey(const string& section, const string& key) {
    INIReader reader(m_filename);
    if (reader.ParseError() != 0) {
        return false;
    }

    map<string, map<string, string>> data;
    for (const auto& sec : reader.GetSections()) {
        map<string, string> sectionData;
        for (const auto& k : reader.GetKeys(sec)) {
            if (!(sec == section && k == key)) {
                sectionData[k] = reader.Get(sec, k, "");
            }
        }
        data[sec] = sectionData;
    }

    return Write(data);
}
