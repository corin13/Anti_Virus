#include "ini.h"
#include <cctype>
#include <cstdlib>
#include <algorithm>
#include <fstream>
#include <sstream>

using namespace std;

INIReader::INIReader(const string& filename) {
    _error = _parse(filename);
}

int INIReader::ParseError() const {
    return _error;
}

string INIReader::Get(const string& section, const string& name, const string& default_value) const {
    string key = _make_key(section, name);
    return _values.count(key) ? _values.at(key) : default_value;
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

string INIReader::_make_key(const string& section, const string& name) {
    string key = section + "." + name;
    transform(key.begin(), key.end(), key.begin(), ::tolower);
    return key;
}

int INIReader::_parse(const string& filename) {
    ifstream infile(filename.c_str());
    if (!infile) return -1;

    string line, section;
    int lineno = 0;
    while (getline(infile, line)) {
        lineno++;
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;
        if (line.front() == '[' && line.back() == ']') {
            section = line.substr(1, line.length() - 2);
        } else {
            istringstream isline(line);
            string name;
            if (getline(isline, name, '=') && name.length()) {
                string value;
                if (getline(isline, value)) {
                    _values[_make_key(section, name)] = value;
                }
            }
        }
    }
    return 0;
}
