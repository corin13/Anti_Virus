#pragma once

#include <string>
#include <map>
#include <vector>

class INIReader {
public:
    INIReader(const std::string& filename);
    int ParseError() const;
    std::string Get(const std::string& section, const std::string& name, const std::string& default_value) const;
    int GetInteger(const std::string& section, const std::string& name, int default_value) const;
    bool GetBoolean(const std::string& section, const std::string& name, bool default_value) const;

private:
    int _parse(const std::string& filename);
    static std::string _make_key(const std::string& section, const std::string& name);
    int _error;
    std::map<std::string, std::string> _values;
};
