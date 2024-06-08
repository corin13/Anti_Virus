#pragma once

#include <string>
#include <map>
#include <vector>
#include <set>

class INIReader {
public:
	INIReader() = default;
    INIReader(const std::string& filename);
    int ParseError() const;
    std::string Get(const std::string& section, const std::string& name, const std::string& default_value) const;
    int GetInteger(const std::string& section, const std::string& name, int default_value) const;
    bool GetBoolean(const std::string& section, const std::string& name, bool default_value) const;

	std::vector<std::string> GetSections() const;
    std::vector<std::string> GetKeys(const std::string& section) const;

private:
    int _parse(const std::string& filename);
    static std::string _make_key(const std::string& section, const std::string& name);
    int _error=-1; // 기본값으로 초기화
    std::map<std::string, std::string> _values;
	std::set<std::string> _sections;
};

class INIWriter {
public:
	INIWriter() = default;
    INIWriter(const std::string& filename);
    bool Write(const std::map<std::string, std::map<std::string, std::string>>& data) const;
    bool DeleteSection(const std::string& section);
    bool DeleteKey(const std::string& section, const std::string& key);

private:
    std::string _filename;
};