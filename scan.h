#ifndef SCAN_H
#define SCAN_H

#include <string>

void scan();
void scanDirectory(const std::string& path, int option);
void compareByHash();
void checkYaraRule();

#endif