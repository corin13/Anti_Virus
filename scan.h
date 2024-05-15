#ifndef SCAN_H
#define SCAN_H

#include <string>
#include <vector>
#include <fts.h>

using namespace std;

void scan();
void scanDirectory(const string& path, int option);
void compareByHash(FTSENT *node, vector<string>& detectedMalware, vector<string>& hashes);
vector<string> loadHashes(const string& filename);
string computeSHA256(const string& filename);
void checkYaraRule();

#endif