#pragma once

#include <iostream>
#include <vector>
#include <fts.h>

void compareByHash(FTSENT *node, std::vector<std::string>& detectedMalware, std::vector<std::string>& hashes);
std::string computeSHA256(const std::string& filename);