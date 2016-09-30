#pragma once

#include <string>

// ----------------------------------------------------------------------

std::string read_file(std::string filename, bool minus_for_std = true);
void write_file(std::string filename, std::string data, bool minus_for_std = true);
std::string write_temp_file(std::string data);

// ----------------------------------------------------------------------
