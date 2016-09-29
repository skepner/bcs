#pragma once

#include <string>

// ----------------------------------------------------------------------

void server(std::string socket_filename, std::string passwd);
void client(std::string socket_filename, char command, std::string arg1 = std::string(), std::string arg2 = std::string());

// ----------------------------------------------------------------------
