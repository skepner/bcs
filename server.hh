#pragma once

#include <string>

// ----------------------------------------------------------------------

enum Command : char
{
    DisconnectClient = ' ',
    KillServer = 'K',

    EncryptDataData = 'A',
    EncryptDataFile = 'B',
    EncryptFileData = 'C',
    EncryptFileFile = 'D',

    DecryptDataData = 'L',
    DecryptDataFile = 'M',
    DecryptFileData = 'N',
    DecryptFileFile = 'O',
    DecryptDataTemp = 'P',
    DecryptFileTemp = 'Q',
};

// ----------------------------------------------------------------------

void server(std::string socket_filename, std::string passwd);
std::string client(std::string socket_filename, Command command, std::string arg1 = std::string(), std::string arg2 = std::string(), bool output_expected = false);
void client_command(std::string socket_filename, bool encrypt, std::string arg1 = std::string(), std::string arg2 = std::string());

// ----------------------------------------------------------------------
