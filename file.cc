#include <iostream>
#include <fstream>
#include <cstdio>
#include <cerrno>

#include "file.hh"

// ----------------------------------------------------------------------

std::string read_file(std::string filename, bool minus_for_std)
{
    if (minus_for_std && filename == "-") {
        std::string data;
        while (std::cin)
            data.append(1, static_cast<char>(std::cin.get()));
        return data;
    }
    if (std::ifstream in{filename, std::ios::binary | std::ios::ate}) {
        const auto size = in.tellg();
        std::string data(static_cast<std::string::size_type>(size), '\0');
        in.seekg(0);
        in.read(&data[0], size);
        return data;
    }
    else
        throw std::runtime_error(filename + ": cannot open for reading");

} // read_file

// ----------------------------------------------------------------------

void write_file(std::string filename, std::string data, bool minus_for_std)
{
    if (minus_for_std && filename == "-")
        std::cout << data;
    else if (minus_for_std && filename == "=")
        std::cerr << data;
    else if (std::ofstream out{filename, std::ios::binary | std::ios::trunc}) {
        if (!out.write(data.c_str(), static_cast<std::streamsize>(data.size())))
            throw std::runtime_error(filename + ": writing failed");
    }
    else
        throw std::runtime_error(filename + ": cannot open for writing");

} // write_file

// ----------------------------------------------------------------------

std::string write_temp_file(std::string data)
{
    char name[L_tmpnam];
    if (!std::tmpnam(name))
        throw std::runtime_error(std::string("tmpnam failed: ") + std::strerror(errno));
    write_file(name, data, false);
    return name;

} // write_temp_file

// ----------------------------------------------------------------------
