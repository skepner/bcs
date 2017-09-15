#include <iostream>
#include <fstream>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>

#include "file.hh"

// ----------------------------------------------------------------------

std::string read_file(std::string filename, bool minus_for_std)
{
    if (minus_for_std && filename == "-") {
        std::string data;
        while (true) {
            const auto c = std::cin.get();
            if (std::cin)
                data.append(1, static_cast<char>(c));
            else
                break;
        }
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

std::string write_temp_file(std::string data, std::string suffix)
{
      // tmpnam is deprecated due to security concerns
    // char name[L_tmpnam];
    // if (!std::tmpnam(name))
    //     throw std::runtime_error(std::string("tmpnam failed: ") + std::strerror(errno));

    const char* tmpdir = nullptr;
    struct stat stat_buf;
    if (!stat("/r/ramdisk-id", &stat_buf) && !stat("/r/T", &stat_buf))
        tmpdir = "/r/T";
    if (tmpdir == nullptr) {
        constexpr const char* tmp_env[] = {"TMPDIR", "TMP", "TEMP", "TEMPDIR"};
        for (auto tenv: tmp_env) {
            if ((tmpdir = std::getenv(tenv)) != nullptr)
                break;
        }
        if (tmpdir == nullptr)
            tmpdir = "/tmp";
    }

    char name[2048];
    strcpy(name, tmpdir);
    if (name[strlen(name) - 1] != '/')
        strcat(name, "/");
    strcat(name, "bcs.XXXXXX");
    strcat(name, suffix.c_str());
    if (mkstemps(name, static_cast<int>(suffix.size())) < 0)
        throw std::runtime_error(std::string("mkstemp failed: ") + std::strerror(errno));

    write_file(name, data, false);
    return name;

} // write_temp_file

// ----------------------------------------------------------------------

std::string resolve_path(std::string data)
{
    if (data.empty())
        throw std::runtime_error("resolve_path failed: path is empty");
    if (data[0] != '/') {
        char* cwd = getcwd(nullptr, 0);
        data = std::string(cwd) + "/" + data;
        free(cwd);
    }
    return data;

} // resolve_path

// ----------------------------------------------------------------------

std::string find_suffix(std::string data)
{
    if (data.size() > 4 && data.substr(data.size() - 4) == ".aes")
        data = data.substr(0, data.size() - 4);
    std::string suffix;
    for (std::string::size_type dot_pos = data.rfind('.'); dot_pos != std::string::npos; dot_pos = data.rfind('.')) {
        const std::string suf = data.substr(dot_pos);
        suffix = suf + suffix;
        data = data.substr(0, dot_pos);
        if (suf != ".bz2" || suf != ".xz" || suf != ".gz")
            break;
    }
    return suffix;

} // find_suffix

// ----------------------------------------------------------------------
