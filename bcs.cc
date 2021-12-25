#include <iostream>
#include <fstream>
#include <getopt.h>
#include <pwd.h>

#include "bcs-encrypt.hh"
#include "file.hh"
#include "server.hh"

// ----------------------------------------------------------------------

[[noreturn]] static void usage(const char* progname);
std::string get_password(bool repeat, std::string encrypted_sample);

// ----------------------------------------------------------------------

enum ClientCommand { Encrypt, Decrypt, Server, StopServer };

static const char* socket_subpath = "/.var/run/bcs.socket";

// ----------------------------------------------------------------------

int main(int argc, char* const* argv)
{
    int exit_code = 0;
    ClientCommand command = Decrypt;
    bool via_server = false;
    std::string encrypted_sample;
    const char* progname = argv[0];
    option longopts[] = {
        {"encrypt",     no_argument, nullptr, 'e'},
        {"decrypt",     no_argument, nullptr, 'd'},
        {"server",      no_argument, nullptr, 's'},
        {"client",      no_argument, nullptr, 'c'},
        {"kill-server", no_argument, nullptr, 'k'},
        {"encrypted-sample", required_argument, nullptr, 'z'},
        { nullptr,      0,           nullptr, 0}
    };
    int ch;
    while ((ch = getopt_long(argc, argv, "edsckz:", longopts, nullptr)) != -1) {
        switch (ch) {
          case 'e':
              command = Encrypt;
              break;
          case 'd':
              command = Decrypt;
              break;
          case 's':
              command = Server;
              break;
          case 'c':
              via_server = true;
              break;
          case 'k':
              command = StopServer;
              break;
          case 'z':
              encrypted_sample = optarg;
              break;
          default:
              usage(progname);
        }
    }
    argc -= optind;
    argv += optind;

    const auto socket_path{std::string{getenv("HOME")} + socket_subpath};
    try {
        switch (command) {
          case Encrypt:
              if (argc != 2)
                  usage(progname);
              if (via_server)
                  client_command(socket_path, true, argv[0], argv[1]);
              else
                  write_file(argv[1], encrypt(get_password(true, encrypted_sample), read_file(argv[0])));
              break;
          case Decrypt:
              if (via_server) {
                  if (argc != 2 && argc != 1)
                      usage(progname);
                  client_command(socket_path, false, argv[0], argc >= 2 ? argv[1] : "");
              }
              else {
                  if (argc != 2)
                      usage(progname);
                  write_file(argv[1], decrypt(get_password(false, encrypted_sample), read_file(argv[0])));
              }
              break;
          case Server:
              server(socket_path, get_password(encrypted_sample.empty(), encrypted_sample));
              break;
          case StopServer:
              client(socket_path, KillServer);
              break;
        }
    }
    catch (std::exception& err) {
        std::cerr << "Error: " << err.what() << std::endl;
        exit_code = 1;
    }

    return exit_code;
}

// ----------------------------------------------------------------------

std::string get_password(bool repeat, std::string encrypted_sample)
{
    std::string passwd = getpass("Password: ");
    if (repeat) {
        if (passwd != getpass("Repeat: "))
            throw std::runtime_error("Password mismatch");
    }
    if (!encrypted_sample.empty()) {
          // check password by decrypting sample
        try {
            decrypt(passwd, read_file(encrypted_sample));
        }
        catch (std::exception& err) {
            throw std::runtime_error(std::string("Cannot decrypt sample with the entered password: ") + err.what());
        }
    }
    return passwd;

} // get_password

// ----------------------------------------------------------------------

void usage(const char* progname)
{
    std::cerr << "Usage: " << progname << " [-e|--encrypt] [-d|--decrypt] [-s|--server] [-c|--client] [-k|--kill-server] [<input> <output>]" << std::endl;
    exit(1);
}

// ----------------------------------------------------------------------
