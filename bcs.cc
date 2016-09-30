#include <iostream>
#include <fstream>
#include <getopt.h>
#include <pwd.h>

#include "bcs-encrypt.hh"
#include "file.hh"
#include "server.hh"

// ----------------------------------------------------------------------

[[noreturn]] static void usage(const char* progname);
std::string get_password(bool repeat);

// ----------------------------------------------------------------------

enum ClientCommand { Encrypt, Decrypt, Server, StopServer };

static const char* socket_path = "/var/run/bcs.socket";

// ----------------------------------------------------------------------

int main(int argc, char* const* argv)
{
    int exit_code = 0;
    ClientCommand command = Decrypt;
    bool via_server = false;
    option longopts[] = {
        {"encrypt",     no_argument, nullptr, 'e'},
        {"decrypt",     no_argument, nullptr, 'd'},
        {"server",      no_argument, nullptr, 's'},
        {"client",      no_argument, nullptr, 'c'},
        {"kill-server", no_argument, nullptr, 'k'},
        { nullptr,      0,           nullptr, 0}
    };
    int ch;
    while ((ch = getopt_long(argc, argv, "edsck", longopts, nullptr)) != -1) {
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
          default:
              usage(argv[0]);
        }
    }
    argc -= optind;
    argv += optind;

    try {
        switch (command) {
          case Encrypt:
              if (argc != 2)
                  usage(argv[0]);
              if (via_server)
                  client_command(socket_path, true, argv[0], argv[1]);
              else
                  write_file(argv[1], encrypt(get_password(true), read_file(argv[0])));
              break;
          case Decrypt:
              if (argc != 2)
                  usage(argv[0]);
              if (via_server)
                  client_command(socket_path, false, argv[0], argv[1]);
              else
                  write_file(argv[1], decrypt(get_password(false), read_file(argv[0])));
              break;
          case Server:
              server(socket_path, get_password(true));
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

std::string get_password(bool repeat)
{
    std::string passwd = getpass("Password: ");
    if (repeat) {
        if (passwd != getpass("Repeat: "))
            throw std::runtime_error("Password mismatch");
    }
    return passwd;

} // get_password

// ----------------------------------------------------------------------

void usage(const char* progname)
{
    std::cerr << "Usage: " << progname << "[-e|--encrypt] [-d|--decrypt] <input> <output>" << std::endl;
    exit(1);
}

// ----------------------------------------------------------------------
