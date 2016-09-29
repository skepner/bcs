#include <iostream>
#include <cstring>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <sys/wait.h>
#include <sys/socket.h>
// #include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "server.hh"
#include "bcs-encrypt.hh"
#include "file.hh"

// ----------------------------------------------------------------------

static void child_completed(int sig);
[[noreturn]] static void server_terminated(int sig);

#pragma GCC diagnostic push
#ifdef __clang__
#pragma GCC diagnostic ignored "-Wglobal-constructors"
#pragma GCC diagnostic ignored "-Wexit-time-destructors"
#endif
static std::string socket_path;
#pragma GCC diagnostic pop

// ----------------------------------------------------------------------

enum Command {
    DisconnectClient,
    KillServer,
    EncryptDataData,
    EncryptDataFile,
    EncryptFileData,
    EncryptFileFile,
    DecryptDataData,
    DecryptDataFile,
    DecryptFileData,
    DecryptFileFile,
};

static Command read_command(int sock);
static void perform(int sock, Command command, std::string passwd);
static std::pair<std::string, std::string> get_args(int sock);

// ----------------------------------------------------------------------

void server(std::string socket_filename, std::string passwd)
{
    std::signal(SIGCHLD, child_completed);
    std::signal(SIGINT, server_terminated);
    std::signal(SIGTERM, server_terminated);

    int sockfd;
    if ((sockfd = socket(AF_UNIX,SOCK_STREAM,0)) < 0)
        throw std::runtime_error("creating socket");
    sockaddr_un serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sun_family = AF_UNIX;
    strcpy(serv_addr.sun_path, socket_filename.c_str());
    serv_addr.sun_len = static_cast<unsigned char>(socket_filename.size() + 1); // BSD only?
    const socklen_t servlen = static_cast<socklen_t>(socket_filename.size() + (reinterpret_cast<char*>(&serv_addr.sun_path) - reinterpret_cast<char*>(&serv_addr)));
    if (bind(sockfd, reinterpret_cast<sockaddr *>(&serv_addr), servlen) < 0)
        throw std::runtime_error("binding socket " + socket_filename + ": " + std::strerror(errno));
    socket_path = socket_filename;
    listen(sockfd, 5);
      // std::cout << "Listen at " << socket_filename << std::endl;

    sockaddr_un cli_addr;
    socklen_t clilen = sizeof(cli_addr);
    while (true) {
        const auto newsockfd = accept(sockfd, reinterpret_cast<sockaddr *>(&cli_addr), &clilen);
        if (newsockfd < 0)
            throw std::runtime_error("accept");
        const Command command = read_command(newsockfd);
        if (command == KillServer) {
            close(newsockfd);
            break;
        }
        if (command != DisconnectClient) {
            const auto pid = fork();
            if (pid < 0)
                throw std::runtime_error("fork");
            if (pid == 0)  {
                  // child
                close(sockfd);
                perform(newsockfd, command, passwd);
                std::exit(0);
            }
        }
        close(newsockfd);
    }
    close(sockfd);
    unlink(socket_filename.c_str());

} // server

// ----------------------------------------------------------------------

Command read_command(int sock)
{
    Command command = DisconnectClient;
    char buf[8];
    const auto bytes_read = read(sock, buf, 8);
    if (bytes_read == 8 && !std::memcmp(buf, "BCSA", 4)) {
        switch (buf[4]) {
          case 'K':
              command = KillServer;
              break;
          case 'E':
              command = EncryptFileFile;
              break;
          case 'D':
              command = DecryptFileFile;
              break;
          default:
              break;
        }
    }
    return command;

} // read_command

// ----------------------------------------------------------------------

void perform(int sock, Command command, std::string passwd)
{
    const auto args = get_args(sock);
    switch (command) {
      case EncryptFileFile:
          write_file(args.second, encrypt(passwd, read_file(args.first, false)), false);
          break;
      case DecryptFileFile:
          write_file(args.second, decrypt(passwd, read_file(args.first, false)), false);
          break;
      case DisconnectClient:
          break;
      default:
          std::cerr << "Not implemented command " << command << std::endl;
          break;
    }
}

// ----------------------------------------------------------------------

std::pair<std::string, std::string> get_args(int sock)
{
    uint32_t s;
    read(sock, &s, sizeof(s));
    std::string arg1(s, '?');
    read(sock, &arg1[0], s);
      //std::cout << "arg1 " << s << " " << arg1 << std::endl;
    read(sock, &s, sizeof(s));
    std::string arg2(s, '?');
    read(sock, &arg2[0], s);
      //std::cout << "arg2 " << s << " " << arg2 << std::endl;

    return std::make_pair(arg1, arg2);

} // get_args

// ----------------------------------------------------------------------

void child_completed(int /*sig*/)
{
    wait3(nullptr, WNOHANG, nullptr);
}

// ----------------------------------------------------------------------

void server_terminated(int /*sig*/)
{
    if (!socket_path.empty())
        unlink(socket_path.c_str());
    exit(0);

} // server_terminated

// ----------------------------------------------------------------------

void client(std::string socket_filename, char command, std::string arg1, std::string arg2)
{
    int sockfd;
    if ((sockfd = socket(AF_UNIX,SOCK_STREAM,0)) < 0)
        throw std::runtime_error("creating socket");
    sockaddr_un serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sun_family = AF_UNIX;
    strcpy(serv_addr.sun_path, socket_filename.c_str());
    serv_addr.sun_len = static_cast<unsigned char>(socket_filename.size() + 1); // BSD only?
    const socklen_t servlen = static_cast<socklen_t>(socket_filename.size() + (reinterpret_cast<char*>(&serv_addr.sun_path) - reinterpret_cast<char*>(&serv_addr)));
    if (connect(sockfd, reinterpret_cast<sockaddr *>(&serv_addr), servlen) < 0)
        throw std::runtime_error("connecting " + socket_filename + ": " + std::strerror(errno));

    char cmd[9] = "BCSA?   ";
    cmd[4] = command;
    write(sockfd, cmd, 8);

    const size_t message_size = arg1.size() + arg2.size() + 8;
    char* buf = new char[message_size];
    try {
        uint32_t s = static_cast<uint32_t>(arg1.size());
        memcpy(buf, &s, sizeof(s));
        memcpy(buf + sizeof(s), arg1.c_str(), arg1.size());
        s = static_cast<uint32_t>(arg2.size());
        memcpy(buf + sizeof(s) + arg1.size(), &s, sizeof(s));
        memcpy(buf + sizeof(s) + arg1.size() + sizeof(s), arg2.c_str(), arg2.size());
        write(sockfd, buf, message_size);
    }
    catch (...) {
        delete [] buf;
        throw;
    }
    delete [] buf;

    close(sockfd);

} // client

// ----------------------------------------------------------------------
