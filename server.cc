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
static void server_terminated(int sig);

#pragma GCC diagnostic push
#ifdef __clang__
#pragma GCC diagnostic ignored "-Wglobal-constructors"
#pragma GCC diagnostic ignored "-Wexit-time-destructors"
#endif
static std::string socket_path;
#pragma GCC diagnostic pop

// ----------------------------------------------------------------------

class Socket
{
 public:
    inline Socket(std::string socket_filename, bool aServer) : sock(-1), socket_path(socket_filename), server(aServer)
        {
            if ((sock = socket(AF_UNIX,SOCK_STREAM,0)) < 0)
                throw std::runtime_error("creating socket");
            try {
                sockaddr_un serv_addr;
                memset(&serv_addr, 0, sizeof(serv_addr));
                serv_addr.sun_family = AF_UNIX;
                strcpy(serv_addr.sun_path, socket_path.c_str());
                serv_addr.sun_len = static_cast<unsigned char>(socket_path.size() + 1); // BSD only?
                const socklen_t servlen = static_cast<socklen_t>(socket_path.size() + (reinterpret_cast<char*>(&serv_addr.sun_path) - reinterpret_cast<char*>(&serv_addr)));
                if (server) {
                    ::socket_path = socket_path;
                    if (bind(sock, reinterpret_cast<sockaddr *>(&serv_addr), servlen) < 0)
                        throw std::runtime_error("binding socket " + socket_path + ": " + std::strerror(errno));
                    if (listen(sock, 5) < 0)
                        throw std::runtime_error("listening socket " + socket_path + ": " + std::strerror(errno));
                }
                else {
                    if (connect(sock, reinterpret_cast<sockaddr *>(&serv_addr), servlen) < 0)
                        throw std::runtime_error("connecting " + socket_path + ": " + std::strerror(errno));
                }
            }
            catch (...) {
                ::close(sock);
                throw;
            }
        }
    inline Socket(const Socket&) = default;

    inline Socket accept()
        {
            sockaddr_un cli_addr;
            socklen_t clilen = sizeof(cli_addr);
            const auto newsock = ::accept(sock, reinterpret_cast<sockaddr *>(&cli_addr), &clilen);
            if (newsock < 0)
                throw std::runtime_error("accept");
            return newsock;
        }

    inline ~Socket()
        {
            if (sock >= 0)
                ::close(sock);
            if (server && !socket_path.empty())
                unlink(socket_path.c_str());
        }

    inline void close()
        {
            ::close(sock);
            sock = -1;
        }

    inline std::string read_bytes(size_t size)
        {
            std::string buf(size, '?');
            size_t bytes_read = 0;
            while (bytes_read < size) {
                const ssize_t result = read(sock, &buf[0] + bytes_read, size - bytes_read);
                if (result < 0)
                    throw std::runtime_error(std::string("reading from socket: ") + std::strerror(errno));
                else if (result == 0)
                    throw std::runtime_error("reading from socket: unexpected end of data");
                bytes_read += static_cast<decltype(bytes_read)>(result);
            }
            return buf;

        } // read_bytes

    inline uint32_t read_uint32()
        {
            uint32_t data;
            const auto result = read(sock, &data, sizeof(data));
            if (result < 0)
                throw std::runtime_error(std::string("reading from socket: ") + std::strerror(errno));
            else if (result == 0)
                throw std::runtime_error("reading from socket: unexpected end of data");
            else if (result != sizeof(data))
                throw std::runtime_error("reading from socket: incomplete data");
            return data;

        } // read_uint32

    inline std::string read_arg()
        {
            return read_bytes(read_uint32());
        }

    inline void send_message(char command, std::string arg1 = std::string(), std::string arg2 = std::string())
        {
            char cmd[9] = "BCSA?   ";
            cmd[4] = command;
            write(sock, cmd, 8);

            if (!arg1.empty()) {
                const uint32_t s1 = static_cast<uint32_t>(arg1.size());
                write(sock, &s1, sizeof(s1));
                write(sock, &arg1[0], arg1.size());

                if (!arg2.empty()) {
                    const uint32_t s2 = static_cast<uint32_t>(arg2.size());
                    write(sock, &s2, sizeof(s2));
                    write(sock, &arg2[0], arg2.size());
                }
            }
        }

 private:
    int sock;
    std::string socket_path;
    bool server;

    inline Socket(int aSock) : sock(aSock), server(false) {}
};

// ----------------------------------------------------------------------

// enum Command {
//     DisconnectClient,
//     KillServer,
//     EncryptDataData,
//     EncryptDataFile,
//     EncryptFileData,
//     EncryptFileFile,
//     DecryptDataData,
//     DecryptDataFile,
//     DecryptFileData,
//     DecryptFileFile,
//     DecryptDataTemp,
//     DecryptFileTemp,
// };

static Command read_command(Socket& sock);
static void perform(Socket& sock, Command command, std::string passwd);

// ----------------------------------------------------------------------

void server(std::string socket_filename, std::string passwd)
{

    const int pid_server = fork();
    if (pid_server < 0)
        throw std::runtime_error("cannot fork server");
    if (pid_server == 0) {
        // child: background server
        setsid();
        std::signal(SIGHUP, SIG_IGN);
        std::signal(SIGCHLD, child_completed);
        std::signal(SIGINT, server_terminated);
        std::signal(SIGTERM, server_terminated);
        ::close(0);
        ::close(1);
        ::close(2);

        Socket sock(socket_filename, true);
        while (true) {
            Socket connection = sock.accept();
            const Command command = read_command(connection);
            if (command == KillServer) {
                connection.send_message('S'); // success
                break;
            }
            if (command != DisconnectClient) {
                const int pid = fork();
                if (pid < 0)
                    throw std::runtime_error("fork");
                if (pid == 0) {
                    // child
                    sock.close();
                    perform(connection, command, passwd);
                    std::exit(0);
                }
            }
        }
    }
    else {
        // parent, server starter
        std::exit(0);
    }

} // server

// ----------------------------------------------------------------------

Command read_command(Socket& sock)
{
    Command command = DisconnectClient;
    const std::string data = sock.read_bytes(8);
    if (data.substr(0, 4) == "BCSA") {
        command = static_cast<Command>(data[4]);
    }
    return command;

} // read_command

// ----------------------------------------------------------------------

void perform(Socket& sock, Command command, std::string passwd)
{
    std::string arg1, arg2, reply;
    try {
        switch (command) {
          case EncryptFileFile:
              arg1 = sock.read_arg();
              arg2 = sock.read_arg();
              write_file(arg2, encrypt(passwd, read_file(arg1, false)), false);
              break;
          case EncryptDataFile:
              arg1 = sock.read_arg();
              arg2 = sock.read_arg();
              write_file(arg2, encrypt(passwd, arg1), false);
              break;
          case EncryptDataData:
              arg1 = sock.read_arg();
              reply = encrypt(passwd, arg1);
              break;
          case EncryptFileData:
              arg1 = sock.read_arg();
              reply = encrypt(passwd, read_file(arg1, false));
              break;
          case DecryptFileFile:
              arg1 = sock.read_arg();
              arg2 = sock.read_arg();
              write_file(arg2, decrypt(passwd, read_file(arg1, false)), false);
              break;
          case DecryptFileData:
              arg1 = sock.read_arg();
              reply = decrypt(passwd, read_file(arg1, false));
              break;
          case DecryptDataData:
              arg1 = sock.read_arg();
              reply = decrypt(passwd, arg1);
              break;
          case DecryptDataFile:
              arg1 = sock.read_arg();
              arg2 = sock.read_arg();
              write_file(arg2, decrypt(passwd, arg1), false);
              break;
          case DecryptDataTemp:
              arg1 = sock.read_arg();
              reply = write_temp_file(decrypt(passwd, arg1), "");
              break;
          case DecryptFileTemp:
              arg1 = sock.read_arg();
              reply = write_temp_file(decrypt(passwd, read_file(arg1, false)), find_suffix(arg1));
              break;
          case DisconnectClient:
          case KillServer:
              break;
          // default:
          //     throw std::runtime_error("Not implemented command " + std::string(1, command));
        }
        sock.send_message('S', reply); // success
    }
    catch (std::exception& err) {
        sock.send_message('F', err.what()); // error
    }
}

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

void client_command(std::string socket_filename, bool encrypt, std::string arg1, std::string arg2)
{
    Command cmd = encrypt ? EncryptFileFile : DecryptFileFile;
    bool output_expected = false;
    if (arg1 == "-") {
        arg1 = read_file(arg1);
        if (arg2 == "-" || arg2 == "=") {
            cmd = encrypt ? EncryptDataData : DecryptDataData;
            output_expected = true;
        }
        else if (!encrypt && arg2.empty()) {
            cmd = DecryptDataTemp;
            output_expected = true;
        }
        else {
            cmd = encrypt ? EncryptDataFile : DecryptDataFile;
        }
    }
    else if (!encrypt && arg2.empty()) {
            cmd = DecryptFileTemp;
            output_expected = true;
    }
    else if (arg2 == "-" || arg2 == "=") {
            cmd = encrypt ? EncryptFileData : DecryptFileData;
            output_expected = true;
    }

    switch (cmd) {
      case EncryptFileFile:
      case DecryptFileFile:
          arg1 = resolve_path(arg1);
          arg2 = resolve_path(arg2);
          break;
      case EncryptDataFile:
      case DecryptDataFile:
          arg2 = resolve_path(arg2);
          break;
      case EncryptFileData:
      case DecryptFileData:
      case DecryptFileTemp:
          arg1 = resolve_path(arg1);
          break;
      case DisconnectClient:
      case KillServer:
      case EncryptDataData:
      case DecryptDataData:
      case DecryptDataTemp:
          break;
    }

    std::string result = client(socket_filename, cmd, arg1, arg2 == "-" || arg2 == "=" ? std::string() : arg2, output_expected);
    if (output_expected) {
        if (arg2 == "-")
            std::cout.write(result.c_str(), static_cast<std::streamsize>(result.size()));
        else if (arg2 == "=")
            std::cerr.write(result.c_str(), static_cast<std::streamsize>(result.size()));
        else                    // name of temp file made by server
            std::cout.write(result.c_str(), static_cast<std::streamsize>(result.size()));
    }

} // client_command

// ----------------------------------------------------------------------

std::string client(std::string socket_filename, Command command, std::string arg1, std::string arg2, bool output_expected)
{
    Socket sock(socket_filename, false);

    sock.send_message(command, arg1, arg2);

    const std::string reply = sock.read_bytes(8);
    std::string result;
    switch (reply[4]) {
      case 'S':                 // success
          if (output_expected)
              result = sock.read_arg();
          break;
      case 'F':
          throw std::runtime_error(sock.read_arg());
      default:
          throw std::runtime_error("Unrecognized reply code " + std::string(1, reply[4]));
    }

    return result;

} // client

// ----------------------------------------------------------------------
