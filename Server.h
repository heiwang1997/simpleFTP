//
// Created by jameshuang on 16-12-13.
//

#ifndef FTP_SERVER_SERVER_H
#define FTP_SERVER_SERVER_H

#include <string>
#include "const.h"
#include <netinet/in.h>

namespace ftp {

class Server {
    int command_socket_fd;
    int command_connection_fd;

    int data_socket_fd;

    bool current_user_ok;
    bool current_user_authorized;

    std::string working_dir;

    int executeCommand(const std::string&);
    void issueCommandResponse(FtpResponseCode code, const std::string& info);
    void openDataConnection(const sockaddr_in& sock_addr);
    void sendViaDataConnection(std::istream& istream);
    void receiveViaDataConnection(std::ostream& ostream);
    void closeDataConnection();

    std::string unixOperation(const std::string& command);

    bool processUserCommand(const str_vec& info);
    bool processPasswordCommand(const str_vec& info);
    bool processRetrieveCommand(const str_vec& info);
    bool processStoreCommand(const str_vec& info);
    bool processPWDCommand(const str_vec& info);
    bool processCWDCommand(const str_vec& info);
    bool processListCommand(const str_vec& info);
    bool processPortCommand(const str_vec& info);
    bool processHelpCommand(const str_vec& info);
public:
    void startService();

    Server();
};

}



#endif //FTP_SERVER_SERVER_H
