//
// Created by jameshuang on 16-12-13.
//

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <glog/logging.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <fstream>
#include "Server.h"
#include "const.h"

using std::memset;

void ftp::Server::startService() {

    google::InitGoogleLogging("Ftp_Server");
    google::SetStderrLogging(google::INFO);

    // Initialize Socket.
    if ((command_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) == -1) {
        LOG(FATAL) << "Socket init error.";
        exit(0);
    }

    sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(FTP_COMMAND_PORT);

    if (bind(command_socket_fd, (sockaddr *) &servaddr, sizeof(servaddr)) == -1) {
        LOG(FATAL) << "Socket bind error.";
        exit(0);
    }

    if (listen(command_socket_fd, 10) == -1) {
        LOG(FATAL) << "Listen error.";
        exit(0);
    }

    LOG(INFO) << "Init Complete. Waiting for connections";
    while (true) {
        if ((command_connection_fd = accept(command_socket_fd, (sockaddr *) NULL, NULL)) == -1) {
            LOG(FATAL) << "Accept error.";
            break;
        }

        issueCommandResponse(SERVICE_READY, SERVER_NAME + " ready.");

        bool isStopServer = false;
        current_user_authorized = false;
        current_user_ok = false;
        std::string buffer_left;

        while (true) {
            int n;
            char buffer[COMMAND_BUFFER_SIZE];
            n = (int) recv(command_connection_fd, buffer, COMMAND_BUFFER_SIZE, 0);
            buffer[n] = 0;
            buffer_left = buffer_left + buffer;
            bool outer_break = false;

            while (true) {
                unsigned long sp_pos = buffer_left.find_first_of(TCP_DELIMITER);
                if (sp_pos == std::string::npos) break;

                std::string cmd = buffer_left.substr(0, sp_pos);
                buffer_left = buffer_left.substr(sp_pos + 2);

                LOG(INFO) << cmd << " Received.";
                int returnAction = executeCommand(cmd);

                if (returnAction == 1) isStopServer = true;

                if (returnAction != 0) {
                    close(command_connection_fd);
                    outer_break = true;
                    break;
                }

            }

            if (outer_break) break;

        }

        if (isStopServer) break;
    }

    close(command_socket_fd);
    google::ShutdownGoogleLogging();
}

int ftp::Server::executeCommand(const std::string &cmd) {
    std::vector<std::string> splitResult;
    stringSplit(cmd, " ", &splitResult);

    FtpCommand ftpCommand = convertToFtpCommand(splitResult[0]);

    if (ftpCommand != USER && ftpCommand != PASS && !current_user_authorized) {
        issueCommandResponse(PERMISSION_DENIED, "Permission denied");
        return -1;
    }

    switch (ftpCommand) {
        case USER:
            processUserCommand(splitResult);
            break;
        case PASS:
            processPasswordCommand(splitResult);
            break;
        case LIST:
            processListCommand(splitResult);
            break;
        case PORT:
            processPortCommand(splitResult);
            break;
        case RETRIEVE:
            processRetrieveCommand(splitResult);
            break;
        case STORE:
            processStoreCommand(splitResult);
            break;
        case PWD:
            processPWDCommand(splitResult);
            break;
        case CWD:
            processCWDCommand(splitResult);
            break;
        case HELP:
            processHelpCommand(splitResult);
            break;
        case QUIT:
            issueCommandResponse(SERVICE_CLOSE, "goodbye!");
            return -1;
        case HALT:
            return 1;
        default:
            return -1;
    }

    return 0;
}

void ftp::Server::issueCommandResponse(ftp::FtpResponseCode code,
                                       const std::string &info) {
    std::string buffer = std::to_string((int) code) + " " + info + TCP_DELIMITER;
    LOG(INFO) << "SEND " << buffer;
    send(command_connection_fd, buffer.c_str(), buffer.size(), 0);
}

bool ftp::Server::processRetrieveCommand(const ftp::str_vec &info) {
    std::ifstream fin(FTP_BASE_DIR + working_dir + '/' + info[1], std::ios::binary);
    if (fin) {
        issueCommandResponse(DATA_CONNECTION_OPEN_TRANSFER_START, "Data connection already open. Transfer starting.");
        sendViaDataConnection(fin);
        fin.close();
        issueCommandResponse(TRANSFER_COMPLETE, "Transfer complete.");
        closeDataConnection();
    } else {
        issueCommandResponse(FILE_UNAVAILABLE, "No such file or directory.");
        closeDataConnection();
    }

    return true;
}

bool ftp::Server::processStoreCommand(const ftp::str_vec &info) {
    std::ofstream fout(FTP_BASE_DIR + working_dir + '/' + info[1], std::ios::binary);
    issueCommandResponse(DATA_CONNECTION_OPEN_TRANSFER_START, "Data connection already open. Transfer starting.");
    receiveViaDataConnection(fout);
    issueCommandResponse(TRANSFER_COMPLETE, "Transfer complete.");
    return true;
}

bool ftp::Server::processPWDCommand(const ftp::str_vec &info) {
    issueCommandResponse(PATHNAME_CREATED, "'" + working_dir + "' is the current directory.");
    return true;
}

bool ftp::Server::processCWDCommand(const ftp::str_vec &info) {
    std::string req = info[1];
    LOG(INFO) << info[1];
    LOG(INFO) << working_dir;
    if (req[0] == '/') working_dir = req;
    else {
        if (req.at(req.size() - 1) != '/') req = req + '/';

        while (req.size() != 0) {
            if (req.size() >= 2 && req[0] == '.' && req[1] == '.') {
                DirUtil::getParent(working_dir, req);
            } else if (req[0] == '.') {
                DirUtil::getCurrent(working_dir, req);
            } else {
                DirUtil::getInto(working_dir, req);
            }
        }

    }
    issueCommandResponse(FILE_COMMAND_OK, "'" + working_dir + "' is the current directory.");
    return true;
}

bool ftp::Server::processListCommand(const ftp::str_vec &info) {
    std::string lsOp = FTP_BASE_DIR + working_dir;
    if (info.size() != 1) lsOp += info[1];
    std::string lsRes = unixOperation("ls " + lsOp + " -l");
    std::istringstream lsStream(lsRes);
    sendViaDataConnection(lsStream);
    // via command connection
    issueCommandResponse(TRANSFER_COMPLETE, "Transfer complete.");
    closeDataConnection();
    return true;
}

bool ftp::Server::processPortCommand(const ftp::str_vec &info) {

    int portOp[6];
    str_vec portSplit;
    stringSplit(info[1], ",", &portSplit);

    for (int i = 0; i < 6; ++i) {
        portOp[i] = atoi(portSplit[i].c_str());
    }

    in_addr_t ipAddr = (in_addr_t) ((portOp[0] << 24) + (portOp[1] << 16) +
                                    (portOp[2] << 8) + (portOp[3]));
    in_port_t inPort = (in_port_t) ((portOp[4] << 8) + portOp[5]);

    sockaddr_in portLocation;

    memset(&portLocation, 0, sizeof(portLocation));

    portLocation.sin_family = AF_INET;
    portLocation.sin_port = htons(inPort);
    portLocation.sin_addr.s_addr = htonl(ipAddr);
    openDataConnection(portLocation);

    issueCommandResponse(COMMAND_OK, "Active data connection established.");

    return true;
}

ftp::Server::Server() {
    command_connection_fd = -1;
    command_socket_fd = -1;
    data_socket_fd = -1;

    current_user_authorized = false;
    current_user_ok = false;
    working_dir = "/";
}

void ftp::Server::openDataConnection(const sockaddr_in &sock_addr) {

    if ((data_socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        LOG(FATAL) << "Create data socket error!";
        exit(0);
    }

    if (connect(data_socket_fd, (sockaddr *) &sock_addr, sizeof(sock_addr)) < 0) {
        LOG(WARNING) << "Failed to connect to client via data link.";
        return;
    }

}

void ftp::Server::closeDataConnection() {
    if (data_socket_fd == -1) return;
    close(data_socket_fd);
}

std::string ftp::Server::unixOperation(const std::string& command) {
    FILE *fstream = popen(command.c_str(), "r");
    char buff[UNIX_OPERATION_BUFFER];
    memset(buff, 0, sizeof(char) * UNIX_OPERATION_BUFFER);
    fread(buff, UNIX_OPERATION_BUFFER, 1, fstream);
    pclose(fstream);
    return std::string(buff);
}

bool ftp::Server::processUserCommand(const ftp::str_vec &info) {
    if (info[1] == ADMIN_NAME) {
        issueCommandResponse(USER_NAME_OK_NEED_PASS, "Username ok, send password.");
        current_user_ok = true;
        return true;
    } else {
        issueCommandResponse(PERMISSION_DENIED, "No such user.");
    }
    return false;
}

bool ftp::Server::processPasswordCommand(const ftp::str_vec &info) {
    if (!current_user_ok) return false;
    if (info[1] == ADMIN_PASS) {
        issueCommandResponse(WELCOME, "welcome, admin!");
        current_user_authorized = true;
        return true;
    }
    issueCommandResponse(PERMISSION_DENIED, "Permission denied");
    return false;
}

void ftp::Server::sendViaDataConnection(std::istream &istream) {

    LOG(INFO) << "Start transferring data";

    fileTrunk* ft = new fileTrunk();
    ft->size = htonl(FILE_TRANSFER_BUFFER);
    istream.seekg(0, istream.beg);

    while (true) {
        istream.read(ft->payload, FILE_TRANSFER_BUFFER);
        if (istream.eof()) {
            unsigned int sendSize = (unsigned int) istream.gcount();
            LOG(INFO) << sendSize;
            ft->size = htonl(sendSize);
            send(data_socket_fd, ft, sendSize + 4, 0);
            break;
        }
        send(data_socket_fd, ft, FILE_TRANSFER_BUFFER + 4, 0);
    }

    delete ft;

    LOG(INFO) << "Data transfer complete.";

}

void ftp::Server::receiveViaDataConnection(std::ostream &ostream) {

    fileTrunk* ft = new fileTrunk();

    unsigned int sizeToRead;
    do {
        recv(data_socket_fd, ft, 4, 0);
        sizeToRead = ntohl(ft->size);

        unsigned int leftSizeToRead = sizeToRead;
        unsigned int payloadOffset = 0;

        while (leftSizeToRead != 0) {
            unsigned int realSizeRead = recv(data_socket_fd,
                                             ft->payload + payloadOffset, leftSizeToRead, 0);
            leftSizeToRead -= realSizeRead;
            payloadOffset += realSizeRead;
        }

        ostream.write(ft->payload, sizeToRead);
    } while (sizeToRead == FILE_TRANSFER_BUFFER);

    delete ft;
}

bool ftp::Server::processHelpCommand(const ftp::str_vec &info) {
    issueCommandResponse(HELP_MESSAGE, FTP_HELP_MSG);
    return false;
}
