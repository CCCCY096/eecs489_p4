#include <iostream>
#include <cstdlib>
#include "fs_client.h"
#include <string>
using std::cout;
using std::cin;

int main(int argc, char *argv[])
{
    char *server;
    int server_port;
    server = argv[1];
    server_port = atoi(argv[2]);
    fs_clientinit(server, server_port);
    const char *writedata = "We hold these truths to\0 be s\0elf-evident, that all men are created equal, that they are endowed by their Creator with certain unalienable Rights, that among these are Life, Liberty and the pursuit of Happiness. -- That to secure these rights, Governments are instituted among Men, deriving their just powers from the consent of the governed, -- That whenever any Form of Government becomes destructive of these ends, it is the Right of the People to alter or to abolish it, and to institute new Government, laying its foundation on such principles and organizing its powers in such form, as to them shall seem most likely to effect their Safety and Happiness.";
    char readdata[FS_BLOCKSIZE];
    std::string request, user, password, path;
    char type;
    unsigned session, seq, offset;
    while (true){
        std::cin >> request >> user >> password >> session >> seq;
        if(request == "FS_SESSION"){
            fs_session(user.c_str(), password.c_str(), &session, seq);
            std::cout << "SESSION: " << session << "created" << std::endl;
        }else if(request == "FS_CREATE"){
            std::cin >> path >> type;
            fs_create(user.c_str(), password.c_str(), session, seq, path.c_str(), type);
        }else if(request == "FS_READBLOCK"){
             std::cin >> path >> offset;
            fs_readblock(user.c_str(), password.c_str(), session, seq, path.c_str(), offset, readdata);
        }else if(request == "FS_WRITE_BLOCK"){
            std::cin >> path >> offset;
            fs_writeblock(user.c_str(), password.c_str(), session, seq, path.c_str(), offset, writedata);
        }else if(request == "FS_DELETE"){
            std::cin >> path;
            fs_delete(user.c_str(), password.c_str(), session, seq, path.c_str());
        }   
    }
    return 0;
}