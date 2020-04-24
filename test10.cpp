#include <iostream>
#include <cstdlib>
#include "fs_client.h"
#include <string>
#include <cstring>
using std::cout;

int main(int argc, char *argv[])

{
    char *server;
    int server_port;
    unsigned int session, seq=0;

    const char *writedata = "We hold these truths to be self-evident, that all men are created equal, that they are endowed by their Creator with certain unalienable Rights, that among these are Life, Liberty and the pursuit of Happiness. -- That to secure these rights, Governments are instituted among Men, deriving their just powers from the consent of the governed, -- That whenever any Form of Government becomes destructive of these ends, it is the Right of the People to alter or to abolish it, and to institute new Government, laying its foundation on such principles and organizing its powers in such form, as to them shall seem most likely to effect their Safety and Happiness.";

    // char readdata[FS_BLOCKSIZE];

    if (argc != 3) {
        cout << "error: usage: " << argv[0] << " <server> <serverPort>\n";
        exit(1);
    }
    server = argv[1];
    server_port = atoi(argv[2]);
    fs_clientinit(server, server_port);
    fs_session("user1", "password1", &session, seq++);
    for(unsigned i = 0; i <  30; i++){
        std::string pathname = "/dir" + std::to_string(i);
        fs_create("user1", "password1", session, seq++, pathname.c_str(), 'd');
    }
    for(unsigned i = 5; i <  10; i++){
        std::string pathname = "/dir" + std::to_string(i);
        fs_delete("user1", "password1", session, seq++, pathname.c_str());
    }
    for(unsigned i = 5; i <  10; i++){
        std::string pathname = "/dir" + std::to_string(i);
        fs_create("user1", "password1", session, seq++, pathname.c_str(), 'f');
    }
    for(unsigned i = 8; i <  16; i++){
        std::string pathname = "/dir" + std::to_string(i);
        fs_delete("user1", "password1", session, seq++, pathname.c_str());
    }
    char entries[FS_BLOCKSIZE];
    memset(entries,0,FS_BLOCKSIZE);
    char fname[] = "Thisisafakedir\0";
    memcpy(entries, fname, 60);
    // *((uint32_t *)(entries + 60)) = 4095;
    fs_writeblock("user1", "password1", session, seq++, "/dir5",0, entries);
    fs_writeblock("user1", "password1", session, seq++, "/dir5",1, writedata);
    fs_writeblock("user1", "password1", session, seq++, "/dir5",2, writedata);
    return 0;
}
