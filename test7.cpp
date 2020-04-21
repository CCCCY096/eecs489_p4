#include <iostream>
#include <cstdlib>
#include "fs_client.h"

using std::cout;
//ERROR HANDLING TEST CASE
int main(int argc, char *argv[])

{
    char *server;
    int server_port;
    unsigned int session, seq = 0;

    const char *writedata = "We hold\0 these truths to be self-evident, that all men are created equal, that they are endowed by their Creator with certain unalienable Rights, that among these are Life, Liberty and the pursuit of Happiness. -- That to secure these rights, Governments are instituted among Men, deriving their just powers from the consent of the governed, -- That whenever any Form of Government becomes destructive of these ends, it is the Right of the People to alter or to abolish it, and to institute new Government, laying its foundation on such principles and organizing its powers in such form, as to them shall seem most likely to effect their Safety and Happiness.";

    char readdata[FS_BLOCKSIZE];
    server = argv[1];
    server_port = atoi(argv[2]);
    fs_clientinit(server, server_port);
    fs_session("user1", "password1", &session, seq++);
    fs_create("user1", "password1", session, seq++, "/admin", 'd');
    fs_create("user1", "password1", session, seq++, "/Downloads", 'd');
    fs_create("user1", "password1", session, seq++, "/Desktop", 'd');
    fs_create("user1", "password1", session, seq++, "/Pictures", 'd');
    fs_create("user1", "password1", session, seq++, "/Desktop/temp.cpp", 'f');
    fs_writeblock("user1", "password1", session, seq++, "/Desktop/temp.cpp", 0, writedata);
    fs_create("user1", "password1", session, seq++, "/Pictures/pic1", 'f');
    fs_writeblock("user1", "password1", session, seq++, "/Pictures/pic1", 0, writedata);
    fs_writeblock("user1", "password1", session, seq++, "/Pictures/pic1", 2, writedata);
    fs_writeblock("user1", "password1", session, seq++, "/Desktop/temp.cpp", 1, writedata);
    fs_writeblock("user1", "password1", session, seq++, "/Desktop/temp.cpp", 2, writedata);
    fs_readblock("user1", "password1", session, seq++, "/Pictures/pic1", 0, readdata);
    fs_readblock("user1", "password1", session, seq++, "/Pictures/pic1", 2, readdata);
    fs_create("user1", "password1", session, seq++, "/Desktop/pic1", 'f');
    for ( unsigned i = 0; i < FS_MAXFILEBLOCKS + 1 ; i++ ){
        fs_writeblock("user1", "password1", session, seq++, "/Desktop/pic1", i, writedata);
    } 
    return 0;
}