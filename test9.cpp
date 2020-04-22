#include <iostream>
#include <cstdlib>
#include "fs_client.h"

using std::cout;
//ERROR HANDLING TEST CASE
int main(int argc, char *argv[])

{
    char *server;
    int server_port;
    unsigned int session1 = 0, session2 = 0, session3, seq = 0;

    const char *writedata = "We hold\0 these truths to be self-evident, that all men are created equal, that they are endowed by their Creator with certain unalienable Rights, that among these are Life, Liberty and the pursuit of Happiness. -- That to secure these rights, Governments are instituted among Men, deriving their just powers from the consent of the governed, -- That whenever any Form of Government becomes destructive of these ends, it is the Right of the People to alter or to abolish it, and to institute new Government, laying its foundation on such principles and organizing its powers in such form, as to them shall seem most likely to effect their Safety and Happiness.";

    char readdata[FS_BLOCKSIZE];
    server = argv[1];
    server_port = atoi(argv[2]);
    fs_clientinit(server, server_port);
    //session 1 2 created seq = 1
    fs_session("user1", "password1", &session1, 0);
    fs_session("user1", "password1", &session2, 0);
    fs_create("user1", "password1", session1, 1, "/dir", 'd');
    //invalid session, doc not created seq = 1
    fs_create("user1", "password1", 4, 0, "/doc", 'f');
    //doc should be valid
    fs_create("user1", "password1", session2, 1, "/doc", 'f');
    //seq repeated not valid
    fs_create("user1", "password1", session2, 1, "/doc", 'f');
    //file repeated not valid
    fs_create("user1", "password1", session1, 2, "/doc", 'd');

    //wrong password
    fs_session("user1", "password", &session3, 0);
    fs_create("user1", "password1", session3, 0, "/doc", 'd');

    //seq not valid
    fs_writeblock("user1", "password1", session1, 2, "/doc", 0, writedata);
    //write some data for read
    fs_writeblock("user1", "password1", session1, 3, "/doc", 0, writedata);

    //READBLOCK error test
    //path invalid
    // fs_readblock("user1", "password1", session1, 4, " doc", 0, readdata);
    fs_readblock("user1", "password1", session1, 4, "doc", 0, readdata);
    fs_readblock("user1", "password1", session1, 4, "doc/", 0, readdata);
    fs_readblock("user1", "password1", session1, 4, "/", 0, readdata);

    //path not exist
    fs_readblock("user1", "password1", session1, 4, "/doc1", 0, readdata);
    fs_readblock("user1", "password1", session1, 5, "/dir/file", 0, readdata);
    fs_readblock("user1", "password1", session1, 6, "/dir/file/stuff", 0, readdata);

    //create another file
    fs_session("user2", "password2", &session3, 0);
    fs_create("user2", "password2", session3, 1, "/game", 'f');
    fs_writeblock("user2", "password2", session3, 2, "/game", 0, writedata);

    //no permission
    fs_readblock("user1", "password1", session1, 7, "/game", 0, readdata);

    //offset out of range
    fs_readblock("user1", "password1", session1, 8, "/doc", 1, readdata);

    //WRITEBLOCK error test
    //invalid path
    fs_writeblock("user1", "password1", session1, 9, " doc", 0, writedata);
    fs_writeblock("user1", "password1", session1, 9, "doc", 0, writedata);
    fs_writeblock("user1", "password1", session1, 9, "doc/", 0, writedata);
    fs_writeblock("user1", "password1", session1, 9, "/", 0, writedata);
    //not a file
    fs_writeblock("user1", "password1", session1, 9, "/dir", 0, writedata);
    //pathname not exist
    fs_writeblock("user1", "password1", session1, 10, "/doc1", 0, writedata);
    fs_writeblock("user1", "password1", session1, 11, "/dir/file", 0, writedata);
    fs_writeblock("user1", "password1", session1, 12, "/dir/file/stuff", 0, writedata);
    //no permission
    fs_writeblock("user1", "password1", session1, 13, "/game", 0, writedata);
    //out of range
    fs_writeblock("user1", "password1", session1, 14, "/doc", 2, writedata);
    return 0;
}