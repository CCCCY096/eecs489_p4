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
    fs_session("user2", "password2", &session3, 0);
    fs_create("user1", "password1", session1, 1, "/dir", 'd');
    //invalid session, doc not created seq = 1
    fs_create("user1", "password1", 4, 0, "/doc", 'f');

    //CREATE ERROR TEST
    //doc should be valid
    fs_create("user1", "password1", session2, 1, "/doc", 'f');
    //invalid pathname
    fs_create("user1", "password1", session2, 2, "/doc/", 'f');
    //file repeated not valid
    fs_create("user1", "password1", session1, 2, "/doc", 'd');
    //no permission
    fs_create("user2", "password2", session3, 1, "/dir/games", 'd');
    //invalid pathname
    fs_create("user1", "password1", session1, 3, "/dir/news/2020", 'f');

    fs_create("user1", "password1", session2, 3, "/desktop", 'd');

    //DELETE ERROR TEST
    //invalid path
    fs_delete("user1", "password1", session2, 4, "/");
    //path not exists
    fs_delete("user1", "password1", session2, 4, "/onedrive");
    fs_delete("user1", "password1", session2, 5, "/onedrive/eecs");
    fs_delete("user1", "password1", session2, 6, "/onedrive/eecs/eecs482");
    //no permission

    fs_delete("user1", "password1", session1, 4, "/dir");
    fs_delete("user1", "password1", session1, 5, "/doc");
    fs_delete("user1", "password1", session1, 6, "/desktop");
    return 0;

}