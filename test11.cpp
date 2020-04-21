#include <iostream>
#include <cstdlib>
#include "fs_client.h"

using namespace std;

int main(int argc, char *argv[])
{
    char *server;
    int server_port;
    unsigned int session, seq = 0;
    const char *writedata = "MEGALO BOX - GEARLESS JOE!!!!!!";
    char readdata[FS_BLOCKSIZE];
    if (argc != 3) {
        cout << "error: usage: " << argv[0] << " <server> <serverPort>\n";
        exit(1);
    }
    server = argv[1];
    server_port = atoi(argv[2]);
    fs_clientinit(server, server_port);

    fs_session("user1", "password1", &session, seq++);
    fs_create("user1", "password1", session, seq++, "/dir", 'd');
    fs_delete("user1", "password1", session, seq++, "/dir");
    fs_create("user1", "password1", session, seq++, "/dir", 'd');

}