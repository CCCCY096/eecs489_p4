#include <string>
#include <cstring>
#include <boost/thread.hpp>
#include "fs_server.h"
#include <unordered_map>
#include <unordered_set>
#include <iostream>
#include <stdlib.h>
extern boost::mutex cout_lock;

std::unordered_map<std::string, std::string> users;
std::unordered_map<unsigned, unsigned> session_seq;
std::unordered_set<unsigned> avail_disk_blocks;
unsigned session_num;
int server_port;
int main( int argc, char* argv[] ){
    std::string username, password;
    while( std::cin >> username >> password ){
        users[username] = password;
    }
    if( argc == 1 ){
        server_port = 0;
    }else if( argc == 2){
        server_port = atoi(argv[1]);
    }else{
        cout_lock.lock();
        std::cout << " wrong commnad line args " << std::endl;
        cout_lock.unlock();
        exit(1);
    }

    // Create the listening socket
    int socket_fd = create_listen_socket(server_port);
    
    return 0;
}

// Return -1 on failure, socket_fd on success
int create_listen_socket(int& server_port)
{
    // Create and set socket
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) return -1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1) return -1;

    // Pass arg to the socket
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(server_port);
    if (bind(sock, (struct sockaddr*) &addr, sizeof(addr)) == -1) return -1;

    // Get the port we actually use. Set the server_port var if necessary
    server_port = get_port_number(socket_fd);
    std::cout << "\n@@@ port " << server_port << std::endl;
    
    return socket_fd;
}