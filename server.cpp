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

    }else if( argc == 2){
        server_port = atoi(argv[1]);
    }else{
        cout_lock.lock();
        std::cout << " wrong commnad line args " << std::endl;
        cout_lock.unlock();
        exit(1);
    }

    return 0;
}