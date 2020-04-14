#include <string>
#include <cstring>
#include <boost/thread.hpp>
#include "fs_server.h"
#include <unordered_map>
#include <unordered_set>
#include <iostream>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sstream>
// #include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> 
extern boost::mutex cout_lock;
boost::mutex listen_sock_lock;
boost::mutex users_lock;


std::unordered_map<std::string, std::string> users;
std::unordered_map<unsigned, unsigned> session_seq;
std::unordered_set<unsigned> avail_disk_blocks;
unsigned session_num = 0;
int server_port = 0;
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
    int listen_sock = create_listen_socket(server_port);
    if (listen_sock == -1)
    {
        cout_lock.lock();
        std::cout << "Failed to create listening socket" << std::endl;
        cout_lock.unlock();
    }
    // Start to listen to requests. Queue size is 30.
    listen(listen_sock, 30);

    // Cout the port number
    cout_lock.lock();
    std::cout << "\n@@@ port " << server_port << std::endl;
    cout_lock.unlock();

    // Serve the requests
    while (true)
    {
        boost::lock_guard<boost::mutex> lock(listen_sock_lock);
        // Create connection
        int connect_sock = accept(listen_sock, 0, 0);
        if (connect_sock == -1) continue; // If the connection fails, ignore this request
        //Boost create thread to handle the request
        boost::thread worker_thread(handle_request, connect_sock);
        worker_thread.detach();
    }


    close(listen_sock);
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
    socklen_t len = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(server_port);
    if (bind(socket_fd, (struct sockaddr*) &addr, len) == -1) return -1;

    // Get the port we actually use. Set the server_port var if necessary
    if (getsockname(socket_fd, (struct sockaddr*) &addr, &len) == -1)
        return -1;
    else 
        server_port = ntohs(addr.sin_port);
    return socket_fd;
}

int handle_request(int connect_sock){
    // Handle the connection
    std::string data;
    char buf[1];
    do{
        int n = recv(connect_sock, buf, sizeof(buf), 0);
        data += buf[0];
    } while (buf[0] != '\0');
    
    std::stringstream ss(data);
    std::string user;
    unsigned request_size;
    ss >> user >> request_size;
    //Error handling: check header correctness
    char request_buf[request_size];
    char request_buf_decrpt[request_size];
    recv(connect_sock, request_buf, sizeof(request_buf), MSG_WAITALL );
    // Error handling: if no user. Need lock on map?
    users_lock.lock();
    int decrypted_len = fs_decrypt(users[user].c_str(), (void*) request_buf, request_size, request_buf_decrpt);
    users_lock.unlock();
    //Error handling: fail to decrypt
    std::string request_data(request_buf_decrpt, decrypted_len);
    std::stringstream request_ss(request_data);
    std::string request_type;
    unsigned session, seq;
    request_ss >> request_type >> session >> seq;
    if (request_type == "FS_SESSION")
    {

    }
    else if (request_type == "FS_READBLOCK")
    {

    }
    else if (request_type == "FS_WRITEBLOCK")
    {

    }
    else if (request_type == "FS_CREATE")
    {

    }
    else if (request_type == "FS_DELETE")
    {

    }
}

int handle_session(const string& user, unsigned seq)
{
    
}