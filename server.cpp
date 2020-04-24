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
#include <vector>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> 
#include <vector>
extern boost::mutex cout_lock;
boost::mutex listen_sock_lock;
boost::mutex users_lock;
boost::mutex session_seq_lock;
boost::mutex avail_block_lock;
boost::mutex user_session_lock;
std::vector<boost::shared_mutex *> fs_mutex_vec;
std::unordered_map<std::string, std::unordered_set<unsigned> > user_session;
std::unordered_map<std::string, std::string> users;
std::unordered_map<unsigned, unsigned> session_seq;
std::unordered_set<unsigned> avail_disk_blocks;
unsigned session_num = 0;
int server_port = 0;

int filename_check(std::string pathname){
    bool root = true;
    if( pathname.size() > FS_MAXPATHNAME )
        return -1;
    if(pathname == "" || pathname[0] != '/' || pathname[pathname.size()-1] == '/')
        return -1;
    while(pathname.find('/') != std::string::npos){
        std::string next_level = pathname.substr(0, pathname.find('/'));
        if (next_level.size() > FS_MAXFILENAME || (!root && next_level == ""))
            return -1;
        if(root)
            root = false;
        pathname = pathname.substr(pathname.find('/')+1);
    }
    if (pathname.size() > FS_MAXFILENAME)
            return -1;
    return 0;
}

unsigned find_avail_blocks(){
    for(unsigned avail_block_num = 1; avail_block_num < FS_DISKSIZE; avail_block_num++){
        if( avail_disk_blocks.find(avail_block_num) != avail_disk_blocks.end())
            return avail_block_num;
    }
    return 0;
}

void get_fs_init_blocks( unsigned curr_inode_block ){
    fs_inode curr_inode;
    disk_readblock(curr_inode_block, &curr_inode);
    if( curr_inode.type == 'f' ){
        for( unsigned i = 0; i < curr_inode.size; i++ )
            avail_disk_blocks.erase( curr_inode.blocks[i] );
    }else if(curr_inode.type == 'd'){
        for( unsigned i = 0; i < curr_inode.size; i++ ){
            avail_disk_blocks.erase( curr_inode.blocks[i] );
            fs_direntry entries[FS_BLOCKSIZE/sizeof(fs_direntry)];
            disk_readblock( curr_inode.blocks[i], entries );
            for( unsigned j = 0; j < FS_BLOCKSIZE/sizeof(fs_direntry); j++){
                if( entries[j].inode_block != 0){
                    avail_disk_blocks.erase( entries[j].inode_block );
                    get_fs_init_blocks( entries[j].inode_block );
                }
            }   
        }
    }
}
// Return -1 on failure, socket_fd on success
int create_listen_socket(int& server_port)
{
    // Create and set socket
    const int opt = 1;
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) return -1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt , sizeof(opt)) == -1) return -1;

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

void send_response( std::string& response, const std::string& user, unsigned connect_sock ){
    unsigned size_decrypt = response.size();
    char encrypt_buf[2*size_decrypt + 64];
    int size_encrypt = fs_encrypt(users[user].c_str(), response.c_str(), size_decrypt, encrypt_buf);
    char header_buf[size_encrypt + 1];
    std::string response_header = std::to_string(size_encrypt) + '\0';
    strcpy(header_buf, response_header.c_str());
    header_buf[size_encrypt] = '\0';
    send(connect_sock, response_header.c_str(), response_header.size(), MSG_NOSIGNAL);
    send(connect_sock, encrypt_buf, size_encrypt, MSG_NOSIGNAL);
    close(connect_sock);
}

int find_target_block(std::string pathname, std::string& user, fs_inode& curr_inode , unsigned& curr_block, unsigned& prev_block){
    while(pathname != ""){
        std::string next_level_name = pathname.substr(0, pathname.find('/'));
        pathname = pathname.substr(pathname.find('/') + 1);
        bool path_found = false;
        fs_mutex_vec[curr_block]->lock_shared();
        // std::cout << "LOCKED : " << curr_block <<std::endl;
        if(curr_block){
            fs_mutex_vec[prev_block]->unlock_shared();
            // std::cout << "UNLOCKED : " << prev_block <<std::endl;
        }
        disk_readblock(curr_block, &curr_inode);
        //invalid owner
        if( std::string(curr_inode.owner) != "" 
        && std::string(curr_inode.owner) != user ){
            // std::cout << user << std::string(curr_inode.owner) <<std::endl;
            fs_mutex_vec[curr_block]->unlock_shared();
            return -1;
        }
        for( unsigned i = 0; i < curr_inode.size; i++ ){
            fs_direntry entries[FS_BLOCKSIZE/sizeof(fs_direntry)];
            disk_readblock(curr_inode.blocks[i], entries);
            for ( unsigned j = 0; j < FS_BLOCKSIZE/sizeof(fs_direntry); j++){
                if( !entries[j].inode_block )
                    continue;
                if( !strcmp(entries[j].name, next_level_name.c_str())){
                    prev_block = curr_block;
                    curr_block = entries[j].inode_block;
                    path_found = true;
                    break;
                }
            }
            if(path_found)
                break;
        }
        if(!path_found){
            fs_mutex_vec[curr_block]->unlock_shared();
            // std::cout << "UNLOCKED : " << curr_block <<std::endl;
            // std::cout << "here " << curr_block <<std::endl;
            return -1;
        }
    }
    return 0;
}

int fs_read_handler(std::string pathname, std::string& user, unsigned target_block, unsigned session, unsigned seq, int connect_sock){
    if (pathname == "/")
        return -1;
    pathname = pathname.substr(pathname.find('/') + 1);
    pathname += '/';
    unsigned curr_block = 0;
    unsigned prev_block = 0;
    fs_inode curr_inode;
    char read_buf[FS_BLOCKSIZE];
    memset(read_buf, 0, FS_BLOCKSIZE);
    if(find_target_block(pathname, user, curr_inode, curr_block, prev_block) < 0) return -1;
    {
        boost::shared_lock<boost::shared_mutex> read_lock(*fs_mutex_vec[curr_block]);
        fs_mutex_vec[prev_block]->unlock_shared();
        disk_readblock(curr_block, &curr_inode);
        if (curr_inode.type != 'f'){
            cout_lock.lock();
            std::cout << "ERROR: READING FROM NON-FILE TYPE" << std::endl;
            cout_lock.unlock();
            return -1;
        }
        if ( target_block >= curr_inode.size ){
            cout_lock.lock();
            std::cout << "ERROR: READING OUTOFRANGE" << std::endl;
            cout_lock.unlock();
            return -1;
        }
        if ( user != std::string(curr_inode.owner) ){
            cout_lock.lock();
            std::cout << "ERROR: READING NO PERMISSION" << std::endl;
            cout_lock.unlock();
            return -1;
        }
        disk_readblock(curr_inode.blocks[target_block], (void*) read_buf );
    }
    std::string response = std::to_string(session) + ' ' + std::to_string(seq) + '\0' + std::string(read_buf, FS_BLOCKSIZE);
    send_response(response, user, connect_sock);
    return 0;
}

int fs_write_handler(const std::string& text, std::string pathname, std::string& user, unsigned target_block, unsigned session, unsigned seq, int connect_sock){
    if(pathname == "/")
        return -1;
    pathname = pathname.substr(pathname.find('/') + 1);
    pathname += '/';
    unsigned curr_block = 0;
    unsigned prev_block = 0;
    fs_inode curr_inode;
    char write_buf[FS_BLOCKSIZE];
    memset(write_buf, 0, FS_BLOCKSIZE);
    memcpy(write_buf, text.c_str(), text.size());
    if(find_target_block(pathname, user, curr_inode, curr_block, prev_block) < 0) return -1;
    {
        boost::unique_lock<boost::shared_mutex> write_lock(*fs_mutex_vec[curr_block]);
        fs_mutex_vec[prev_block]->unlock_shared();
        disk_readblock(curr_block, &curr_inode);
        if (curr_inode.type != 'f'){
            cout_lock.lock();
            std::cout << "ERROR: WRITING TO NON-FILE TYPE" << std::endl;
            cout_lock.unlock();
            return -1;
        }
        if ( user != std::string(curr_inode.owner) ){
            cout_lock.lock();
            std::cout << "ERROR: WRITING NO PERMISSION" << std::endl;
            cout_lock.unlock();
            return -1;
        }
        if (target_block < curr_inode.size)
            disk_writeblock(curr_inode.blocks[target_block], (void*) write_buf );
        else{
            if(curr_inode.size >= FS_MAXFILEBLOCKS || curr_inode.size != target_block ){
                cout_lock.lock();
                std::cout << "ERROR: INVALID OFFSET OR CURR FILE FULL" << std::endl;
                cout_lock.unlock();
                return -1;
            }
            boost::unique_lock<boost::mutex> block_lock(avail_block_lock);
            unsigned avail_block_num = find_avail_blocks();
            if( !avail_block_num ){
                cout_lock.lock();
                std::cout << "ERROR: NO SPACE" <<std::endl;
                cout_lock.unlock();
                return -1;
            }
            curr_inode.blocks[target_block] = avail_block_num;
            disk_writeblock(curr_inode.blocks[curr_inode.size++], (void*) write_buf );
            disk_writeblock(curr_block, (void*) &curr_inode );
            avail_disk_blocks.erase(avail_block_num);
        }
    }
    std::string response = std::to_string(session) + ' ' + std::to_string(seq) + '\0';
    send_response(response, user, connect_sock);
    return 0;
}

int fs_create_handler(std::string pathname, std::string& user, char type, unsigned session, unsigned seq, int connect_sock){
    if(pathname == "/")
        return -1;
    std::string new_name = pathname.substr(pathname.rfind('/') + 1);
    pathname = pathname.substr(0, pathname.rfind('/'));
    pathname = pathname.substr(pathname.find('/') + 1);
    if(pathname != "")
        pathname += '/';
    unsigned curr_block = 0;
    unsigned prev_block = 0;
    //init new dir or file
    fs_inode new_dirorfile;
    strcpy(new_dirorfile.owner, user.c_str());
    new_dirorfile.type = type;
    new_dirorfile.size = 0;
    //init completed
    fs_inode curr_inode;
    if(find_target_block(pathname, user, curr_inode, curr_block, prev_block) < 0) return -1;
    // std::cout << "ACQUIRE LOCK:" << curr_block << std::endl; 
    {
        boost::unique_lock<boost::shared_mutex> write_lock(*fs_mutex_vec[curr_block]);
        // std::cout << "ACQUIRE LOCK SUCCESS:" << curr_block << std::endl; 
        if(curr_block)
            fs_mutex_vec[prev_block]->unlock_shared();
        disk_readblock(curr_block, &curr_inode);
        if ( std::string(curr_inode.owner) != "" && user != std::string(curr_inode.owner) ){
            cout_lock.lock();
            std::cout << "ERROR: CREATE NO PERMISSION" << std::endl;
            cout_lock.unlock();
            return -1;
        }
        bool file_create = false;
        unsigned entries_index;
        unsigned curr_inode_index;
        fs_direntry tmp_buf[FS_BLOCKSIZE/sizeof(fs_direntry)];
        memset(tmp_buf, 0, FS_BLOCKSIZE );
        for( unsigned i = 0; i < curr_inode.size; i++){
            fs_direntry entries[FS_BLOCKSIZE/sizeof(fs_direntry)];
            disk_readblock(curr_inode.blocks[i], entries);
            for ( unsigned j = 0; j < FS_BLOCKSIZE/sizeof(fs_direntry); j++){
                if( entries[j].inode_block && !strcmp(entries[j].name, new_name.c_str())){
                    cout_lock.lock();
                    std::cout << "ERROR: FILE ALREADY EXISTS" <<std::endl;
                    cout_lock.unlock();
                    return -1;
                }
                if( !entries[j].inode_block  && !file_create){
                    memcpy(tmp_buf, entries, FS_BLOCKSIZE);
                    curr_inode_index = i;
                    entries_index = j;
                    file_create = true;
                }
            }
        }
        if( file_create ){
            boost::unique_lock<boost::mutex> block_lock(avail_block_lock);
            unsigned avail_block_num = find_avail_blocks();
            if( !avail_block_num ){
                cout_lock.lock();
                std::cout << "ERROR: NO SPACE" <<std::endl;
                cout_lock.unlock();
                return -1;
            }
            tmp_buf[entries_index].inode_block = avail_block_num;
            disk_writeblock(avail_block_num, &new_dirorfile);
            memset(tmp_buf[entries_index].name, 0, sizeof(tmp_buf[entries_index].name));
            strcpy(tmp_buf[entries_index].name, new_name.c_str());
            disk_writeblock(curr_inode.blocks[curr_inode_index], tmp_buf);
            avail_disk_blocks.erase(avail_block_num);
        }
        if ( !file_create && curr_inode.size >= FS_MAXFILEBLOCKS)
            return -1;
        else if( !file_create){
            fs_direntry new_entries[FS_BLOCKSIZE/sizeof(fs_direntry)];
            memset(new_entries, 0, FS_BLOCKSIZE);
            boost::unique_lock<boost::mutex> block_lock(avail_block_lock);
            if( avail_disk_blocks.size() < 2 ){
                cout_lock.lock();
                std::cout << "ERROR:CREATE (CASE 2) NO SPACE" <<std::endl;
                cout_lock.unlock();
                return -1;
            }
            unsigned avail_block_num = find_avail_blocks();
            new_entries[0].inode_block = avail_block_num;
            // assert(avail_block_num != 0);
            avail_disk_blocks.erase(avail_block_num);
            unsigned parent_block_num = find_avail_blocks();
            // assert(parent_block_num != 0);
            avail_disk_blocks.insert(avail_block_num);
            strcpy(new_entries[0].name, new_name.c_str());
            curr_inode.blocks[curr_inode.size++] = parent_block_num;
            disk_writeblock(new_entries[0].inode_block, &new_dirorfile);
            disk_writeblock(parent_block_num, new_entries);
            disk_writeblock(curr_block, &curr_inode);
            avail_disk_blocks.erase(avail_block_num);
            avail_disk_blocks.erase(parent_block_num);
        }
    }
    std::string response = std::to_string(session) + ' ' + std::to_string(seq) + '\0';
    send_response(response, user, connect_sock);
    return 0;
}

int fs_delete_handler(std::string pathname, std::string& user, unsigned session, unsigned seq, int connect_sock){
    if(pathname == "/")
        return -1;
    std::string delete_name = pathname.substr(pathname.rfind('/') + 1);
    pathname = pathname.substr(0, pathname.rfind('/'));
    pathname = pathname.substr(pathname.find('/') + 1);
    if(pathname != "")
        pathname += '/';
    unsigned curr_block = 0;
    unsigned delete_block = 0;
    unsigned prev_block = 0;
    fs_inode curr_inode;
    fs_inode to_delete_inode;
    if(find_target_block(pathname, user, curr_inode, curr_block, prev_block) < 0) return -1;
    // std::cout << "ACQUIRE LOCK " << curr_block << std::endl;
    {
        boost::unique_lock<boost::shared_mutex> write_lock1(*fs_mutex_vec[curr_block]);
        // std::cout << "ACQUIRE LOCK SUCCESS" << curr_block << std::endl;
        if(curr_block){
            // std::cout << "UNLOCK " << prev_block << std::endl;
            fs_mutex_vec[prev_block]->unlock_shared();
        }
        disk_readblock(curr_block, &curr_inode);
        bool path_found = false;
        unsigned parent_file_block_index = 0;
        unsigned delete_index = 0;
        fs_direntry entries[FS_BLOCKSIZE/sizeof(fs_direntry)];
        for( parent_file_block_index = 0; parent_file_block_index < curr_inode.size; parent_file_block_index++ ){
            disk_readblock(curr_inode.blocks[parent_file_block_index], entries);
            for ( unsigned j = 0; j < FS_BLOCKSIZE/sizeof(fs_direntry); j++){
                if( !entries[j].inode_block )
                    continue;
                if( !strcmp(entries[j].name, delete_name.c_str())){
                    delete_index = j;
                    delete_block = entries[j].inode_block;
                    path_found = true;
                    break;
                }
            }
            if(path_found)
                break;
        }
        if(!path_found) return -1;
        boost::unique_lock<boost::shared_mutex> write_lock2(*fs_mutex_vec[delete_block]);
        disk_readblock(delete_block, &to_delete_inode);
        if(to_delete_inode.type == 'd' && to_delete_inode.size)
            return -1;
        entries[delete_index].inode_block = 0;
        bool entries_empty = true;
        for ( unsigned j = 0; j < FS_BLOCKSIZE/sizeof(fs_direntry); j++){
            if (entries[j].inode_block){
                entries_empty &= false;
                break;
            }
        }
        unsigned parent_blocks = curr_inode.blocks[ parent_file_block_index ];
        // std::cout << "PARENT BLOCK" << parent_file_block_index << std::endl;
        if( entries_empty ){
            for( unsigned i = parent_file_block_index; i < curr_inode.size - 1; i++ ){
                curr_inode.blocks[ i ] = curr_inode.blocks[ i + 1 ];
            }
            curr_inode.blocks[ curr_inode.size - 1 ] = 0;
            curr_inode.size--;
            disk_writeblock(curr_block, &curr_inode);
        }else {
            disk_writeblock(parent_blocks, entries);
        }
        {
            boost::unique_lock<boost::mutex> block_lock(avail_block_lock);
            if( entries_empty )
                avail_disk_blocks.insert(parent_blocks);
            if( to_delete_inode.type == 'f' ){
                for( unsigned i = 0; i < to_delete_inode.size; i++)
                    avail_disk_blocks.insert(to_delete_inode.blocks[i]);
            }
            avail_disk_blocks.insert(delete_block);
        }
    }
    std::string response = std::to_string(session) + ' ' + std::to_string(seq) + '\0';
    send_response(response, user, connect_sock);
    return 0;
}

int session_owner_check (std::string& type, std::string& user, unsigned session, unsigned seq){
    if( type != "FS_SESSION"){
        {
            boost::unique_lock<boost::mutex> lock_user_session(user_session_lock);
            if(user_session.find(user) == user_session.end())
                return -1;
            if(user_session[user].find(session) == user_session[user].end())
                return -1;
        }
        {
            boost::unique_lock<boost::mutex> lock_seseq(session_seq_lock);
            if( session_seq.find(session) != session_seq.end() && session_seq[session] >= seq )
                return -1;
        }
    }
    return 0;
}

void handle_request(int connect_sock){
    // Handle the connection
    std::string data;
    char buf[1];
    do{
        if (recv(connect_sock, buf, sizeof(buf), 0) < 0){
            close(connect_sock);
            return;
        }
        // assert(n == 1);
        data += buf[0];
        if ( data.size() > FS_MAXUSERNAME + 1 + sizeof(int) + 1 ){
            close(connect_sock);
            return;
        }
    } while (buf[0] != '\0');
    std::stringstream ss(data);
    std::string user;
    unsigned request_size;
    ss >> user >> request_size;
    if( user + ' ' + std::to_string(request_size) + '\0' != data ){
        close(connect_sock);
        return;
    }
    unsigned MAX_REQ_SIZE = 13 + sizeof(unsigned int) + sizeof(unsigned int) 
    + FS_MAXPATHNAME + 3 + 1 + FS_BLOCKSIZE + 4;
    if ( user.size() > FS_MAXUSERNAME || request_size >  (2 * MAX_REQ_SIZE + 64) ){
        close(connect_sock);
        return;
    }
    // std::cout << "request_size "<< request_size << std::endl; 
    //Error handling: check header correctness
    char request_buf[request_size];
    char request_buf_decrpt[request_size];
    if (recv(connect_sock, request_buf, sizeof(request_buf), MSG_WAITALL ) < 0){
        close(connect_sock);
        return;
    }
    // Error handling: if no user. Need lock on map?
    {
        boost::unique_lock<boost::mutex> lock_user(users_lock);
        if(users.find(user) == users.end()){
            close(connect_sock);
            return;
        }  
    }
    int decrypted_len = fs_decrypt(users[user].c_str(), (void*) request_buf, request_size, request_buf_decrpt);
    if ( decrypted_len == -1 ){
        close(connect_sock);
        return;
    }
    //Error handling: fail to decrypt
    std::string request_data(request_buf_decrpt, decrypted_len);
    std::stringstream request_ss(request_data);
    std::string request_type;
    // std::string response = "";
    std::string reconstrunction = "";
    unsigned session, seq;
    request_ss >> request_type >> session >> seq;
    int ck1 = session_owner_check(request_type ,user, session, seq);
    // std::cout << ck1 << std::endl;
    if(ck1 < 0){
        close(connect_sock);
        return;
    }
    // std::cout<<request_type << session <<std::endl;
    if (request_type == "FS_SESSION")
    {
        reconstrunction = "FS_SESSION " + std::to_string(session) + ' ' +  std::to_string(seq) + '\0';
        if (reconstrunction != request_data){
            close(connect_sock);
            return;
        }
        //create a session lock needed?
        {
            boost::unique_lock<boost::mutex> lock_user_session(user_session_lock);
            user_session[user].insert(session_num);
        }
        std::string response;
        {
            boost::unique_lock<boost::mutex> lock_seseq(session_seq_lock);
            session_seq[session_num] = seq;
        }
        response = std::to_string(session_num++) + ' ' + std::to_string(seq) + '\0';
        //send response
        send_response(response, user, connect_sock);
    }
    else if (request_type == "FS_READBLOCK")
    {
        std::string pathname;
        unsigned block;
        request_ss >> pathname >> block;
        reconstrunction = "FS_READBLOCK " + std::to_string(session) + ' ' +
          std::to_string(seq) + ' ' + pathname + ' ' + std::to_string(block) + '\0';
        if (reconstrunction != request_data){
            close(connect_sock);
            return;
        }
        if (filename_check(pathname) < 0 || block >= FS_MAXFILEBLOCKS){
            cout_lock.lock();
            std::cout << "ERROR: INVALID PATHNAME OR BLOCK NUM" <<std::endl;
            cout_lock.unlock();
            close(connect_sock);
            return;
        }
        {
            boost::unique_lock<boost::mutex> lock_seseq(session_seq_lock);
            session_seq[session] = seq;
        }
        if( fs_read_handler(pathname, user, block, session, seq, connect_sock) == -1)
            close(connect_sock);
    }
    else if (request_type == "FS_WRITEBLOCK")
    {
        // std::cout<<session_seq[session] << " " << seq <<std::endl;
        std::string pathname;
        unsigned block;
        request_ss >> pathname >> block;
        unsigned curr_len = 13 + std::to_string(session).size() 
        + std::to_string(seq).size() + std::to_string(block).size() + pathname.size() + 4 + 1;
        std::string text = request_data.substr(curr_len, request_size - curr_len); 
        reconstrunction = "FS_WRITEBLOCK " + std::to_string(session) + ' ' +
          std::to_string(seq) + ' ' + pathname + ' ' + std::to_string(block) + '\0' + text;
        if (reconstrunction != request_data ){
            close(connect_sock);
            return;
        }
        if (filename_check(pathname) < 0 || block >= FS_MAXFILEBLOCKS || text.size() > FS_BLOCKSIZE){
            cout_lock.lock();
            std::cout << "ERROR: INVALID PATHNAME OR BLOCK NUM" <<std::endl;
            cout_lock.unlock();
            close(connect_sock);
            return;
        }
        {
            boost::unique_lock<boost::mutex> lock_seseq(session_seq_lock);
            session_seq[session] = seq;
        }
        // std::cout << text << std::endl;
        if(fs_write_handler(text, pathname, user, block, session, seq, connect_sock) == -1)
            close(connect_sock);
    }
    else if (request_type == "FS_CREATE")
    {
        // std::cout<<session_seq[session] << " " << seq <<std::endl;
        std::string pathname;
        char file_type;
        request_ss >> pathname >> file_type;
        reconstrunction = "FS_CREATE " + std::to_string(session) + ' ' +
          std::to_string(seq) + ' ' + pathname + ' ' + file_type + '\0';
        if (reconstrunction != request_data){
            close(connect_sock);
            return;
        }
        if (filename_check(pathname) < 0){
            cout_lock.lock();
            std::cout << "ERROR: INVALID PATHNAME" <<std::endl;
            cout_lock.unlock();
            close(connect_sock);
            return;
        }
        if( file_type != 'd' && file_type != 'f' ){
            close(connect_sock);
            return;
        }
        {
            boost::unique_lock<boost::mutex> lock_seseq(session_seq_lock);
            session_seq[session] = seq;
        }
        if( fs_create_handler(pathname, user, file_type, session, seq, connect_sock) == -1)
            close(connect_sock);
    }
    else if (request_type == "FS_DELETE")
    {
        std::string pathname;
        request_ss >> pathname;
        pathname = std::string(pathname.c_str());
        reconstrunction = "FS_DELETE " + std::to_string(session) + ' ' +
          std::to_string(seq) + ' ' + pathname + '\0';
        if (reconstrunction != request_data){
            close(connect_sock);
            return;
        }
        if (filename_check(pathname) < 0){
            cout_lock.lock();
            std::cout << "ERROR: INVALID PATHNAME" <<std::endl;
            cout_lock.unlock();
            close(connect_sock);
            return;
        }
        {
            boost::unique_lock<boost::mutex> lock_seseq(session_seq_lock);
            session_seq[session] = seq;
        }
        if (fs_delete_handler(pathname, user, session, seq, connect_sock ) == -1)
            close(connect_sock);
    }else{
        cout_lock.lock();
        std::cout << "ERROR: UNKNOWN REQUEST TYPE." <<std::endl;
        cout_lock.unlock();
        close(connect_sock);
        return;
    }
}


int main( int argc, char* argv[] ){
    fs_mutex_vec.resize(FS_DISKSIZE);
    for(unsigned i = 0; i < FS_DISKSIZE; i++){
        fs_mutex_vec[i] = new boost::shared_mutex;
    }
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
    //read disk blocks
    for( unsigned i = 1; i < FS_DISKSIZE; i++){
        avail_disk_blocks.insert(i);
    }
    get_fs_init_blocks(0);
    cout_lock.lock();
    std::cout << avail_disk_blocks.size() << std::endl;
    cout_lock.unlock();
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
        // boost::lock_guard<boost::mutex> lock(listen_sock_lock);
        // Create connection
        int connect_sock = accept(listen_sock, 0, 0);
        // std::cout << "accept : " << connect_sock <<std::endl;
        if (connect_sock == -1) continue; // If the connection fails, ignore this request
        //Boost create thread to handle the request
        boost::thread worker_thread(handle_request, connect_sock);
        worker_thread.detach();
    }
    close(listen_sock);
    return 0;
}

