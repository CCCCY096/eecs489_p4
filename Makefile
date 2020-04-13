CC=g++ -g -Wall

# List of source files for your file server
FS_SOURCES=file1.cpp file2.cpp

# Generate the names of the file server's object files
FS_OBJS=${FS_SOURCES:.cpp=.o}

all: fs app

# Compile the file server and tag this compilation
fs: ${FS_OBJS} libfs_server.o
	./autotag.sh
	${CC} -o $@ $^ -lboost_thread -lboost_system -pthread -ldl

# Compile a client program
app: app.cpp libfs_client.o
	${CC} -o $@ $^

# Generic rules for compiling a source file to an object file
%.o: %.cpp
	${CC} -c $<
%.o: %.cc
	${CC} -c $<

clean:
	rm -f ${FS_OBJS} fs app
