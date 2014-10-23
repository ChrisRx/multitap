# the compiler: gcc for C program, define as g++ for C++
CC = gcc
INSTALL = install
DESTDIR = /usr/local/bin

# compiler flags:
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
CFLAGS  = -pthread -g -O0 -Wall
LIBS = -lyaml -lpcap -ldnet -ldumbnet

# the build target executable:
TARGET = multitap

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c $(LIBS)

clean:
	$(RM) $(TARGET)

install:
	$(INSTALL) $(TARGET) $(DESTDIR)
