CC = gcc
INSTALL = install
DESTDIR = /usr/local/bin

CFLAGS  = -pthread -pie -fPIE -ftrapv -O2 -Wall -Wconversion -Wformat-security -Wsign-conversion -Werror -fstack-protector-all -Wstack-protector --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2
LIBS = -lyaml -lpcap -ldumbnet
LDFLAGS="-Wl,-z,relro,-z,now"

TARGET = multitap

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $(TARGET) $(TARGET).c $(LIBS)

clean:
	$(RM) $(TARGET)

install:
	$(INSTALL) $(TARGET) $(DESTDIR)
