CC = gcc
INSTALL = install
DESTDIR = /usr/local/bin

CFLAGS  = -pthread -pie -fPIE -ftrapv -O2 -Wall -Wconversion -Wformat-security -Wsign-conversion -Werror -fstack-protector-all -Wstack-protector --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2
LIBS = -lyaml -lpcap -ldumbnet
LDFLAGS="-Wl,-z,relro,-z,now"

BUILD_DIR = bin
SOURCE_DIR = src
TARGET = $(BUILD_DIR)/multitap
SOURCE_FILES = $(SOURCE_DIR)/multitap.c

all: $(TARGET)

$(TARGET): $(SOURCE_FILES)
	@mkdir -p bin
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $(TARGET) $< $(LIBS)

clean:
	$(RM) $(TARGET)

install:
	$(INSTALL) $(TARGET) $(DESTDIR)
