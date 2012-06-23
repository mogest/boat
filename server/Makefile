CFLAGS=-Wall -Wno-deprecated-declarations
LDLIBS=-levent -levent_openssl -lssl -lcrypto

all: boatd

boatd: boatd.o client_data.o commands.o configuration.o utils.o

clean:
	rm -f *.o boatd
