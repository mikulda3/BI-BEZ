CC = g++
CFLAGS = -g
LDFLAGS = -lcrypto

all: task3

task3: task3.o
	$(CC) -o $@ $< $(LDFLAGS)
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)
clean:
	rm task3
	rm task3.o
run:
	./task3 -e cbc Mad_scientist.tga
	./task3 -e ecb Mad_scientist.tga
	./task3 -d cbc Mad_scientist_cbc.tga
	./task3 -d ecb Mad_scientist_ecb.tga