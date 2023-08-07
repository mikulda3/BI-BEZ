CC = g++
CFLAGS = -g
LDFLAGS = -lcrypto

all: task2

task2: task2.o
	$(CC) -o $@ $< $(LDFLAGS)
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)
clean:
	rm task2
	rm task2.o
run:
	./task2 1