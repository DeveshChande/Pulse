CFLAGS = -Werror -Wall -Wextra -Wconversion -Wsign-conversion -Wcast-align -Wformat=2 -Wformat-security -fno-common -fstack-protector-all -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes -Wunreachable-code -std=c17 -O3 -I headers/ -g -c -D DEBUG

LDFLAGS = -fsanitize=address -lcrypto -lcurl -lcmocka -o sakizuke

sakizuke: main.o
	gcc main.o $(LDFLAGS)

main.o: main.c
	gcc main.c $(CFLAGS)

clean:
	rm main.o sakizuke
