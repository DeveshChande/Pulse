CFLAGS = -Werror -Wall -Wextra -Wconversion -Wsign-conversion -Wcast-align -Wformat=2 -Wformat-security -fno-common -fstack-protector-all -Wmissing-prototypes -Wmissing-declarations -Wstrict-prototypes -Wunreachable-code -std=c17 -I headers/ -g -c

LDFLAGS = -fsanitize=address -lcrypto -lcurl -lcmocka -o pulse

pulse: main.o
	gcc main.o $(LDFLAGS)

main.o: main.c
	gcc main.c $(CFLAGS)

clean:
	rm main.o pulse
