pulse: main.o
	gcc main.o -lcrypto -lcurl -lcmocka -o pulse

main.o: main.c
	gcc main.c -Werror -std=c17 -c -I .

clean:
	rm main.o pulse
