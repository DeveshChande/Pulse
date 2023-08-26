pulse: main.o
	gcc main.o -o pulse

main.o: main.c
	gcc main.c -Werror -std=c17 -I . -c

clean:
	rm main.o pulse