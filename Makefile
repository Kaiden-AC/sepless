CC = clang
CFLAGS = -Iinclude

sepless: src/sepless.c
	$(CC) $(CFLAGS) src/sepless.c -o sepless

clean:
	rm -f sepless
