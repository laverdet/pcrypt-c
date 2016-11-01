CFLAGS += -Wno-bitwise-op-parentheses

all: pcrypt.a

pcrypt.a: pcrypt.o shuffle2.o unshuffle.o unshuffle2.o
	$(AR) rc $@ $^
	$(AR) -s $@

example: pcrypt.a example.c

clean:
	$(RM) -f pcrypt.a example *.o
