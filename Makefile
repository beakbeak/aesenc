CFLAGS += -Wall -Werror
deps = openssl

CFLAGS += $(shell pkg-config --cflags ${deps})
LDFLAGS += $(shell pkg-config --libs ${deps})

.PHONY: all
all: aesdec aesenc

aesenc: aesenc.c
	${CC} -o aesenc aesenc.c ${CFLAGS} ${LDFLAGS} 

aesdec: aesdec.c
	${CC} -o aesdec aesdec.c ${CFLAGS} ${LDFLAGS} 

clean:
	rm -f aesenc aesdec
