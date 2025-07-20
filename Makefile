CFLAGS = -g -Wall -pedantic
#CFLAGS = -O2

ifeq ($(OS),Windows_NT)
	LDFLAGS = -lwinhttp
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Darwin)
		LDFLAGS = -framework Foundation
		CFLAGS += -Wno-gnu-zero-variadic-macro-arguments
	else ifeq ($(UNAME_S),Linux)
		LDFLAGS = -lcurl -lpthread
	endif
endif

CFLAGS += -Ithird-party/civetweb/include

BChat: main.c third-party/naett/naett.c third-party/civetweb/src/civetweb.c third-party/Monocypher/src/monocypher.c
	gcc $^ -o $@ $(CFLAGS) $(LDFLAGS)
