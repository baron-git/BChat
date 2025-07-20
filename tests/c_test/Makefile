CFLAGS=-ansi -pedantic -Wall -Werror -Wextra -g -O0 -D_POSIX_SOURCE -I"../.."
LDLIBS=-lreadline

ALL: compile_c_test compile_c_submenu

clean:
	rm -f c_test
	rm -f c_submenu
	rm -rf *.dSYM

c_test: c_test.c
c_submenu: c_submenu.c

compile_c_test: c_test
compile_c_submenu: c_submenu
