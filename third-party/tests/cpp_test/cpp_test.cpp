/*
 * test.cpp - A test program for the libcmdf library, using the C++ API
 * Public domain; no warrenty applied, use at your own risk!
 * Authored by Ronen Lapushner, 2017 - 2025.
 *
 * License:
 * --------
 * This software is dual-licensed to the public domain and under the following license: 
 * you are granted a perpetual, irrevocable license to copy, modify, 
 * publish and distribute this file as you see fit.
 */

#define _CRT_SECURE_NO_WARNINGS
#define LIBCMDF_IMPL
#include "libcmdf.h"

#include <iostream>

using std::cout;
using std::endl;

#define PROG_INTRO "test - A simple test program for libcmdf.\n" \
	"You can use this as a reference on how to use the library!"
#define PRINTARGS_HELP "This is a very long help string for a command.\n" \
                       "As you can see, this is concatenated properly. It's pretty good!"

static CMDF_RETURN do_hello(cmdf_arglist *) {
    cout << "Hello, world!" << endl;

    return CMDF_OK;
}

static CMDF_RETURN do_printargs(cmdf_arglist *arglist) {
    if (!arglist) {
        cout << "No arguments provided!" << endl;
        return CMDF_OK;
    }

    cout << "Total arguments = " << arglist->count << endl;
    for (size_t i = 0; i < arglist->count; i++)
        cout << "Argument " << i <<  ": \'" << arglist->args[i] << "\'" << endl;

    cout << endl;

    return CMDF_OK;
}

int main() {
    cmdf &c = cmdf::instance();

    // This will always be true, of course, so this is here just to test out the API
    if (!c.isInitialized()) {
        c.initialize("libcmdf-test> ", PROG_INTRO);
    }

    /* Register our custom commands */
    c.registerCommand(do_hello, "hello");
    c.registerCommand(do_printargs, "printargs", PRINTARGS_HELP);

    c.commandLoop();

    return 0;
}
