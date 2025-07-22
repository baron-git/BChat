/* 
    Author: Michael Behrens - 113504382
    CS 4173 - Project
 */

#include "third-party/naett/naett.h" // naett: HTTP client library
#include "third-party/des/des.h" // DES encryption/decryption
#include "third-party/tiny-AES-c/aes.h" // AES encryption/decryption
#include "third-party/monocypher/src/monocypher.h" // Monocypher: Cryptographic library for encryption/decryption (used for key exchange)
#include "third-party/civetweb/include/civetweb.h" // CivetWeb: Web server library
#include "third-party/randombytes/randombytes.h" // Random bytes generation

#define LIBCMDF_IMPL
#include "third-party/libcmdf/libcmdf.h" // Command line argument parsing

#include <stdio.h>

#define INTRO "BChat\n" \
	"Next generation chat application.\n\n" \
    "Type 'help' for a list of commands.\n"
#define LOGIN_HELP "Login as your user.\n" \
                       "Usage: login <user>\n" \
                       "Users: alice, bob, charlie \n"
#define CHAT_HELP "Chat with another user.\n" \
                       "Usage: chat <user> \n"
#define ALGO_HELP "Select an algorithm for encryption/decryption.\n" \
                       "Usage: algo <algo>\n" \
                       "Algorithms: des, aes\n"


const char *user = NULL; // Global variable to store the logged-in user
int logged_in = 0; // Flag to check if a user is logged in, 0 = not logged in, 1 = logged in
int first_time = 1; // Flag to check if it's the user's first time logging in, 0 = returning user, 1 = first time user
const char *algo = NULL; // Global variable to store the selected algorithm
const uint8_t their_pk[32]; /* Their public key */
uint8_t your_sk[32]; /* Your secret key */
uint8_t your_pk[32]; /* Your public key */
uint8_t shared_secret[32]; /* Shared secret (NOT a key) */

int check_user_firsttime(const char *username) {
    // check if the user is logging in for the first time
    // return 1 if first time, 0 otherwise
    
    return 1; 
}

static CMDF_RETURN do_login(cmdf_arglist *arglist) {
    // check if the user provided exactly one argument
    if (arglist->count != 1) {
        printf("Usage: login <user>\n");
        return CMDF_ERROR_ARGUMENT_ERROR;
    }

    // check if the user is one of the valid users
    const char *username = arglist->args[0];
    if (strcmp(username, "alice") != 0 && 
        strcmp(username, "bob") != 0 && 
        strcmp(username, "charlie") != 0) {
        printf("Unknown user, valid users are: alice, bob, charlie.\n");
        return CMDF_ERROR_ARGUMENT_ERROR;
    }

    // if the user is valid, proceed with login
    user = strdup(username); // store the username in the global variable
    logged_in = 1; // set the logged-in flag to 1
    // check if the user is logging in for the first time
    if (check_user_firsttime(username)) {
        // first time login
        printf("Welcome %s! This is your first time logging in.\n", username);
    } else {
        // returning user
        printf("Welcome back %s!\n", username);
        first_time = 0; // set the first time flag to 0
    }

    return CMDF_OK;
}

static CMDF_RETURN do_algo(cmdf_arglist *arglist) {
    // check if the user is logged in
    if (!logged_in) {
        printf("You must be logged in to use this command.\n");
        return CMDF_ERROR_ARGUMENT_ERROR;
    }

    // check if the user provided exactly one argument
    if (arglist->count != 1) {
        printf("Usage: algo <algo>\n");
        return CMDF_ERROR_ARGUMENT_ERROR;
    }

    const char *algo = arglist->args[0];
    if (strcmp(algo, "des") == 0) {
        // DES encryption/decryption
        printf("Using DES algorithm.\n");
        algo = "des"; // store the selected algorithm in the global variable
    } else if (strcmp(algo, "aes") == 0) {
        // AES encryption/decryption
        printf("Using AES algorithm.\n");
        algo = "aes"; // store the selected algorithm in the global variable
    } else {
        printf("Unknown algorithm. Supported algorithms: des, aes.\n");
        return CMDF_ERROR_ARGUMENT_ERROR;
    }

    return CMDF_OK;
}

static CMDF_RETURN do_chat(cmdf_arglist *arglist) {
    // check if the user is logged in
    if (!logged_in) {
        printf("You must be logged in to use this command.\n");
        return CMDF_ERROR_ARGUMENT_ERROR;
    }
    
    // check if the user provided exactly one argument
    if (arglist->count != 1) {
        printf("Usage: chat <user>\n");
        return CMDF_ERROR_ARGUMENT_ERROR;
    }

    // check if the user is one of the valid users
    const char *chat_user = arglist->args[0];
    if (strcmp(chat_user, "alice") != 0 &&
        strcmp(chat_user, "bob") != 0 &&
        strcmp(chat_user, "charlie") != 0) {
        printf("Unknown user, valid users are: alice, bob, charlie.\n");
        return CMDF_ERROR_ARGUMENT_ERROR;
    }

    // if the user is valid, proceed with chat
    if (strcmp(chat_user, user) == 0) {
        printf("You cannot chat with yourself!\n");
        return CMDF_ERROR_ARGUMENT_ERROR;
    }

    printf("Attempting to establish chat connection with %s...\n", chat_user);
    

    return CMDF_OK;
}


static int handler(struct mg_connection *conn, void *ignored) {
	const char *msg = "Hello world";
	unsigned long len = (unsigned long)strlen(msg);

	mg_send_http_ok(conn, "text/plain", len);
    struct mg_request_info *ri = mg_get_request_info(conn);

	mg_write(conn, msg, len);

	return 200; /* HTTP state 200 = OK */
}

uint64_t uint8_to_uint64(const uint8_t *bytes) {
    uint64_t value = 0;
    for (int i = 0; i < 8; i++) {
        value = (value << 8) | bytes[i];
    }
    return value;
}

uint64_t des_test_encrypt(uint64_t key, uint64_t input) {
    // Test the DES encryption
    uint64_t encrypted = des(input, key, 'e');
    printf("DES Encryption:\n");
    printf("Input: 0x%016llx\n", input);
    printf("Key: 0x%016llx\n", key);
    printf("Encrypted: 0x%016llx\n", encrypted);
    return encrypted;
}

uint64_t des_test_decrypt(uint64_t key, uint64_t input) {
    // Test the DES decryption
    uint64_t decrypted = des(input, key, 'd');
    printf("DES Decryption:\n");
    printf("Input: 0x%016llx\n", input);
    printf("Key: 0x%016llx\n", key);
    printf("Decrypted: 0x%016llx\n", decrypted);
    return decrypted;
}


int main(void) {
    uint8_t key[8];
    int ret = randombytes(&key[0], sizeof(key));
    if (ret != 0) {
        printf("Error in 'randombytes'\n");
    }
    uint64_t key64 = 0;

    for (int i = 0; i < 8; i++) {
        key64 = (key64 << 8) | key[i];
    }
    
    uint64_t input = 0x0123456789abcdef; // Example input for DES encryption/decryption
    uint64_t encrypted = des_test_encrypt(key64, input);
    uint64_t decrypted = des_test_decrypt(key64, encrypted);

    // initialize the command line interface
    cmdf_init("BChat> ", INTRO, NULL, NULL, 0, 1);

    // register our custom commands
    cmdf_register_command(do_login, "login", LOGIN_HELP);
    cmdf_register_command(do_algo, "algo", ALGO_HELP);
    cmdf_register_command(do_chat, "chat", CHAT_HELP);


    // start http server
    struct mg_context *ctx;
    mg_init_library(0);
    ctx = mg_start(NULL, 0, NULL);
    mg_set_request_handler(ctx, "/chat", handler, "Hello world");

    cmdf_commandloop();

    mg_stop(ctx);
    mg_exit_library();
    return 0;
}
