#include <stdio.h>
#include <string.h>
#include <tcp_server.h>
#include <eloop.h>

#include "password_file.h"


#define STR(x) #x
#define ROOTUSER "root"
#define ROOTPASS "toor"

typedef struct {
    eloop_t * eloop;
    size_t number_of_users;
} authenticator_t;

int main(int argc, char ** argv)
{
    int rv = -1;
    authenticator_t authenticator = {0};

    if (argc != 3)
    {
        fputs("Usage: ./authenticator_main [port] [password_file]", stderr);
        goto main_return;
    }

    tcp_server_t * server = tcp_server_setup(argv[1]);

    if (!server)
    {
        goto main_return;
    }

    password_entry_t * entry = new_passwd_entry(ROOTUSER, ROOTPASS, ADMIN);
    password_file_init(argv[2], entry);
    destroy_passwd_entry(entry);
    tcp_server_teardown(server);
main_return:
    return rv;
}
// END OF SOURCE