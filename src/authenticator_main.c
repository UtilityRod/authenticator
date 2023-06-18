#include <stdio.h>
#include <string.h>
#include <eloop.h>
#include <unistd.h>
#include <tcp_server.h>
#include <semaphore.h>

#include "password_file.h"

#define STR(x) #x
#define ROOTUSER "root"
#define ROOTPASS "toor"
#define USAGE "Usage: ./authenticator_main [password file]"

typedef struct {
    eloop_t * eloop;
    tcp_server_t * server;
    const char * port;
    sem_t semaphore;
} authenticator_t;

static int passwd_setup_event(event_t * event);
static int tcp_setup_event(event_t * event);
static void handle_connections(authenticator_t * auth);

int main(int argc, char ** argv)
{
    int rv = -1;

    if (argc != 3)
    {
        fputs(USAGE, stdout);
        goto main_return;
    }

    authenticator_t auth = {0};
    sem_init(&(auth.semaphore), 0, 0);
    auth.port = argv[2];
    auth.eloop = eloop_create();

    if (!auth.eloop)
    {
        goto main_return;
    }

    event_t passwd_setup = {
        .data = argv[1],
        .efunc = passwd_setup_event,
    };

    eloop_add(auth.eloop, &passwd_setup);

    event_t tcp_setup = {
        .data = &auth,
        .efunc = tcp_setup_event,
    };

    eloop_add(auth.eloop, &tcp_setup);
    sem_wait(&(auth.semaphore));
    
    if (!auth.server)
    {
        goto cleanup;
    }

    handle_connections(&auth);

cleanup:
    tcp_server_teardown(auth.server);
    auth.server = NULL;
    eloop_destroy(auth.eloop);
    auth.eloop = NULL;
    sem_destroy(&(auth.semaphore));
main_return:
    return rv;
}

static int passwd_setup_event(event_t * event)
{
    int rv = -1;
    const char * path = (const char *)event->data;
    password_entry_t * root = new_passwd_entry(ROOTUSER, ROOTPASS, ADMIN);

    if (!root)
    {
        goto setup_return;
    }

    rv = password_file_init(path, root);
    destroy_passwd_entry(root);
 
setup_return:
    event->efunc = NULL;
    event->data = NULL;
    return rv;
}

static int tcp_setup_event(event_t * event)
{
    int rv = -1;
    authenticator_t * auth = (authenticator_t *)event->data;
    auth->server = tcp_server_setup(auth->port);

    if (!auth->server)
    {
        goto tcp_setup_return;
    }

    rv = 0;

tcp_setup_return:
    sem_post(&(auth->semaphore));
    return rv;
}

static void handle_connections(authenticator_t * auth)
{
    for (;;)
    {
        int client_fd = tcp_server_accept(auth->server);
        printf("Client connected\n");
        close(client_fd);
        break;
    }

    return;
}
// END OF SOURCE