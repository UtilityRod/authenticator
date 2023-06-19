#include <stdio.h>
#include <string.h>
#include <eloop.h>
#include <unistd.h>
#include <tcp_server.h>
#include <tcp_operations.h>
#include <semaphore.h>
#include <signal.h>
#include <stdint.h>

#include "password_file.h"

#define ROOTUSER "root"
#define ROOTPASS "toor"
#define USAGE "Usage: ./authenticator_main [password file] [port]\n"
#define AUTH_HEADER_SZ sizeof(uint8_t) * 2

typedef struct {
    eloop_t * eloop;
    tcp_server_t * server;
    const char * port;
    sem_t semaphore;
} authenticator_t;

static int passwd_setup_event(event_t * event);
static int tcp_setup_event(event_t * event);
static void handle_connections(authenticator_t * auth);

static void establish_handler(int sig, void (*func)(int));
static void signal_handler(int sig);

volatile sig_atomic_t teardown_server = 0; 

int main(int argc, char ** argv)
{
    establish_handler(SIGINT, signal_handler);

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

static int client_connect_event(event_t * event)
{
    int rv = -1;
    int * client = (int *)event->data;

    uint8_t auth_header[AUTH_HEADER_SZ];
    memset(auth_header, 0, AUTH_HEADER_SZ);

    int nread = tcp_read_all(*client, auth_header, AUTH_HEADER_SZ);

    if (nread != AUTH_HEADER_SZ)
    {
        goto cleanup;
    }

    uint8_t * tmp_ptr = auth_header;
    uint8_t username_sz = *tmp_ptr++;
    uint8_t password_sz = *tmp_ptr;

    if (username_sz >= MAX_USERNAME_SZ || password_sz >= MAX_PASSWORD_SZ)
    {
        fputs("ERROR: username or password is too long\n", stderr);
        goto cleanup;
    }

    int userpass_sz = username_sz + password_sz;
    char * userpass = calloc(userpass_sz + 2, sizeof(*userpass));

    if (!userpass)
    {
        goto cleanup;
    }

    nread = tcp_read_all(*client, userpass, userpass_sz);

    if (nread != userpass_sz)
    {
        goto cleanup;
    }

    char * username = userpass;
    char * password = userpass + username_sz;
    memmove(password + 1, password, password_sz);
    *password = '\0';
    password++;

cleanup:
    free(userpass);
    close(*client);
    free(event->data);
    event->data = NULL;
    event->efunc = NULL;
    free(event);
    rv = 0;
    return rv;
}

static void handle_connections(authenticator_t * auth)
{
    while (!teardown_server)
    {
        int client_fd = tcp_server_accept(auth->server);

        if (client_fd == -1)
        {
            continue;
        }

        event_t * connect_event = calloc(1, sizeof(*connect_event));

        if (!connect_event)
        {
            close(client_fd);
            continue;
        }

        int * event_fd = calloc(1, sizeof(*event_fd));

        if (!event_fd)
        {
            close(client_fd);
            free(connect_event);
            continue;
        }

        *event_fd = client_fd;
        connect_event->data = event_fd;
        connect_event->efunc = client_connect_event;
        eloop_add(auth->eloop, connect_event);
    }

    return;
}

static void establish_handler(int sig, void (*func)(int))
{
    int rv = 0;
    struct sigaction sa = {
        .sa_handler = func
    };

    if (sigaction(sig, &sa, NULL) == -1)
    {
        fputs("ERROR: failed to set sigation\n", stderr);
        exit(-1);
    }
}

static void signal_handler(int sig)
{
    switch(sig)
    {
        case SIGINT:
            teardown_server = 1;
            break;
        default:
            fputs("ERROR: unknown signal has been captured\n", stderr);
            break;
    }
}
// END OF SOURCE