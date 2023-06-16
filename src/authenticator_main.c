#include <stdio.h>
#include <string.h>
#include <tcp_server.h>
#include <circular_ll.h>

#include "user.h"


#define STR(x) #x

typedef struct {
    circular_list_t * db;
    size_t number_of_users;
} authenticator_t;

static int passwd_db_init(authenticator_t * authenticator);
static int authenticate(authenticator_t * authenticator, user_t * cmp_user);

int main(int argc, char ** argv)
{
    int rv = -1;
    authenticator_t authenticator = {0};

    if (argc != 2)
    {
        fputs("Usage: ./authenticator_main [port]", stderr);
        goto main_return;
    }

    tcp_server_t * server = tcp_server_setup(argv[1]);

    if (!server)
    {
        goto main_return;
    }

    if (passwd_db_init(&authenticator) != 0)
    {
        fputs("ERROR: failed password database setup\n", stderr);
        goto teardown;
    }

    user_t * cmp_user = create_new_user(STR(root), STR(toor));

    int cmp = authenticate(&authenticator, cmp_user);
    if (cmp == 0)
    {
        printf("User successfully authenticated\n");
    }
    else
    {
        printf("Invalid user logon: %d\n", cmp);
    }

    user_destroy(cmp_user);

teardown:
    circular_destroy(authenticator.db);
    tcp_server_teardown(server);
main_return:
    return rv;
}

static int passwd_db_init(authenticator_t * authenticator)
{
    int rv = -1;
    authenticator->db = circular_create(user_compare, user_destroy);

    user_t * root = create_new_user(STR(root), STR(toor));
    size_t list_sz = circular_insert(authenticator->db, root, BACK);

    if (list_sz != (authenticator->number_of_users + 1))
    {
        fputs("ERROR: failed to add root user to database\n", stderr);
        user_destroy(root);
        goto init_return;
    }

    authenticator->number_of_users++;
    rv = 0;
init_return:
    return rv;
}

static int authenticate(authenticator_t * authenticator, user_t * cmp_user)
{
    int rv = -1;
    user_t * db_user = circular_search(authenticator->db, cmp_user);

    if (!db_user)
    {
        rv = -2;
        goto compare_return;
    }
    
    if (strcmp(cmp_user->md, db_user->md) == 0)
    {
        rv = 0;
    }

compare_return:
    return rv;
}
// END OF SOURCE