#include "user.h"
#include <string.h>
#include <stdlib.h>

static unsigned int md5hash(const char * password, unsigned char md[EVP_MAX_MD_SIZE]);

int user_compare(const void * data1, const void * data2)
{
    user_t * user1 = (user_t *)data1;
    user_t * user2 = (user_t *)data2;

    return strcmp(user1->username, user2->username);
}

void user_destroy(void * data)
{
    user_t * user = (user_t *)data;
    memset(user->username, 0, USERNAME_MAX_SZ);
    memset(user->md, 0, EVP_MAX_MD_SIZE);
    free(user);
}

user_t * create_new_user(const char username[USERNAME_MAX_SZ], const char * password)
{
    user_t * user = calloc(1, sizeof(*user));

    if (!user)
    {
        goto create_new_user_return;
    }

    strncpy(user->username, username, USERNAME_MAX_SZ);
    user->md_size = md5hash(password, user->md);

    if (user->md_size == 0)
    {
        user_destroy(user);
        user = NULL;
    }

create_new_user_return:
    return user;
}

static unsigned int md5hash(const char * password, unsigned char md[EVP_MAX_MD_SIZE])
{
    unsigned int md_len = 0;
    EVP_MD_CTX * mdctx = EVP_MD_CTX_new();
    const EVP_MD *EVP_md5();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, md, &md_len);
    EVP_MD_CTX_free(mdctx);

hash_password_return:
    return md_len;
}
// END OF SOURCE