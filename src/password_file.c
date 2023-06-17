#include "password_file.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define ENTRY_FORMAT "%s:%d:$1$%s$%s\n"
#define B64_ENCODE_BUF_LEN (1 + ((EVP_MAX_MD_SIZE + 2) / 3 * 4))

typedef enum {
    PASSWD_NULL_PTR = -1,
    PASSWD_ALLOC_ERROR = -2,
    PASSWD_FILE_PERM = -3,
} passwd_error_t;

static char * generate_passwd_string(const password_entry_t * user);
static unsigned int md5hash(const char * password, const char * salt, unsigned char md[EVP_MAX_MD_SIZE]);

int password_file_init(const char * path, const password_entry_t * rootuser)
{
    int rv = 0;
    FILE * passwd = NULL;
    char * passwd_str = NULL;
    
    if (!path || !rootuser)
    {
        rv = PASSWD_NULL_PTR;
        goto init_return;
    }

    passwd = fopen(path, "w");

    if (!passwd)
    {
        rv = PASSWD_FILE_PERM;
        goto init_return;
    }

    passwd_str = generate_passwd_string(rootuser);

    if (!passwd_str)
    {
        rv = PASSWD_ALLOC_ERROR;
        goto cleanup;
    }
    
    fwrite(passwd_str, sizeof(*passwd_str), strlen(passwd_str), passwd);

cleanup:
    free(passwd_str);
    fclose(passwd);
init_return:
    return rv;
}

password_entry_t * new_passwd_entry(const char * user, const char * password, permissions_t permissions)
{
    password_entry_t * entry = NULL;

    if (!user || !password || permissions >= NUMBER_OF_PERMISSIONS)
    {
        goto new_passwd_return; 
    }

    entry = calloc(1, sizeof(*entry));

    if (!entry)
    {
        goto new_passwd_return;
    }

    entry->user = strdup(user);

    if (!(entry->user))
    {
        goto cleanup;
    }

    time_t t = {0};
    srand((unsigned)time(&t));

    for (int i = 0; i < SALT_LEN; i++)
    {
        entry->salt[i] = rand() % 255;
    }

    entry->md_len = md5hash(password, entry->salt, entry->md);
    entry->permissions = permissions;
    goto new_passwd_return;

cleanup:
    destroy_passwd_entry(entry);
    entry = NULL;
new_passwd_return:
    return entry;
}

void destroy_passwd_entry(password_entry_t * entry)
{
    if (!entry)
    {
        return;
    }

    free(entry->user);
    entry->user = NULL;

    for (int i = 0; i < SALT_LEN; i++)
    {
        entry->salt[i] = 0;
    }

    for (int i = 0; i < entry->md_len; i++)
    {
        entry->md[i] = 0;
    }

    entry->permissions = 0;
    entry->md_len = 0;
    free(entry);
    return;
}

static char * generate_passwd_string(const password_entry_t * pwentry)
{
    char * pwstr = NULL;
    size_t entry_len = snprintf(
        NULL, 0, ENTRY_FORMAT, pwentry->user, pwentry->permissions, pwentry->salt, pwentry->md
    );

    char b64pass[B64_ENCODE_BUF_LEN];
    char b64salt[B64_ENCODE_BUF_LEN];
    memset(b64pass, 0, B64_ENCODE_BUF_LEN);
    memset(b64salt, 0, B64_ENCODE_BUF_LEN);
    EVP_EncodeBlock(b64pass, pwentry->md, pwentry->md_len);
    EVP_EncodeBlock(b64salt, pwentry->salt, SALT_LEN - 1);

    pwstr = calloc(entry_len, sizeof(*pwstr));

    if (pwstr)
    {
        snprintf(
            pwstr, entry_len, 
            ENTRY_FORMAT, pwentry->user, pwentry->permissions, b64salt, b64pass
        );
    }

generate_return:
    return pwstr;
}

static unsigned int md5hash(const char * password, const char * salt, unsigned char md[EVP_MAX_MD_SIZE])
{
    unsigned int md_len = 0;
    EVP_MD_CTX * mdctx = EVP_MD_CTX_new();
    const EVP_MD *EVP_md5();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
    EVP_DigestUpdate(mdctx, salt, strlen(salt));
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, md, &md_len);
    EVP_MD_CTX_free(mdctx);

hash_password_return:
    return md_len;
}
// END OF SOURCE