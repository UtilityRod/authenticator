#ifndef _PASSWORD_FILE_H_
#define _PASSWORD_FILE_H_

#include <openssl/evp.h>

#define SALT_LEN 6

typedef enum {
    ADMIN,
    USER,
    NUMBER_OF_PERMISSIONS
} permissions_t;

typedef struct {
    char * user;
    char salt[SALT_LEN];
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    permissions_t permissions;
} password_entry_t;

int password_file_init(const char * path, const password_entry_t * rootuser);
password_entry_t * new_passwd_entry(const char * user, const char * password, permissions_t permissions);
void destroy_passwd_entry(password_entry_t * entry);

#endif