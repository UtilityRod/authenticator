#ifndef _USER_H_
#define _USER_H_

#include <openssl/evp.h>

#define USERNAME_MAX_SZ 10

typedef struct {
    char username[USERNAME_MAX_SZ];
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_size;
} user_t;

int user_compare(const void * data1, const void * data2);
void user_destroy(void * username);
user_t * create_new_user(const char username[USERNAME_MAX_SZ], const char * password);

#endif