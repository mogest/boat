#ifndef __CONFIGURATION_H
#define __CONFIGURATION_H

struct user_configuration_t
{
    char *username;
    char *password;
    char *repository;
    int versioning_enabled;
    struct user_configuration_t *next;
};

struct configuration_t
{
    char *listen_address;
    short listen_port;
    char *repository_root;
    char *ssl_key_file;
    char *ssl_cert_file;
    struct user_configuration_t *head_user;
    struct user_configuration_t *tail_user;
};

extern struct configuration_t configuration;

int process_configuration_option(const char *key, const char *value, int line_number);
int load_configuration(char *config_file);
void make_directories(void);

#endif
