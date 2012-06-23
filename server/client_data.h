#ifndef __CLIENT_DATA_H
#define __CLIENT_DATA_H

#include "configuration.h"

enum client_state { STATE_INIT = 0, STATE_WAITING_FOR_PASSWORD, STATE_AUTHENTICATED, STATE_PUT, STATE_DATA };

struct client_data_t
{
    enum client_state state;
    int sock;
    char *username;
    char *temp_path;
    char *filename;
    unsigned int incoming_data_size;
    struct user_configuration_t *user;
    int fd;
};

void free_client_data(struct client_data_t *client_data);

#endif
