#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "client_data.h"

void free_client_data(struct client_data_t *client_data)
{
    if (client_data->fd) close(client_data->fd);
    if (client_data->temp_path) {
        unlink(client_data->temp_path); // ignore result
        free(client_data->temp_path);
    }
    if (client_data->filename) free(client_data->filename);
    if (client_data->user) free(client_data->user);
    memset(client_data, 0, sizeof(struct client_data_t));
    free(client_data);
}
