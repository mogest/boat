#include <event2/bufferevent_ssl.h>
#include "client_data.h"

int valid_filename(const char *filename);
char *binary_to_hex(const unsigned char *input, int length);
int mkdir_p(const char *path);
void system_error(struct bufferevent *bufev, struct client_data_t *client_data);
int bufferevent_write0(struct bufferevent *bufev, const char *data);
