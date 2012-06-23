#include <event2/bufferevent_ssl.h>
#include "configuration.h"
#include "client_data.h"

void command_user(struct client_data_t *client_data, struct bufferevent *bev, char *args);
void command_pass(struct client_data_t *client_data, struct bufferevent *bev, char *args);
void command_put(struct client_data_t *client_data, struct bufferevent *bev, char *args);
void command_block(struct client_data_t *client_data, struct bufferevent *bev, char *args);
void command_save(struct client_data_t *client_data, struct bufferevent *bev, char *args);
