#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "commands.h"
#include "constants.h"
#include "client_data.h"
#include "utils.h"

static int upload_counter = 0;

void command_user(struct client_data_t *client_data, struct bufferevent *bev, char *args)
{
    if (!*args) {
        bufferevent_write0(bev, "510 must specify a username\n");
        return;
    }

    if (client_data->user) free(client_data->user);
    client_data->username = strdup(args);
    client_data->state = STATE_WAITING_FOR_PASSWORD;

    bufferevent_write0(bev, "251 hi, password please\n");
}

void command_pass(struct client_data_t *client_data, struct bufferevent *bev, char *args)
{
    if (!*args) {
        bufferevent_write0(bev, "510 must specify a password\n");
        return;
    }

    struct user_configuration_t *user = configuration.head_user;
    int success = 0;

    // Find the user configuration record
    while (user && strcmp(user->username, client_data->username)) user = user->next;

    if (user) {
        unsigned char server_password[EVP_MAX_MD_SIZE];
        unsigned int server_password_length;

        if (HMAC(EVP_sha256(), args, strlen(args), (unsigned char *)user->password, SALT_LENGTH, server_password, &server_password_length)) {
            char *server_password_in_hex = binary_to_hex(server_password, server_password_length);
            success = !strcmp(user->password + SALT_LENGTH, server_password_in_hex);
            free(server_password_in_hex);
        }
    }

    while (*args) *(args++) = 0;

    if (success) {
        bufferevent_write0(bev, "252 authenticated\n");
        client_data->state = STATE_AUTHENTICATED;
        client_data->user = user;
    }
    else {
        bufferevent_write0(bev, "552 invalid password\n");
        client_data->state = STATE_INIT;
    }
}

void command_put(struct client_data_t *client_data, struct bufferevent *bev, char *args)
{
    if (!*args) {
        bufferevent_write0(bev, "510 must specify a filename\n");
        return;
    }

    if (strlen(args) > MAX_FILENAME_LENGTH) {
        bufferevent_write0(bev, "510 filename is too long\n");
        return;
    }

    if (!valid_filename(args)) {
        bufferevent_write0(bev, "510 invalid characters in filename\n");
        return;
    }

    if (!client_data->user->versioning_enabled) {
        char *path;
        int n;
        n = asprintf(&path, "%s/%s/current.%s", configuration.repository_root, client_data->user->repository, args);
        if (n == -1 || path == NULL) {
            system_error(bev, client_data);
            return;
        }

        struct stat buf;
        if (stat(path, &buf) != -1 || errno != ENOENT) {
            free(path);
            bufferevent_write0(bev, "520 file already exists\n");
            return;
        }
        free(path);
    }

    if (client_data->filename) free(client_data->filename);
    client_data->filename = strdup(args);
    client_data->state = STATE_PUT;

    if (client_data->temp_path) free(client_data->temp_path);
    int n;
    n = asprintf(&(client_data->temp_path), "%s/tmp/%d.%d", configuration.repository_root, getpid(), upload_counter++);
    if (n == -1 || client_data->temp_path == NULL) {
        system_error(bev, client_data);
        return;
    }

    client_data->fd = open(client_data->temp_path, O_WRONLY|O_CREAT, 0640);

    bufferevent_write0(bev, "255 ok\n");
}

void command_block(struct client_data_t *client_data, struct bufferevent *bev, char *args)
{
    if (!*args) {
        bufferevent_write0(bev, "510 must specify a block size\n");
        return;
    }

    char *p = args;
    while (*p) {
        if (*p < '0' || *p > '9') {
            bufferevent_write0(bev, "510 invalid block size\n");
            return;
        }
        p++;
    }

    if (p - args > 9 || atoi(args) > MAX_BLOCK_SIZE) {
        bufferevent_write0(bev, "510 invalid block size\n");
        return;
    }

    client_data->state = STATE_DATA;
    client_data->incoming_data_size = atoi(args);
    bufferevent_write0(bev, "256 commence data upload\n");
}

void command_save(struct client_data_t *client_data, struct bufferevent *bev, char *args)
{
    if (*args) {
        bufferevent_write0(bev, "510 save does not take an argument\n");
        return;
    }

    close(client_data->fd);
    client_data->fd = 0;

    char *path;
    int n;
    time_t now = time(NULL);
    n = asprintf(&path, "%s/%s/%d.%d.%d.%s", configuration.repository_root, client_data->user->repository, getpid(), upload_counter++, (int)now, client_data->filename);
    if (n == -1 || path == NULL) {
        system_error(bev, client_data);
        return;
    }

    n = rename(client_data->temp_path, path);
    if (n == -1) {
        system_error(bev, client_data);
        return;
    }

    char *current_symlink;
    n = asprintf(&current_symlink, "%s/%s/current.%s", configuration.repository_root, client_data->user->repository, client_data->filename);
    if (n == -1 || current_symlink == NULL) {
        system_error(bev, client_data);
        return;
    }

    unlink(current_symlink); // ignore return value
    n = symlink(path, current_symlink);
    if (n == -1) {
        system_error(bev, client_data);
        return;
    }

    free(current_symlink);
    free(path);

    client_data->state = STATE_AUTHENTICATED;
    bufferevent_write0(bev, "259 file saved\n");
}



