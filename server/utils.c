#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "utils.h"

int valid_filename(const char *filename)
{
    while (*filename) {
        if ((*filename < 'a' || *filename > 'z') &&
                (*filename < 'A' || *filename > 'Z') &&
                (*filename < '0' || *filename > '9') &&
                *filename != '_' && *filename != '.' && *filename != '%' && *filename != '+' && *filename != '-') {
            return 0;
        }
        filename++;
    }
    return 1;
}

char *binary_to_hex(const unsigned char *input, int length)
{
    char *out, *p;
    const char *hex = "0123456789abcdef";

    if (length <= 0) return NULL;

    out = p = (char *)malloc(length * 2 + 1);
    if (out == NULL) return NULL;

    while (length--) {
        *(p++) = hex[*input >> 4];
        *(p++) = hex[*(input++) & 0xf];
    }
    *p = 0;

    return out;
}

int mkdir_p(const char *path)
{
    if (mkdir(path, 0770) == 0) return 0;
    if (errno == EEXIST) return 0;
    if (errno != ENOENT) return -1;
    char *subpath = strdup(path);
    char *slash = strrchr(subpath, '/');
    if (slash == NULL) return -1;
    *slash = 0;
    int n = mkdir_p(subpath);
    free(subpath);
    if (n == 0) n = mkdir(path, 0770);
    return n;
}

int bufferevent_write0(struct bufferevent *bufev, const char *data)
{
    return bufferevent_write(bufev, data, strlen(data));
}

void system_error(struct bufferevent *bufev, struct client_data_t *client_data)
{
    bufferevent_write0(bufev, "599 system error occurred, disconnecting\n");
    free_client_data(client_data);
    bufferevent_free(bufev);
}
