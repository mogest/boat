#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "configuration.h"
#include "constants.h"
#include "utils.h"

struct configuration_t configuration;

int process_configuration_option(const char *key, const char *value, int line_number)
{
    if (!strcasecmp(key, "listen address")) {
        configuration.listen_address = strdup(value);
    }

    else if (!strcasecmp(key, "listen port")) {
        int n = atoi(value);
        if (n < 1 || n > 65535) {
            fprintf(stderr, "invalid value for listen_port; it must be between 1 and 65535\n");
            return -1;
        }
        configuration.listen_port = n;
    }

    else if (!strcasecmp(key, "repository root")) {
        configuration.repository_root = strdup(value);
    }

    else if (!strcasecmp(key, "ssl key file")) {
        configuration.ssl_key_file = strdup(value);
    }

    else if (!strcasecmp(key, "ssl cert file")) {
        configuration.ssl_cert_file = strdup(value);
    }

    else if (!strcasecmp(key, "user")) {
        struct user_configuration_t *new_user;

        new_user = (struct user_configuration_t *)malloc(sizeof(struct user_configuration_t));
        assert(new_user);
        memset(new_user, 0, sizeof(struct user_configuration_t));
        if (configuration.tail_user) {
            configuration.tail_user->next = new_user;
        }
        else {
            configuration.head_user = new_user;
        }
        configuration.tail_user = new_user;
        new_user->username = strdup(value);
    }

#define USER_FIRST_ERROR { fprintf(stderr, "must specify a 'user' before specifying a '%s' on line %d of configuration file\n", key, line_number); return -1; }
#define DUPLICATE_FIELD_ERROR { fprintf(stderr, "'%s' already supplied for this user on line %d of configuration file\n", key, line_number); return -1; }

    else if (!strcasecmp(key, "user password")) {
        if (configuration.tail_user == NULL) USER_FIRST_ERROR;
        if (configuration.tail_user->password) DUPLICATE_FIELD_ERROR;

        if (strlen(value) != 64 + SALT_LENGTH) {
            fprintf(stderr, "invalid password value on line %d of configuration file\n", line_number);
            return -1;
        }

        configuration.tail_user->password = strdup(value);
    }

    else if (!strcasecmp(key, "user repository")) {
        if (configuration.tail_user == NULL) USER_FIRST_ERROR;
        if (configuration.tail_user->repository) DUPLICATE_FIELD_ERROR;

        if (!valid_filename(value)) {
            fprintf(stderr, "value for 'user repository' is not a valid filename in line %d of configuration file\n", line_number);
            return -1;
        }

        configuration.tail_user->repository = strdup(value);
    }

    else if (!strcasecmp(key, "user versioning enabled")) {
        if (configuration.tail_user == NULL) USER_FIRST_ERROR;

        if (!strcasecmp(value, "yes") || !strcasecmp(value, "1") || !strcasecmp(value, "true"))
            configuration.tail_user->versioning_enabled = 1;
        else if (!strcasecmp(value, "no") || !strcasecmp(value, "0") || !strcasecmp(value, "false"))
            configuration.tail_user->versioning_enabled = 0;
        else {
            fprintf(stderr, "value for 'user versioning enabled' must be yes or no on line %d of configuration file\n", line_number);
            return -1;
        }
    }

    else {
        fprintf(stderr, "unrecognised configuration key '%s' on line number %d of configuration file\n", key, line_number);
        return -1;
    }

    return 0;
}

int load_configuration(char *config_file)
{
    if (config_file == NULL) config_file = "/etc/boat.conf";

    FILE *file;
    file = fopen(config_file, "r");
    if (file == NULL) {
        fprintf(stderr, "could not open configuration file '%s'\n", config_file);
        return -1;
    }

    char line[1024], *p, *key, *value, line_number = 0;
    while (fgets(line, 1024, file)) {
        line_number++;
        p = line + strlen(line) - 1;
        if (*p != '\n') {
            fprintf(stderr, "could not parse configuration file, line %d is over 1024 characters\n", line_number);
            fclose(file);
            return -1;
        }

        // Remove trailing newline characters.
        while (p >= line && (*p == '\n' || *p == '\r')) *(p--) = 0;

        // Skip leading whitespace chararcters for the key.
        p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#') continue;

        // Go in search of the = sign that delimits the key and value.
        key = p;
        while (*p && *p != '=') p++;
        if (!*p) {
            fprintf(stderr, "error in line %d of configuration file: no '=' found in directive\n", line_number);
            fclose(file);
            return -1;
        }

        value = p + 1;

        // Strip trailing whitespaces from the end of the key.
        *(p--) = 0;
        while (*p == ' ' || *p == '\t') *(p--) = 0;

        // Strip leading whitespaces from the start of the value.
        while (*value == ' ' || *value == '\t') value++;

        if (process_configuration_option(key, value, line_number) != 0) {
            fclose(file);
            return -1;
        }
    }

    fclose(file);

    if (configuration.ssl_key_file == NULL) {
        fprintf(stderr, "your configuration file must specify a 'SSL key file'\n");
        return -1;
    }
    if (configuration.ssl_cert_file == NULL) {
        fprintf(stderr, "your configuration file must specify a 'SSL cert file'\n");
        return -1;
    }

    struct user_configuration_t *user = configuration.head_user;
    if (user == NULL) {
        fprintf(stderr, "at least one user must be specified in the configuration file\n");
        return -1;
    }
    while (user) {
        if (user->password == NULL) {
            fprintf(stderr, "no 'user password' specified for user '%s' in configuration file\n", user->username);
            return -1;
        }
        if (user->repository == NULL) {
            fprintf(stderr, "no 'user repository' specified for user '%s' in configuration file\n", user->username);
            return -1;
        }

        user = user->next;
    }

    return 0;
}

void make_directories(void)
{
    char *path;
    int n;

    n = asprintf(&path, "%s/tmp", configuration.repository_root);
    assert(n != -1 && path);
    if (mkdir_p(path) != 0) {
        fprintf(stderr, "error while trying to create directory %s\n", path);
        exit(1);
    }
    free(path);

    struct user_configuration_t *user = configuration.head_user;
    while (user) {
        n = asprintf(&path, "%s/%s", configuration.repository_root, user->repository);
        assert(n != -1 && path);
        if (mkdir_p(path) != 0) {
            fprintf(stderr, "error while trying to create directory %s\n", path);
            exit(1);
        }
        free(path);
        user = user->next;
    }
}

