#include <assert.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <event.h>
#include <event2/listener.h>

#include "client_data.h"
#include "commands.h"
#include "configuration.h"
#include "utils.h"

static void ssl_readcb(struct bufferevent *bev, void *data)
{
    struct evbuffer *in = bufferevent_get_input(bev);
    struct client_data_t *client_data = (struct client_data_t *)data;

    if (client_data->state == STATE_DATA) {
        int bytes = evbuffer_write_atmost(in, client_data->fd, client_data->incoming_data_size);
        if (bytes == -1) {
            system_error(bev, client_data);
            return;
        }
        client_data->incoming_data_size -= bytes;

        if (client_data->incoming_data_size == 0) {
            bufferevent_write0(bev, "257 block received\n");
            client_data->state = STATE_PUT;
        }
    }
    else {
        char *line, *args;

        while ((line = evbuffer_readline(in))) {
            args = line;
            while (*args && *args != ' ') {
                *args = toupper(*args);
                args++;
            }
            if (*args) *(args++) = 0;

            if (!strcmp(line, "QUIT")) {
                bufferevent_write0(bev, "221 bye\n");
                free_client_data(client_data);
                bufferevent_free(bev);
            }

            else if (!strcmp(line, "USER") && client_data->state == STATE_INIT) {
                command_user(client_data, bev, args);
            }

            else if (!strcmp(line, "PASS") && client_data->state == STATE_WAITING_FOR_PASSWORD) {
                command_pass(client_data, bev, args);
            }

            else if (!strcmp(line, "PUT") && client_data->state == STATE_AUTHENTICATED) {
                command_put(client_data, bev, args);
            }

            else if (!strcmp(line, "BLOCK") && client_data->state == STATE_PUT) {
                command_block(client_data, bev, args);
            }

            else if (!strcmp(line, "SAVE") && client_data->state == STATE_PUT) {
                command_save(client_data, bev, args);
            }

            else {
                bufferevent_write0(bev, "500 unknown command or inappropriate command for current state\n");
            }
        }
    }
}

static void ssl_errorcb(struct bufferevent *bev, short what, void *data)
{
    struct client_data_t *client_data = (struct client_data_t *)data;

    if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        free_client_data(client_data);
    }
}

static void ssl_acceptcb(struct evconnlistener *serv, int sock, struct sockaddr *sa, int sa_len, void *arg)
{
    struct event_base *evbase;
    struct bufferevent *bev;
    SSL_CTX *server_ctx;
    SSL *client_ctx;
    struct client_data_t *client_data;

    server_ctx = (SSL_CTX *)arg;
    client_ctx = SSL_new(server_ctx);
    evbase = evconnlistener_get_base(serv);

    client_data = (struct client_data_t *)malloc(sizeof(struct client_data_t));
    assert(client_data);
    memset(client_data, 0, sizeof(struct client_data_t));
    client_data->sock = sock;

    bev = bufferevent_openssl_socket_new(
            evbase, sock, client_ctx,
            BUFFEREVENT_SSL_ACCEPTING,
            BEV_OPT_CLOSE_ON_FREE);

    bufferevent_write0(bev, "220 boat server\n");

    bufferevent_enable(bev, EV_READ);
    bufferevent_setcb(bev, ssl_readcb, NULL, ssl_errorcb, client_data);
}

static SSL_CTX *evssl_init(void)
{
    SSL_CTX *server_ctx;

    SSL_load_error_strings();
    SSL_library_init();

    server_ctx = SSL_CTX_new(TLSv1_server_method());

    if (!SSL_CTX_use_certificate_chain_file(server_ctx, configuration.ssl_cert_file)) {
        fprintf(stderr, "Couldn't load SSL cert file '%s'\n", configuration.ssl_cert_file);
        return NULL;
    }

    if (!SSL_CTX_use_PrivateKey_file(server_ctx, configuration.ssl_key_file, SSL_FILETYPE_PEM)) {
        fprintf(stderr, "Couldn't load SSL key file '%s'\n", configuration.ssl_key_file);
        return NULL;
    }

    return server_ctx;
}

int main(int argc, char **argv)
{
    SSL_CTX *ctx;
    struct evconnlistener *listener;
    struct event_base *evbase;
    struct sockaddr_in sin;

    memset(&configuration, 0, sizeof(configuration));
    configuration.listen_address = "0.0.0.0";
    configuration.listen_port = 8235;
    configuration.repository_root = "/var/lib/boat";

    if (load_configuration(argc == 1 ? NULL : argv[1]) != 0) return 1;

    make_directories();

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(configuration.listen_port);
    int n = inet_pton(sin.sin_family, configuration.listen_address, &sin.sin_addr.s_addr);
    if (n != 1) {
        fprintf(stderr, "listen address '%s' is not a valid IP address\n", configuration.listen_address);
        return 1;
    }

    ctx = evssl_init();
    if (ctx == NULL) return 1;
    evbase = event_base_new();
    listener = evconnlistener_new_bind(
            evbase, ssl_acceptcb, (void *)ctx,
            LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, 1024,
            (struct sockaddr *)&sin, sizeof(sin));

    event_base_loop(evbase, 0);

    evconnlistener_free(listener);
    SSL_CTX_free(ctx);

    return 0;
}
