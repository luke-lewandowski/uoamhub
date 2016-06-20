/*
 * uoamhub
 * $Id: uoamhub.c 127 2005-02-17 20:56:05Z max $
 *
 * (c) 2004-2005 Max Kellermann <max@duempel.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/*
 * dedicated server for UOAutoMap (which is non-free)
 *
 * Home page: http://max.kellermann.name/projects/uoamhub/
 *
 */

#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#ifdef __GLIBC__
#include <getopt.h>
#endif
#include <pwd.h>
#include <grp.h>
#include <time.h>

#ifdef DISABLE_LOGGING
#define log(level, ...)
#else
#define log(level, ...) do { if (verbose >= (level)) { printf(__VA_ARGS__); fflush(stdout); } } while (0)
#endif

/** source for client ids (which are important for security). if you
    have a hardware random device, change this */
#ifndef RANDOM_DEVICE
#define RANDOM_DEVICE "/dev/urandom"
#endif

/*
  feel free to tune:
*/

/** maximum number of domains */
#define MAX_DOMAINS 64

/** maximum number of clients per domain */
#define MAX_CLIENTS 256

/** maximum number of connections per client */
#define MAX_SOCKETS 16

/** length of the chat queue per client */
#define MAX_CHATS 64

/** version number of this software */
static const char VERSION[] = "0.9.1";

#ifndef DISABLE_LOGGING
/** verbosity - increasing this will trash the screen */
static int verbose = 1;
#endif

/** set by the signal handler to tell the main loop to exit */
static volatile int should_exit = 0;

/** global host configuration */
struct config {
    unsigned port;
    struct addrinfo *bind_address;
    char *password;
#ifndef DISABLE_DAEMON_CODE
    int no_daemon;
    const char *pidfile, *logger, *chroot_dir;
    uid_t uid;
    gid_t gid;
#endif /* DISABLE_DAEMON_CODE */
};

struct noip_player_info {
    char name[64];
    unsigned char reserved[12];
    unsigned char position[16];
};

/** this structure is sent by the client in position update packets */
struct player_info {
    /** the internal client's IP address, not affected by NAT */
    unsigned char ip[4];
    /** public client info */
    struct noip_player_info noip;
};

/** an item in the chat queue */
struct chat {
    size_t size;
    char data[1];
};

/** a client, which may consist of more than one socket */
struct client {
    /** doubly linked list */
    struct client *prev, *next;
#ifndef DISABLE_LOGGING
    /** socket address */
    struct sockaddr address;
    /** length of address */
    socklen_t address_length;
    /** visible name */
    char name[64];
#endif
    /** client id */
    uint32_t id;
    /** list of all sockets (a client can use several sockets at
        once) */
    int sockets[MAX_SOCKETS];
    /** number of sockets in the sockets array */
    unsigned num_sockets;
    /** unix time when this client times out, unless he successfully
        talks to server meanwhile */
    time_t timeout;
    /** the domain this client is logged in */
    struct domain *domain;
    /** several flags */
    int should_destroy:1, handshake:1, authorized:1, have_position:1;
    /** player info, including name and position */
    struct player_info info;
    /** chat settings */
    void *font_buffer;
    /** size of the chat settings */
    size_t font_buffer_size;
    /** pending chat entries */
    struct chat *chats[MAX_CHATS];
    /** number of chat entries not yet sent to the client */
    unsigned num_chats;
};

/** a domain - all clients who chose the same password are in the same
    domain and can see each others */
struct domain {
    /** doubly linked list */
    struct domain *prev, *next;
    /** password of this domain */
    char password[20];
    /** the host this domain belongs to */
    struct host *host;
    /** pointer to the first client */
    struct client *clients_head;
    /** number of clients */
    unsigned num_clients;
};

/** a host - currently only one host is supported, so this is a
    singleton */
struct host {
    /** configuration of this host */
    const struct config *config;
    /** pointer to the first domain */
    struct domain *domains_head;
    /** number of domains */
    unsigned num_domains;
};

/*
  Some templates for packets are following. I havn't decoded some of
  them yet, but that doesn't matter as long as the client understands
  us.
*/

/** response to the first packet in a TCP connection */
static unsigned char packet_handshake_response[] = {
    0x05, 0x00, 0x0c, 0x03, 0x10, 0x00, 0x00, 0x00,
    0x3c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xd0, 0x16, 0xd0, 0x16, 0xff, 0xff, 0xff, 0xff,
    0x05, 0x00, 0x32, 0x30, 0x30, 0x30, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
    0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
    0x02, 0x00, 0x00, 0x00,
};

/** server acknowledges information sent by the client */
static unsigned char packet_ack[] = {
    0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
    0x1c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

/** response to a chat poll: no chat item in the client's queue */
static unsigned char packet_no_chat[] = {
    0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
    0x2c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

/** packet header of a chat poll response - a chat packet is appended
    (either chat text or chat font) */
static const unsigned char header_chat[] = {
    0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00,
};

/** packet header of a list response - a list of players with their
    position is appended */
static const unsigned char header_list[] = {
    0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff,
};

/** response to a 0x0e packet. no idea what this means */
static unsigned char packet_response2[] = {
    0x05, 0x00, 0x0f, 0x03, 0x10, 0x00, 0x00, 0x00,
    0x38, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0xd0, 0x16, 0xd0, 0x16, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
    0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
    0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00,
};

/** signal handler for SIGTERM, SIGINT etc. */
static void exit_signal_handler(int sig) {
    (void)sig;

    log(2, "signal %d received, shutting down...\n", sig);

    should_exit++;
}

static int getaddrinfo_helper(const char *host_and_port, int default_port,
                              const struct addrinfo *hints,
                              struct addrinfo **aip) {
    const char *colon, *host, *port;
    char buffer[256];

    colon = strchr(host_and_port, ':');
    if (colon == NULL) {
        snprintf(buffer, sizeof(buffer), "%d", default_port);

        host = host_and_port;
        port = buffer;
    } else {
        size_t len = colon - host_and_port;

        if (len >= sizeof(buffer)) {
            errno = ENAMETOOLONG;
            return EAI_SYSTEM;
        }

        memcpy(buffer, host_and_port, len);
        buffer[len] = 0;

        host = buffer;
        port = colon + 1;
    }

    if (strcmp(host, "*") == 0)
        host = "0.0.0.0";

    return getaddrinfo(host, port, hints, aip);
}

/** print a short usage description */
static void usage(void) __attribute__ ((noreturn));
static void usage(void) {
    fprintf(stderr, "usage: uoamhub [options]\n\n"
            "valid options:\n"
            " -h             help (this text)\n"
            " -V             print version number\n"
#ifdef __GLIBC__
            " --verbose\n"
#endif
            " -v             increase verbosity (default 1)\n"
#ifdef __GLIBC__
            " --quiet\n"
#endif
            " -q             reset verbosity to 0\n"
#ifdef __GLIBC__
            " --password file\n"
#endif
            " -w file        single-domain, only accept the password from the file\n"
#ifdef __GLIBC__
            " --port port\n"
#endif
            " -p port        listen on this port (default 2000)\n"
#ifdef __GLIBC__
            " --logger program\n"
#endif
            " -l program     specifies a logger program (executed by /bin/sh)\n"
#ifdef __GLIBC__
            " --chroot dir\n"
#endif
            " -r dir         chroot into this directory (requires root)\n"
#ifdef __GLIBC__
            " --user username\n"
#endif
            " -u username    change user id (don't run uoamhub as root!)\n"
            " -D             don't detach (daemonize)\n"
#ifdef __GLIBC__
            " --pidfile file\n"
#endif
            " -P file        create a pid file\n"
            "\n"
            );
    exit(1);
}

/** read the contents of a file into a new string on the heap */
static int read_file_string(const char *filename, char **value) {
    FILE *file;
    char line[1024], *p;
    int save_errno;
    size_t len;

    assert(value != NULL);
    assert(*value == NULL);

    /* open file */
    file = fopen(filename, "r");
    if (file == NULL)
        return -1;

    /* read the first line */
    p = fgets(line, sizeof(line), file);
    save_errno = errno;
    fclose(file);
    if (p == NULL) {
        errno = save_errno;
        return -1;
    }

    /* trim value */
    while (*p > 0 && *p <= 0x20)
        p++;

    len = strlen(p);

    while (p[len - 1] > 0 && p[len - 1] <= 0x20)
        len--;

    p[len] = 0;

    /* allocate memory */
    *value = strdup(p);
    if (*value == NULL)
        return -1;

    return 0;
}

/** read configuration options from the command line */
static void read_config(struct config *config, int argc, char **argv) {
    int ret;
    struct addrinfo hints;
#ifdef __GLIBC__
    static const struct option long_options[] = {
        {"version", 0, 0, 'V'},
        {"verbose", 0, 0, 'v'},
        {"quiet", 0, 0, 'q'},
        {"help", 0, 0, 'h'},
        {"port", 1, 0, 'p'},
        {"chroot", 1, 0, 'r'},
        {"user", 1, 0, 'u'},
        {"logger", 1, 0, 'l'},
        {"pidfile", 1, 0, 'P'},
        {"password", 1, 0, 'w'},
        {0,0,0,0}
    };
#endif
#ifndef DISABLE_DAEMON_CODE
    struct passwd *pw;
    struct stat st;
#endif

    memset(config, 0, sizeof(*config));
    config->port = 2000;

    while (1) {
#ifdef __GLIBC__
        int option_index = 0;

        ret = getopt_long(argc, argv, "Vvqhp:r:u:Dl:w:",
                          long_options, &option_index);
#else
        ret = getopt(argc, argv, "Vvqhp:r:u:Dl:w:");
#endif
        if (ret == -1)
            break;

        switch (ret) {
        case 'V':
            printf("uoamhub v%s\n", VERSION);
            exit(0);
#ifndef DISABLE_LOGGING
        case 'v':
            verbose++;
            break;
        case 'q':
            verbose = 0;
            break;
#endif
        case 'h':
            usage();
        case 'p':
            config->port = (unsigned)strtoul(optarg, NULL, 10);
            if (config->port == 0) {
                fprintf(stderr, "invalid port specification\n");
                exit(1);
            }
            break;
        case 'w':
            if (config->password != NULL) {
                free(config->password);
                config->password = NULL;
            }

            ret = read_file_string(optarg, &config->password);
            if (ret < 0) {
                fprintf(stderr, "failed to read '%s': %s\n",
                        optarg, strerror(errno));
                exit(1);
            }

            if (config->password[0] == 0) {
                fprintf(stderr, "password in '%s' is empty\n",
                        optarg);
                exit(1);
            }

            break;
#ifndef DISABLE_DAEMON_CODE
        case 'D':
            config->no_daemon = 1;
            break;
        case 'P':
            config->pidfile = optarg;
            break;
        case 'l':
            config->logger = optarg;
            break;
        case 'r':
            ret = stat(optarg, &st);
            if (ret < 0) {
                fprintf(stderr, "failed to stat '%s': %s\n",
                        optarg, strerror(errno));
                exit(1);
            }
            if (!S_ISDIR(st.st_mode)) {
                fprintf(stderr, "not a directory: '%s'\n",
                        optarg);
                exit(1);
            }

            config->chroot_dir = optarg;
            break;
        case 'u':
            pw = getpwnam(optarg);
            if (pw == NULL) {
                fprintf(stderr, "user '%s' not found\n", optarg);
                exit(1);
            }
            if (pw->pw_uid == 0) {
                fprintf(stderr, "setuid root is not allowed\n");
                exit(1);
            }
            config->uid = pw->pw_uid;
            config->gid = pw->pw_gid;
            break;
#endif /* DISABLE_DAEMON_CODE */
        default:
            exit(1);
        }
    }

    if (optind < argc) {
        fprintf(stderr, "unrecognized argument: %s\n", argv[optind]);
        usage();
    }

#ifndef DISABLE_DAEMON_CODE
    if (geteuid() == 0 && config->uid == 0) {
        fprintf(stderr, "running uoamhub as root is a Bad Thing(TM), please use --user\n");
        exit(1);
    }
#endif /* DISABLE_DAEMON_CODE */

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo_helper("*", config->port, &hints, &config->bind_address);
    if (ret < 0) {
        fprintf(stderr, "getaddrinfo_helper failed: %s\n",
                strerror(errno));
        exit(1);
    }
}

/** free data in a config struct; the struct itself is not freed */
static void free_config(struct config *config) {
    if (config->bind_address != NULL)
        freeaddrinfo(config->bind_address);

    if (config->password != NULL)
        free(config->password);

    memset(config, 0, sizeof(*config));
}

/** set up stuff, e.g. sockets, pipes, daemonize */
static void setup(struct config *config, int *randomfdp, int *sockfdp) {
    int ret, sockfd, param;
#ifndef DISABLE_DAEMON_CODE
    int parentfd = -1, loggerfd = -1;
    pid_t logger_pid = -1;
#endif
    struct sigaction sa;

    /* random device */
#ifdef HAVE_DEV_RANDOM
    *randomfdp = open(RANDOM_DEVICE, O_RDONLY);
    if (*randomfdp < 0) {
        fprintf(stderr, "failed to open %s: %s\n",
                RANDOM_DEVICE, strerror(errno));
        exit(1);
    }
#else
    *randomfdp = -1;
#endif

    /* server socket stuff */
    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "failed to create socket: %s\n",
                strerror(errno));
        exit(1);
    }

    /* get rid of the "Address already in use" errors */
    param = 1;
    ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &param, sizeof(param));
    if (ret < 0) {
        fprintf(stderr, "setsockopt failed: %s\n",
                strerror(errno));
        exit(1);
    }

    param = 1;
    ret = setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &param, sizeof(param));
    if (ret < 0) {
        fprintf(stderr, "setsockopt failed: %s\n",
                strerror(errno));
        exit(1);
    }

    ret = bind(sockfd, config->bind_address->ai_addr,
               config->bind_address->ai_addrlen);
    if (ret < 0) {
        fprintf(stderr, "failed to bind: %s\n",
                strerror(errno));
        exit(1);
    }

    ret = listen(sockfd, 4);
    if (ret < 0) {
        fprintf(stderr, "listen failed: %s\n",
                strerror(errno));
        exit(1);
    }

    *sockfdp = sockfd;

#ifndef DISABLE_DAEMON_CODE
    /* daemonize */
    if (!config->no_daemon && getppid() != 1) {
        int fds[2];
        pid_t pid;

        ret = pipe(fds);
        if (ret < 0) {
            fprintf(stderr, "pipe failed: %s\n", strerror(errno));
            exit(1);
        }

        pid = fork();
        if (pid < 0) {
            fprintf(stderr, "fork failed: %s\n", strerror(errno));
            exit(1);
        }

        if (pid > 0) {
            int status;
            fd_set rfds;
            char buffer[256];
            struct timeval tv;

            close(fds[1]);

            log(4, "waiting for daemon process %ld\n", (long)pid);

            do {
                FD_ZERO(&rfds);
                FD_SET(fds[0], &rfds);
                tv.tv_sec = 0;
                tv.tv_usec = 100000;
                ret = select(fds[0] + 1, &rfds, NULL, NULL, &tv);
                if (ret > 0 && read(fds[0], buffer, sizeof(buffer)) > 0) {
                    log(2, "detaching %ld\n", (long)getpid());
                    exit(0);
                }

                pid = waitpid(pid, &status, WNOHANG);
            } while (pid <= 0);

            log(3, "daemon process exited with %d\n",
                WEXITSTATUS(status));
            exit(WEXITSTATUS(status));
        }

        close(fds[0]);
        parentfd = fds[1];

        setsid();

        close(0);

        signal(SIGTSTP, SIG_IGN);
        signal(SIGTTOU, SIG_IGN);
        signal(SIGTTIN, SIG_IGN);

        log(3, "daemonized as pid %ld\n", (long)getpid());
    }

    /* write PID file */
    if (config->pidfile != NULL) {
        FILE *file;

        file = fopen(config->pidfile, "w");
        if (file == NULL) {
            fprintf(stderr, "failed to create '%s': %s\n",
                    config->pidfile, strerror(errno));
            exit(1);
        }

        fprintf(file, "%ld\n", (long)getpid());
        fclose(file);
    }

    /* start logger process */
    if (config->logger != NULL) {
        int fds[2];

        log(3, "starting logger '%s'\n", config->logger);

        ret = pipe(fds);
        if (ret < 0) {
            fprintf(stderr, "pipe failed: %s\n", strerror(errno));
            exit(1);
        }

        logger_pid = fork();
        if (logger_pid < 0) {
            fprintf(stderr, "fork failed: %s\n", strerror(errno));
            exit(1);
        } else if (logger_pid == 0) {
            if (fds[0] != 0) {
                dup2(fds[0], 0);
                close(fds[0]);
            }

            close(fds[1]);
            close(1);
            close(2);
            close(sockfd);
#ifdef HAVE_DEV_RANDOM
            close(*randomfdp);
#endif

            execl("/bin/sh", "sh", "-c", config->logger, NULL);
            exit(1);
        }

        log(2, "logger started as pid %ld\n", (long)logger_pid);

        close(fds[0]);
        loggerfd = fds[1];

        log(3, "logger %ld connected\n", (long)logger_pid);
    }

    /* chroot */
    if (config->chroot_dir != NULL) {
        ret = chroot(config->chroot_dir);
        if (ret < 0) {
            fprintf(stderr, "chroot '%s' failed: %s\n",
                    config->chroot_dir, strerror(errno));
            exit(1);
        }
    }

    chdir("/");

    /* setuid */
    if (config->uid > 0) {
        ret = setgroups(0, NULL);
        if (ret < 0) {
            fprintf(stderr, "setgroups failed: %s\n", strerror(errno));
            exit(1);
        }

        ret = setregid(config->gid, config->gid);
        if (ret < 0) {
            fprintf(stderr, "setgid failed: %s\n", strerror(errno));
            exit(1);
        }

        ret = setreuid(config->uid, config->uid);
        if (ret < 0) {
            fprintf(stderr, "setuid failed: %s\n", strerror(errno));
            exit(1);
        }
    } else if (getuid() == 0) {
        /* drop a real_uid root */
        setuid(geteuid());
    }
#endif /* DISABLE_DAEMON_CODE */

    /* signals */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = exit_signal_handler;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);

    sa.sa_handler = SIG_IGN;
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    sigaction(SIGALRM, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);

#ifndef DISABLE_DAEMON_CODE
    /* send parent process a signal */
    if (parentfd >= 0) {
        log(4, "closing parent pipe %d\n", parentfd);
        write(parentfd, &parentfd, sizeof(parentfd));
        close(parentfd);
    }

    /* now connect logger */
    if (loggerfd >= 0) {
        dup2(loggerfd, 1);
        dup2(loggerfd, 2);
        close(loggerfd);
    }
#endif /* DISABLE_DAEMON_CODE */
}

/** free memory used by a client, including sockets and the client
    struct itself */
static void free_client(struct client *client) {
    unsigned z;

    assert(client != NULL);
    assert(client->domain == NULL);
    assert(client->prev == NULL);
    assert(client->next == NULL);

    for (z = 0; z < client->num_sockets; z++)
        close(client->sockets[z]);

    if (client->font_buffer != NULL)
        free(client->font_buffer);

    for (z = 0; z < client->num_chats; z++) {
        free(client->chats[z]);
    }

    free(client);
}

/** add an unbound client to a domain; fails if the domain is full */
static int add_client(struct domain *domain, struct client *client) {
    assert(client->domain == NULL);

    if (domain->num_clients >= MAX_CLIENTS)
        return 0;

    if (domain->clients_head == NULL) {
        assert(domain->num_clients == 0);

        client->next = client;
        client->prev = client;
        domain->clients_head = client;
    } else {
        assert(domain->num_clients > 0);

        client->prev = domain->clients_head->prev;
        client->next = domain->clients_head;
        client->prev->next = client;
        client->next->prev = client;
    }

    domain->num_clients++;
    client->domain = domain;

    return 1;
}

/** remove a bound client from its damain */
static void remove_client(struct client *client) {
    assert(client->domain != NULL);
    assert(client->domain->num_clients > 0);

    client->domain->num_clients--;

    if (client->domain->num_clients == 0) {
        client->domain->clients_head = NULL;
    } else {
        client->prev->next = client->next;
        client->next->prev = client->prev;

        if (client->domain->clients_head == client)
            client->domain->clients_head = client->next;
    }

    client->prev = NULL;
    client->next = NULL;
    client->domain = NULL;
}

#ifndef DISABLE_LOGGING
/** generate a new client->name from the client IP address and nick
    name */
static void update_client_name(struct client *client) {
    struct sockaddr_in *addr_in = (struct sockaddr_in*)&client->address;
    char ip[16];

    inet_ntop(addr_in->sin_family, &addr_in->sin_addr,
              ip, sizeof(ip));

    if (client->have_position) {
        snprintf(client->name, sizeof(client->name),
                 "%s('%s';%u.%u.%u.%u)", ip,
                 client->info.noip.name,
                 client->info.ip[0], client->info.ip[1],
                 client->info.ip[2], client->info.ip[3]);
    } else {
        snprintf(client->name, sizeof(client->name),
                 "%s:%u", ip, addr_in->sin_port);
    }
}
#endif /* DISABLE_LOGGING */

/** create a new client and adds it to the domain */
static struct client *create_client(struct domain *domain, int sockfd,
#ifndef DISABLE_LOGGING
                                    struct sockaddr *addr, socklen_t addrlen,
#endif
                                    int randomfd) {
    struct client *client;
    int ret;
#ifdef HAVE_DEV_RANDOM
    ssize_t nbytes;
#endif

    client = calloc(1, sizeof(*client));
    if (client == NULL)
        return NULL;

#ifndef DISABLE_LOGGING
    if (addrlen > sizeof(client->address))
        addrlen = sizeof(client->address);
    memcpy(&client->address, addr, addrlen);
#endif /* DISABLE_LOGGING */

    /* a good random client id is vitally important for security,
       because secondary connections authorized themselves with it */
#ifdef HAVE_DEV_RANDOM
    nbytes = read(randomfd, &client->id, sizeof(client->id));
    if (nbytes < (ssize_t)sizeof(client->id)) {
        fprintf(stderr, "random number generation failed\n");
        free(client);
        return NULL;
    }
#else
    (void)randomfd;

    client->id = (random() << 24) + (random() << 16)
        + (random() << 8) + random();
#endif

    client->sockets[0] = sockfd;
    client->num_sockets = 1;
    client->timeout = time(NULL) + 60;

#ifndef DISABLE_LOGGING
    update_client_name(client);
#endif

    ret = add_client(domain, client);
    if (!ret) {
        log(1, "domain 0 is full, rejecting new client %s\n",
            client->name);
        free_client(client);
        return NULL;
    }

    log(2, "new client: %s\n", client->name);

    return client;
}

/** merge two clients */
static int append_client(struct client *dest, struct client *src,
                         unsigned *socket_index) {
    assert(dest->num_sockets > 0);
    assert(src->num_sockets > 0);
    assert(*socket_index < src->num_sockets);

    if (src->num_sockets + dest->num_sockets > MAX_SOCKETS)
        return -1;

    if (socket_index != NULL)
        *socket_index += dest->num_sockets;

    memcpy(dest->sockets + dest->num_sockets, src->sockets,
           src->num_sockets * sizeof(dest->sockets[0]));
    dest->num_sockets += src->num_sockets;
    src->num_sockets = 0;
    src->should_destroy = 1;

    return 0;
}

/** kill a client */
static void kill_client(struct client *client) {
    log(2, "kill_client %s\n", client->name);

    remove_client(client);
    free_client(client);
}

/** find a client with the specified id on the whole host (all
    domains) */
static struct client *get_client(struct host *host, uint32_t id) {
    struct domain *domain = host->domains_head;

    if (domain == NULL)
        return NULL;

    do {
        struct client *client = domain->clients_head;

        assert(domain->host == host);

        if (client != NULL) {
            do {
                assert(client->domain == domain);

                if (client->id == id)
                    return client;

                client = client->next;
            } while (client != domain->clients_head);
        }

        domain = domain->next;
    } while (domain != host->domains_head);

    return NULL;
}

/** find a domain by its password */
static struct domain *get_domain(struct host *host, const char *password) {
    struct domain *domain = host->domains_head;

    if (domain == NULL)
        return NULL;

    do {
        if (strcmp(password, domain->password) == 0)
            return domain;

        domain = domain->next;
    } while (domain != host->domains_head);

    return NULL;
}

/** create a domain and add it to the host */
static struct domain *create_domain(struct host *host, const char *password) {
    size_t password_len;
    struct domain *domain;

    password_len = strlen(password);
    if (password_len >= sizeof(domain->password)) {
        log(1, "password too long: %u\n", (unsigned)password_len);
        return NULL;
    }

    if (host->num_domains >= MAX_DOMAINS) {
        log(1, "domain table is full: %u\n", host->num_domains);
        return NULL;
    }

    domain = calloc(1, sizeof(*domain));
    if (domain == NULL)
        return NULL;

    memcpy(domain->password, password, password_len);
    domain->host = host;

    if (host->domains_head == NULL) {
        assert(host->num_domains == 0);

        domain->prev = domain;
        domain->next = domain;
        host->domains_head = domain;
    } else {
        assert(host->num_domains > 0);

        domain->prev = host->domains_head->prev;
        domain->next = host->domains_head;

        host->domains_head->prev->next = domain;
        host->domains_head->prev = domain;
    }

    host->num_domains++;

    log(2, "created domain '%s'\n", password);

    return domain;
}

/** kill a domain and remove it from the host */
static void kill_domain(struct domain *domain) {
    struct host *host;

    assert(domain != NULL);
    assert(domain->host != NULL);

    log(2, "killing domain '%s'\n", domain->password);

    host = domain->host;

    while (domain->num_clients > 0)
        kill_client(domain->clients_head->prev);

    host->num_domains--;

    if (host->num_domains == 0) {
        assert(domain->next == domain);
        assert(domain->prev == domain);

        host->domains_head = NULL;
    } else {
        if (domain == host->domains_head)
            host->domains_head = domain->next;

        domain->next->prev = domain->prev;
        domain->prev->next = domain->next;
    }

    free(domain);
}

/** move a bound client to another domain */
static int move_client(struct client *client, struct domain *domain) {
    int ret;
    struct domain *old_domain = client->domain;

    assert(client != NULL);
    assert(client->domain != NULL);
    assert(domain != NULL);
    assert(client->domain->host == domain->host);

    if (client->domain == domain)
        return 1;

    remove_client(client);
    ret = add_client(domain, client);
    if (!ret) {
        log(1, "domain '%s' is full\n", domain->password);
        add_client(old_domain, client);
        return 0;
    }

    return 1;
}

/** enqueue a chat packet in a client structure */
static void enqueue_client_chat(struct client *client,
                                const void *data, size_t size) {
    struct chat *chat;

    if (client->num_chats >= MAX_CHATS)
        return;

    chat = malloc(sizeof(*chat) - sizeof(chat->data) + size);
    if (chat == NULL)
        return;

    chat->size = size;
    memcpy(chat->data, data, size);

    client->chats[client->num_chats++] = chat;
}

/** broadcast a chat packet to all clients in a domain */
static void enqueue_chat(struct domain *domain,
                         const void *data, size_t size) {
    struct client *client = domain->clients_head;

    assert(size <= 2048);

    if (client == NULL)
        return;

    do {
        enqueue_client_chat(client, data, size);

        client = client->next;
    } while (client != domain->clients_head);
}

#ifndef DISABLE_LOGGING
/** dump a packet as text */
static void dump_packet(FILE *file, const unsigned char *data, size_t length) {
    size_t y;

    for (y = 0; y < length; y += 0x10, data += 0x10) {
        size_t x, columns = length - y;
        if (columns > 0x10)
            columns = 0x10;

        fprintf(file, "%08lx   ", (unsigned long)y);
        for (x = 0; x < columns; x++) {
            if (x == 0x08)
                fprintf(file, " ");

            fprintf(file, "%02x ", data[x]);
        }

        for (; x < 0x10; x++) {
            if (x == 0x08)
                fprintf(file, " ");

            fprintf(file, "   ");
        }

        fprintf(file, " ");
        for (x = 0; x < columns; x++)
            fputc(data[x] >= 0x20 && data[x] < 0x80 ? data[x] : '.', file);

        fprintf(file, "\n");
    }
}
#endif /* DISABLE_LOGGING */

/** read a 32 bit unsigned integer (intel byte order) */
static uint32_t read_uint32(const unsigned char *buffer) {
    return buffer[0] |
        buffer[1] << 8 |
        buffer[2] << 16 |
        buffer[3] << 24;
}

/** write a 32 bit unsigned integer (intel byte order) */
static void write_uint32(unsigned char *buffer, uint32_t value) {
    buffer[0] = value & 0xff;
    buffer[1] = (value >> 8) & 0xff;
    buffer[2] = (value >> 16) & 0xff;
    buffer[3] = (value >> 24) & 0xff;
}

/** send a response packet, tweaking some fields */
static void respond(struct client *client, unsigned socket_index,
                    unsigned sequence,
                    unsigned char *response, size_t response_length) {
    ssize_t nbytes;

    assert(response_length >= 16);
    assert(response[2] != 0x02 || response_length >= 24);
    assert(socket_index < client->num_sockets);

    /* copy packet sequence number */
    write_uint32(response + 12, (uint32_t)sequence);

    /* insert packet length and other stuff; that's a hack because
       I've been too lazy to make response constant and do this in all
       callers  */
    write_uint32(response + 8, (uint32_t)response_length);

    if (response[2] == 0x02)
        write_uint32(response + 16, (uint32_t)(response_length - 24));

    if (response[2] == 0x0c || response[2] == 0x0f)
        write_uint32(response + 20, client->id);

    /* dump it */
#ifndef DISABLE_LOGGING
    if (verbose >= 6) {
        printf("sending to client %s\n", client->name);
        dump_packet(stdout, response, response_length);
        printf("\n");
    }
#endif

    /* send it */
    nbytes = send(client->sockets[socket_index], response, response_length, 0);

    if (nbytes < (ssize_t)response_length) {
        log(1, "send failure, killing connection %s[%u]\n",
            client->name, socket_index);
        close(client->sockets[socket_index]);
        client->sockets[socket_index] = -1;
        return;
    }

    /* update timeout */
    client->timeout = time(NULL) + 60;
}

static void process_position_update(struct client *client,
                                    const unsigned char *data, size_t length) {
    const struct player_info *info = (const struct player_info*)(data + 44);

    assert(length == 0x8c);

    (void)length;

    if (memchr(info->noip.name, 0, sizeof(info->noip.name)) == NULL) {
        log(1, "client %s: no NUL character in name\n",
            client->name);
        return;
    }

    memcpy(&client->info, info, sizeof(client->info));

    if (!client->have_position) {
        client->have_position = 1;
#ifndef DISABLE_LOGGING
        update_client_name(client);
#endif /* DISABLE_LOGGING */
    }
}

static void handle_query_list(struct client *client, unsigned socket_index,
                              unsigned sequence) {
    struct domain *domain = client->domain;
    unsigned char buffer[4096];
    size_t pos;
    unsigned num = 0;

    memcpy(buffer, header_list, sizeof(header_list));
    pos = sizeof(header_list);

    if (domain->clients_head != NULL) {
        struct client *client2 = domain->clients_head;
        const size_t max_pos = sizeof(buffer) - sizeof(client->info.noip) - 4;

        do {
            if (client2->info.noip.name[0] != 0 &&
                !client2->should_destroy) {
                memcpy(buffer + pos, &client2->info.noip,
                       sizeof(client2->info.noip));
                num++;
                pos += sizeof(client2->info.noip);
            }

            client2 = client2->next;
        } while (pos <= max_pos && client2 != domain->clients_head);
    }

    write_uint32(buffer + 24, (uint32_t)num);
    write_uint32(buffer + 32, (uint32_t)num);

    memset(buffer + pos, 0, 4);
    pos += 4;

    respond(client, socket_index, sequence, buffer, pos);
}

/** send font info of all clients in this domain to the new client */
static void resend_fonts(struct client *client) {
    struct domain *domain = client->domain;
    struct client *p = domain->clients_head;

    assert(p != NULL);

    do {
        assert(p->domain == domain);

        if (p != client && p->font_buffer != NULL &&
            p->font_buffer_size > 0)
            enqueue_client_chat(client, p->font_buffer, p->font_buffer_size);
    } while (p != domain->clients_head);
}

/** checks the password and tries to log the client in; creates a new
    domain if required */
static int login(struct client *client, const char *password) {
    struct domain *domain;
    int ret;

    if (password[0] == 0) {
        log(1, "empty password from client %s, rejecting\n",
            client->name);
        client->should_destroy = 1;
        return 0;
    }

    domain = get_domain(client->domain->host, password);
    if (domain == NULL) {
        if (client->domain->host->config->password != NULL &&
            strcmp(password, client->domain->host->config->password) != 0) {
            log(1, "wrong password, rejecting client %s\n",
                client->name);
            client->should_destroy = 1;
            return 0;
        }

        domain = create_domain(client->domain->host, password);
        if (domain == NULL) {
            log(1, "domain creation failed, rejecting client %s\n",
                client->name);
            client->should_destroy = 1;
            return 0;
        }
    }

    ret = move_client(client, domain);
    if (!ret) {
        client->should_destroy = 1;
        return 0;
    }

    resend_fonts(client);

    client->authorized = 1;

    log(1, "client %s logged into domain '%s'\n",
        client->name, domain->password);

    return 1;
}

static void handle_poll(struct client *client, unsigned socket_index,
                        unsigned sequence) {
    if (client->num_chats > 0) {
        /* send the first chat entry */
        unsigned char buffer[4096];
        size_t pos;

        /* build the packet */
        memcpy(buffer, header_chat, sizeof(header_chat));
        pos = sizeof(header_chat);

        memcpy(buffer + pos, client->chats[0]->data,
               client->chats[0]->size);
        pos += client->chats[0]->size;

        memset(buffer + pos, 0, 5);
        pos += 5;

        /* free memory */
        free(client->chats[0]);
        client->num_chats--;
        if (client->num_chats > 0)
            memmove(client->chats, client->chats + 1,
                    sizeof(client->chats[0]) * client->num_chats);

        /* send packet */
        respond(client, socket_index, sequence, buffer, pos);
    } else {
        /* nothing in the queue */
        respond(client, socket_index, sequence,
                packet_no_chat,
                sizeof(packet_no_chat));
    }
}

/** respond to a packet from the client */
static void handle_packet(struct client *client, unsigned socket_index,
                          const unsigned char *data, size_t length) {
    unsigned sequence;

    sequence = read_uint32(data + 12);

    /* the first packet a client sends in a TCP connection */
    if (data[2] == 0x0b) {
        if (!client->handshake) {
            uint32_t master_id;

            assert(client->num_sockets == 1);

            if (length < 24) {
                /* too short */
                client->should_destroy = 1;
                return;
            }

            master_id = read_uint32(data + 20);
            if (master_id != 0) {
                /* this is a secondary connection; find the primary
                   one and merge both clients */
                struct client *master;
                int ret;

                master = get_client(client->domain->host, master_id);
                if (master == NULL) {
                    log(1, "invalid master id in handshake, killing client %s\n",
                        client->name);
                    client->should_destroy = 1;
                    return;
                }

                log(2, "appending client %s to %s\n",
                    client->name, master->name);

                ret = append_client(master, client, &socket_index);
                if (ret < 0) {
                    client->should_destroy = 1;
                    return;
                }

                client = master;
            }
        }

        client->handshake = 1;

        /* send the response */
        snprintf((char*)packet_handshake_response + 26, 6, "%u", client->domain->host->config->port);

        respond(client, socket_index, sequence,
                packet_handshake_response,
                sizeof(packet_handshake_response));
        return;
    }

    if (!client->handshake) {
        /* handshake omitted, kill this client */
        log(1, "handshake omitted, killing client %s\n",
            client->name);
        client->should_destroy = 1;
        return;
    }

    /* the "0x0e" packet */
    if (data[2] == 0x0e) {
        /* some strange packet. dunno what this is, but we respond
           something */
        respond(client, socket_index, sequence,
                packet_response2,
                sizeof(packet_response2));
        return;
    }

    /* the rest must be 0x00 */
    if (data[2] != 0x00) {
        log(1, "unknown code %u from client %s, killing\n",
            data[2], client->name);
        client->should_destroy = 1;
        return;
    }

    if (length < 24) {
        /* too short */
        client->should_destroy = 1;
        return;
    }

    /* position update - handle this before login, so we have the nick
       name available when the login is logged */
    if (data[20] == 0x00 && data[22] != 0x02) {
        /* 00 00 10 00 or 00 00 00 00 */

        /* only packets with length 0x8c contain a valid position;
           after a reconnect, the clients sends shorter packets */
        if (length == 0x8c)
            process_position_update(client, data, length);

        /* the response is sent later in this function */
    }

    /* handle login */
    if (memchr(data + 24, 0, 20) == NULL) {
        log(1, "malformed password field from, killing client %s\n",
            client->name);
        client->should_destroy = 1;
        return;
    }

    if (!client->authorized ||
        strcmp((const char*)(data + 24), client->domain->password) != 0) {
        /* the password is sent with every 0x00 packet (what a waste);
           we use the first 0x00 packet to log in and ignore all
           following passwords */
        int ret;

        ret = login(client, (const char*)(data + 24));
        if (!ret)
            return;
    }

    /* now check the 0x00 subtype */
    if (data[22] == 0x02) {
        /* 00 00 02 00: client polls */

        handle_query_list(client, socket_index, sequence);
    } else if (data[20] == 0x01 && data[22] == 0x01) {
        /* 01 00 01 00: poll chat */

        handle_poll(client, socket_index, sequence);
    } else if (data[20] == 0x01) {
        /* 01 00 00 00: chat; data[52] is the code of the
           sub-sub-type */

        /* data[52]==0x02 is evil for some reason, it lets the
           UOAutoMap client crash under certain circumstances; only
           broadcast 0x01 (chat text) and 0x03 (font and color) to the
           other clients */
        if (length < 2048 &&
            (data[52] == 0x01 || data[52] == 0x03))
            enqueue_chat(client->domain, data + 52, length - 52);

        /* remember font+color, we need this when a new client
           connects, to give him information about all existing
           clients */
        if (data[52] == 0x03) {
            if (client->font_buffer != NULL)
                free(client->font_buffer);
            client->font_buffer_size = length - 52;
            client->font_buffer = malloc(client->font_buffer_size);
            if (client->font_buffer != NULL) {
                memcpy(client->font_buffer, data + 52, client->font_buffer_size);
            }
        }

        respond(client, socket_index, sequence,
                packet_ack,
                sizeof(packet_ack));
    } else {
        /* 00 00 10 00 or 00 00 00 00: client sends position update */

        /* the contents of the request are already handled above, but
           we send the ACK response here, because the login may have
           failed meanwhile */

        respond(client, socket_index, sequence,
                packet_ack,
                sizeof(packet_ack));
    }
}

/** see if more data is available, don't block */
static ssize_t select_more_data(int sockfd, unsigned char *buffer,
                                size_t max_len) {
    fd_set rfds;
    int ret;
    struct timeval tv;

    FD_ZERO(&rfds);
    FD_SET(sockfd, &rfds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    ret = select(sockfd + 1, &rfds, NULL, NULL, &tv);
    if (ret < 0)
        return -1;
    if (ret == 0)
        return 0;

    return recv(sockfd, buffer, max_len, 0);
}

/** select() told us that data is available on this socket */
static void client_data_available(struct client *client,
                                  unsigned socket_index) {
    unsigned char buffer[4096];
    ssize_t nbytes;
    size_t position = 0, length;

    assert(socket_index < client->num_sockets);

    /* read from stream */
    nbytes = recv(client->sockets[socket_index], buffer, sizeof(buffer), 0);
    if (nbytes <= 0) {
        log(2, "client %s[%u] disconnected\n", client->name, socket_index);
        close(client->sockets[socket_index]);
        client->sockets[socket_index] = -1;
        return;
    }

#ifndef DISABLE_LOGGING
    if (verbose >= 6) {
        printf("received from client %s\n", client->name);
        dump_packet(stdout, buffer, (size_t)nbytes);
        printf("\n");
    }
#endif

    /* the recv() may have read more than one packet - handle all of
       them serially */
    while (nbytes > 0 && !client->should_destroy) {
        if (nbytes < 16) {
            /* we need 16 bytes for a header */
            log(1, "packet from client %s is too small (%lu bytes)\n",
                client->name, (unsigned long)nbytes);
            client->should_destroy = 1;
            return;
        }

        /* check header */
        if (buffer[0] != 0x05 || buffer[1] != 0x00 ||
            buffer[3] != 0x03 || buffer[4] != 0x10) {
            log(1, "malformed packet, killing client %s\n",
                client->name);
            client->should_destroy = 1;
            return;
        }

        /* length check - check if the UOAM packet length is OK */
        length = read_uint32(buffer + 8);

        if (length < 16 || length > (size_t)nbytes) {
            log(1, "malformed length %lu in packet, killing client %s\n",
                (unsigned long)length, client->name);
            client->should_destroy = 1;
            return;
        }

        /* handle packet */
        handle_packet(client, socket_index, buffer + position, length);

        nbytes -= (ssize_t)length;
        position += length;

        /* try to read more data - the first read may have stopped at
           the buffer boundary, i.e. the rest of a packet may come
           with the next recv() call, so do it here to prevent an
           error at the length check */
        if (nbytes > 0) {
            ssize_t ret;

            memmove(buffer, buffer + position, (size_t)nbytes);
            position = 0;

            ret = select_more_data(client->sockets[socket_index],
                                   buffer + nbytes, sizeof(buffer) - nbytes);
            if (ret > 0)
                nbytes += ret;
        }
    }
}

/** welcome to main() */
int main(int argc, char **argv) {
    struct config config;
    int ret, randomfd, sockfd;
    struct host host;
    struct domain *domain_zero, *domain;

    /* parse command line arguments */
    read_config(&config, argc, argv);

    /* setup uid, sockets, chroot, logger etc. */
    setup(&config, &randomfd, &sockfd);

    /* create domain 0 */
    memset(&host, 0, sizeof(host));
    host.config = &config;

    domain_zero = create_domain(&host, "");
    if (domain_zero == NULL) {
        fprintf(stderr, "failed to create domain 0\n");
        exit(1);
    }

    /* main loop */
    log(1, "starting uoamhub v%s\n", VERSION);

    do {
        fd_set rfds;
        int max_fd;
        time_t now = time(NULL);

        /* select() on all sockets */
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);
        max_fd = sockfd;

        domain = host.domains_head;
        assert(domain == domain_zero);

        do {
            struct client *client, *next_client = domain->clients_head;

            while (next_client != NULL) {
                int z;

                client = next_client;
                next_client = client->next;
                if (next_client == domain->clients_head)
                    next_client = NULL;

                assert(client->domain == domain);

                if (client->should_destroy) {
                    kill_client(client);
                    continue;
                }

                if (client->num_sockets == 0) {
                    log(1, "client %s disconnected\n", client->name);
                    kill_client(client);
                    continue;
                }

                if (now > client->timeout) {
                    log(1, "timeout on client %s\n", client->name);
                    kill_client(client);
                    continue;
                }

                for (z = client->num_sockets - 1; z >= 0; z--) {
                    if (client->sockets[z] < 0) {
                        if (z < (int)client->num_sockets - 1)
                            client->sockets[z] = client->sockets[client->num_sockets - 1];
                        client->num_sockets--;
                    } else {
                        FD_SET(client->sockets[z], &rfds);
                        if (client->sockets[z] > max_fd)
                            max_fd = client->sockets[z];
                    }
                }
            }

            if (domain != domain_zero && domain->num_clients == 0) {
                /* empty domain, delete it */
                domain = domain->next;
                kill_domain(domain->prev);
                assert(host.domains_head == domain_zero);
                continue;
            }

            domain = domain->next;
        } while (domain != host.domains_head);

        ret = select(max_fd + 1, &rfds, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno == EINTR)
                continue;

            log(0, "select failed: %s\n", strerror(errno));
            break;
        }

        if (ret == 0) {
            log(0, "select returned %d\n", ret);
            sleep(1);
        }

        /* read on all sockets where FD_ISSET is true */
        if (FD_ISSET(sockfd, &rfds)) {
            struct sockaddr addr;
            socklen_t addrlen = sizeof(addr);

            ret = accept(sockfd, &addr, &addrlen);
            if (ret >= 0) {
                create_client(domain_zero, ret,
#ifndef DISABLE_LOGGING
                              &addr, addrlen,
#endif
                              randomfd);
            } else {
                log(0, "accept failed: %s\n", strerror(errno));
            }
        }

        domain = host.domains_head;
        assert(domain == domain_zero);

        do {
            struct client *client, *next_client = domain->clients_head;

            while (next_client != NULL) {
                unsigned z;

                client = next_client;
                next_client = client->next;
                if (next_client == domain->clients_head)
                    next_client = NULL;

                assert(client->domain == domain);

                for (z = 0; z < client->num_sockets; z++) {
                    if (FD_ISSET(client->sockets[z], &rfds)) {
                        FD_CLR(client->sockets[z], &rfds);
                        client_data_available(client, z);

                        if (client->should_destroy)
                            break;
                    }
                }
            }

            domain = domain->next;
        } while (domain != host.domains_head);
    } while (!should_exit);

    /* cleanup */
    close(sockfd);

    while (host.num_domains > 0)
        kill_domain(host.domains_head->prev);

    free_config(&config);

    log(1, "exiting uoamhub v%s\n", VERSION);
    return 0;
}
