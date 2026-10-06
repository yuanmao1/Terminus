/* Aggregate header for the `ssh2` translate-c module: libssh2 plus the
 * socket APIs (getaddrinfo, WSAStartup, ...) that the SSH transport
 * needs. std.Io.net cannot provide the socket here: on Windows it hands
 * out raw AFD device handles, which libssh2's send()/recv() reject. */
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>
#endif
#include <libssh2.h>

/* vendor/terminus_ssh.c */
LIBSSH2_CHANNEL *terminus_scp_recv(LIBSSH2_SESSION *session, const char *path,
                                   libssh2_int64_t *size);
