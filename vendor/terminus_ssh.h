/* Aggregate header for the `ssh2` translate-c module: libssh2 plus the
 * winsock APIs (getaddrinfo, WSAStartup, ...) that the SSH transport
 * needs. std.Io.net cannot provide the socket here: on Windows it hands
 * out raw AFD device handles, which libssh2's send()/recv() reject. */
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#include <libssh2.h>
