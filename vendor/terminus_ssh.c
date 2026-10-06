/* `libssh2_scp_recv2` reports the remote size through a platform `struct
 * stat`, which translate-c cannot render on musl (its timespec fields turn
 * the struct opaque). The size is all the caller reads, so it is taken out
 * here and only it crosses into Zig. */
#include <string.h>
#include "terminus_ssh.h"

LIBSSH2_CHANNEL *terminus_scp_recv(LIBSSH2_SESSION *session, const char *path,
                                   libssh2_int64_t *size)
{
    libssh2_struct_stat sb;
    LIBSSH2_CHANNEL *channel;
    memset(&sb, 0, sizeof(sb));
    channel = libssh2_scp_recv2(session, path, &sb);
    if (channel)
        *size = (libssh2_int64_t)sb.st_size;
    return channel;
}
