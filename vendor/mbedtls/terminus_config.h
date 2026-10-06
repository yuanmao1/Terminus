/* Terminus additions on top of mbedTLS's default `mbedtls_config.h`, applied
 * through MBEDTLS_USER_CONFIG_FILE by build.zig.
 *
 * Threading: the daemon serves each client on its own thread, and libssh2's
 * mbedTLS backend shares one CTR-DRBG across every session in the process.
 * Without these two the DRBG and the PSA key store have no lock. */
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_PTHREAD
