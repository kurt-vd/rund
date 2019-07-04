#ifndef _libnetrc_h_
#define _libnetrc_h_

#ifdef __cplusplus
extern "C" {
#endif

/* lookup user+pwd for host, or pwd for host+user */
extern int lib_netrc(const char *host, char **user, char **pwd);

#ifdef __cplusplus
}
#endif
#endif
