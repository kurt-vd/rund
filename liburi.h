#ifndef _liburi_h_
#define _liburi_h_

#ifdef __cplusplus
extern "C" {
#endif

/* URI parser */
struct uri {
	const char *scheme;
	const char *host;
	int port;
	const char *user;
	const char *pass;
	const char *path;
	const char *fragment;
	int nparams; /* used */
	int sparams; /* allocated */
	char **params;
};

extern void lib_parse_uri(const char *uri, struct uri *);
extern void lib_clean_uri(struct uri *);
extern const char *lib_uri_param(struct uri *p, const char *key);

#ifdef __cplusplus
}
#endif
#endif
