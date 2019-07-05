#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libnetrc.h"

static int netrc_cmp(const char *wanthost, const char *foundhost,
		const char *wantuser, const char *founduser,
		const char *wantpwd, const char *foundpwd)
{
	if (wanthost && strcmp(wanthost, foundhost ?: ""))
		return -1;
	if (wantuser && strcmp(wantuser, founduser ?: ""))
		return -1;
	if (wantpwd && strcmp(wantpwd, foundpwd ?: ""))
		return -1;
	/* all wanted items match */
	return 0;
}
#define xfree(x) if (x) free(x)

/* fill user+pwd for host, or pwd for host+user */
int lib_netrc(const char *host, char **user, char **pwd)
{
	char *line = NULL;
	size_t linesize = 0;
	FILE *fp;
	char *tok, *val;
	char *h, *u, *p;
	char *file;
	int result = -1, ret;

	/* read .netrc in $HOME, or /var/lib if $HOME not set */
	asprintf(&file, "%s/.netrc", getenv("HOME") ?: "/var/lib");

	/* open netrc file */
	fp = fopen(file, "r");
	if (!fp)
		goto fail_fopen;

	h = u = p = NULL;
	while (1) {
		ret = getline(&line, &linesize, fp);
		if (ret <= 0) {
			if (feof(fp) && h && !netrc_cmp(host, h, user ? *user : NULL, u, pwd ? *pwd : NULL, p))
				goto found;
			goto fail_read;
		}
		if (line[0] == '#')
			continue;
		static const char sep[] = " \t\r\n\v\f";
		for (tok = strtok(line, sep); tok; tok = strtok(NULL, sep)) {
			val = strtok(NULL, sep);
			if (!val)
				continue;

			if (!strcmp(tok, "machine")) {
				/* new machine, compare prev when we had one */
				if (h && !netrc_cmp(host, h, user ? *user : NULL, u, pwd ? *pwd : NULL, p))
					/* found */
					goto found;
				/* clear all values */
				xfree(h);
				xfree(u);
				xfree(p);
				h = strdup(val ?: "");
				u = p = NULL;

			} else if (!strcmp(tok, "login")) {
				xfree(u);
				u = strdup(val ?: "");

			} else if (!strcmp(tok, "password")) {
				xfree(p);
				p = strdup(val ?: "");
			}
		}
	}
found:
	result = 0;
	/* assign results */
	if (u && user && !*user) {
		*user = u;
		u = NULL;
		++result;
	}
	if (p && pwd && !*pwd) {
		*pwd = p;
		p = NULL;
		++result;
	}

fail_read:
	fclose(fp);
	xfree(h);
	xfree(u);
	xfree(p);
	xfree(line);
fail_fopen:
	free(file);

	return result;
}
