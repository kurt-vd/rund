#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <syslog.h>

#include "liburi.h"

void lib_clean_uri(struct uri *p)
{
	if (p->params)
		free(p->params);
	memset(p, 0, sizeof(*p));
}

const char *lib_uri_param(struct uri *p, const char *key)
{
	int j;

	for (j = 0; j < p->nparams; j += 2) {
		if (!strcmp(p->params[j], key))
			/* return value, or empty non-null string */
			return p->params[j+1] ?: "";
	}
	return NULL;
}

void lib_parse_uri(const char *uri, struct uri *p)
{
	static char *copy;
	static char *hoststr;
	char *str, *tmp;

	memset(p, 0, sizeof(*p));
	if (copy)
		free(copy);
	copy = strdup(uri ?: "");
	uri = copy;

	str = strstr(uri, "://");
	if (str) {
		/* save proto */
		*str = 0;
		p->scheme = uri;
		uri = str+3;
	}

	str = strchr(uri, '?');
	if (str) {
		/* save params */
		*str++ = 0;
		for (str = strtok(str, "&"); str; str = strtok(NULL, "&")) {
			if (p->nparams +2 > p->sparams) {
				p->sparams += 16;
				p->params = realloc(p->params, sizeof(void *)*p->sparams);
#if 0
				if (!p->params)
					mylog(LOG_ERR, "realloc %u params: %s",
							p->sparams, ESTR(errno));
#endif
			}
			p->params[p->nparams++] = str;
			str = strchr(str, '=');
			if (str)
				*str++ = 0;
			p->params[p->nparams++] = str;
		}
	}

	str = strchr(uri, '#');
	if (str) {
		/* save fragment */
		*str++ = 0;
		p->fragment = str;
	}

	if (*uri == '@' || *uri == '/')
		goto unix_sock;

	str = strchr(uri, '@');
	if (str) {
		*str++ = 0;
		tmp = strchr(uri, ':');
		if (tmp)
			*tmp++ = 0;
		p->user = uri;
		p->pass = tmp;
		uri = str;
	}

	if (*uri == '[') {
		/* ipv6 numerical */
		p->host = uri+1;
		str = strchr(uri+1, ']');
		if (str) {
			*str = 0;
			uri = str+1;
			str = strpbrk(uri, ":/?");
		} else
			/* not good ... but return */
			goto done;
	}

	str = strpbrk(uri, ":/");
	if (!str) {
		if (*uri)
			p->host = uri;
		goto done;
	}

	if (*str == ':') {
		if (!strchr(str+1, '/') && strchr(str+1, ':')) {
			/* multiple ::, no /, suspect ipv6 hostname */
			if (*uri)
				p->host = uri;
			goto done;
		}
		*str = 0;
		if (str > uri)
			/* save host */
			p->host = uri;
		uri = str+1;
		p->port = strtoul(uri, &str, 10);
		if (str > uri && (!*str || *str == '/'))
			/* looks like a IP port identifier */
			uri = str;
		else if (str > uri && *str == ':')
			/* looks like a IP port identifier */
			uri = str+1;
		else
			p->port = 0;
	} else if (str > uri) {
		/* duplicate host, without loosing the seperating / */
		if (hoststr)
			free(hoststr);
		hoststr = strndup(uri, str-uri);
		p->host = hoststr;
		uri = str;
	}
unix_sock:
	if (*uri)
		/* save path */
		p->path = uri;
done:
		str = strpbrk(uri, ":/");
	return;
}
