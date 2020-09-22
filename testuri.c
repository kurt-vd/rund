#include <stdio.h>
#include "liburi.h"

int main(int argc, char *argv[])
{
	int j,k;

	for (j = 1; j < argc; ++j) {
		struct uri uri = {};

		lib_parse_uri(argv[j], &uri);
		printf("%s\n", argv[j]);
		printf("\t'%s' :// '%s' : '%s' @ '%s' : '%u' '%s' # '%s'",
				uri.scheme ?: "",
				uri.user ?: "",
				uri.pass ?: "",
				uri.host ?: "",
				uri.port,
				uri.path ?: "",
				uri.fragment ?: "");
		if (uri.nparams) {
			printf(" ?");
			for (k = 0; k < uri.nparams; k += 2) {
				printf(" %s", uri.params[k]);
				if (uri.params[k+1])
					printf("=%s", uri.params[k+1]);
			}
		}
		printf("\n");
	}
	return 0;
}
