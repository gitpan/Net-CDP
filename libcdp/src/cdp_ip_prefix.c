/*
 * $Id: cdp_ip_prefix.c,v 1.1 2004/09/02 04:25:06 mchapman Exp $
 */

#include <config.h>

#include "cdp.h"

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

struct cdp_ip_prefix *
cdp_ip_prefix_new(const u_int8_t *network, u_int8_t length) {
	struct cdp_ip_prefix *x;

	x = (struct cdp_ip_prefix *)calloc(1, sizeof(struct cdp_ip_prefix));
	memcpy(x->network, network, 4 * sizeof(u_int8_t));
	x->length = length;
	return x;
}

struct cdp_ip_prefix *
cdp_ip_prefix_dup(const struct cdp_ip_prefix *x) {
	return cdp_ip_prefix_new(
		x->network,
		x->length
	);
}

void
cdp_ip_prefix_free(struct cdp_ip_prefix *ip_prefix) {
	free(ip_prefix);
}
