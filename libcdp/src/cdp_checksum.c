/*
 * $Id: cdp_checksum.c,v 1.1 2004/09/02 04:25:06 mchapman Exp $
 */

#include <config.h>

#include "cdp.h"

/*
 * Actually, this is the standard IP checksum algorithm.
 */
u_int16_t
cdp_checksum(const u_int8_t *data, u_int16_t length) {
	register long sum = 0;
	register const u_int16_t *d = (const u_int16_t *)data;
	
	while (length > 1) {
		sum += *d++;
		length -= 2;
	}
	if (length)
		sum += htons(*(const u_int8_t *)d);
	
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}
