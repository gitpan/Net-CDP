/*
 * $Id: cdp_checksum.c,v 1.2 2004/06/04 06:11:44 mchapman Exp $
 */

#include "cdp.h"

/*
 * Actually, this is the standard IP checksum algorithm.
 */
u_int16_t
cdp_checksum(const u_int8_t *data, u_int16_t length) {
	register long sum = 0;
	u_int16_t *d;
	
	d = (u_int16_t *)data;
	while (length > 1) {
		sum += *d++;
		length -= sizeof(u_int16_t);
	}
	if (length)
		sum += htons(((u_int16_t)*data));
	
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}
