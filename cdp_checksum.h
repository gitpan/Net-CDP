/*
 * $Id: cdp_checksum.h,v 1.1.1.1 2004/06/04 06:01:29 mchapman Exp $
 */

#ifndef _CDP_CHECKSUM_H
#define _CDP_CHECKSUM_H

#include <sys/types.h>

/*
 * Calculate checksum for buffer.
 */
u_int16_t cdp_checksum(const u_int8_t *, u_int16_t);

#endif /* _CDP_CHECKSUM_H */
