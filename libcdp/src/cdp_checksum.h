/*
 * $Id: cdp_checksum.h,v 1.1 2004/09/02 04:25:06 mchapman Exp $
 */

#ifndef _CDP_CHECKSUM_H
#define _CDP_CHECKSUM_H

#include <config.h>

/*
 * Calculate checksum for buffer.
 */
u_int16_t cdp_checksum(const u_int8_t *, u_int16_t);

#endif /* _CDP_CHECKSUM_H */
