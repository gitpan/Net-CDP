/*
 * $Id: cdp_encoding.h,v 1.1.1.1 2004/06/04 06:01:29 mchapman Exp $
 */

#ifndef _CDP_ENCODING_H
#define _CDP_ENCODING_H

#include "cdp.h"

/*
 * CDP chunk types.
 */
#define CDP_TYPE_DEVICE_ID       0x0001
#define CDP_TYPE_ADDRESS         0x0002
#define CDP_TYPE_PORT_ID         0x0003
#define CDP_TYPE_CAPABILITIES    0x0004
#define CDP_TYPE_IOS_VERSION     0x0005
#define CDP_TYPE_PLATFORM        0x0006
#define CDP_TYPE_IP_PREFIX       0x0007

#define CDP_TYPE_VTP_MGMT_DOMAIN 0x0009
#define CDP_TYPE_NATIVE_VLAN     0x000a
#define CDP_TYPE_DUPLEX          0x000b

struct cdp_packet * cdp_decode(const u_int8_t *, size_t, char *);
u_int16_t cdp_decode_checksum(const u_int8_t *, size_t);
ssize_t cdp_encode(const struct cdp_packet *, u_int8_t *, size_t);

#endif /* _CDP_ENCODING_H */
