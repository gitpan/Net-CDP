/*
 * $Id: cdp_address.c,v 1.1 2004/09/02 04:25:06 mchapman Exp $
 */

#include <config.h>

#include "cdp.h"

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

/*
 * These tables were derived from the Cisco documentation at
 * http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/frames.htm
 */

u_int8_t cdp_address_protocol_type[] = {
	/* CDP_ADDR_PROTO_CLNP      */ 0x01,
	/* CDP_ADDR_PROTO_IPV4      */ 0x01,
	/* CDP_ADDR_PROTO_IPV6      */ 0x02,
	/* CDP_ADDR_PROTO_DECNET    */ 0x02,
	/* CDP_ADDR_PROTO_APPLETALK */ 0x02,
	/* CDP_ADDR_PROTO_IPX       */ 0x02,
	/* CDP_ADDR_PROTO_VINES     */ 0x02,
	/* CDP_ADDR_PROTO_XNS       */ 0x02,
	/* CDP_ADDR_PROTO_APOLLO    */ 0x02
};

u_int8_t cdp_address_protocol_length[] = {
	/* CDP_ADDR_PROTO_CLNP      */ 1,
	/* CDP_ADDR_PROTO_IPV4      */ 1,
	/* CDP_ADDR_PROTO_IPV6      */ 8,
	/* CDP_ADDR_PROTO_DECNET    */ 8,
	/* CDP_ADDR_PROTO_APPLETALK */ 8,
	/* CDP_ADDR_PROTO_IPX       */ 8,
	/* CDP_ADDR_PROTO_VINES     */ 8,
	/* CDP_ADDR_PROTO_XNS       */ 8,
	/* CDP_ADDR_PROTO_APOLLO    */ 8
};

u_int8_t cdp_address_protocol[][8] = {
	/* CDP_ADDR_PROTO_CLNP      */ { 0x81 },
	/* CDP_ADDR_PROTO_IPV4      */ { 0xcc },
	/* CDP_ADDR_PROTO_IPV6      */ { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x80, 0xdd },
	/* CDP_ADDR_PROTO_DECNET    */ { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x60, 0x03 },
	/* CDP_ADDR_PROTO_APPLETALK */ { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x80, 0x9b },
	/* CDP_ADDR_PROTO_IPX       */ { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x81, 0x37 },
	/* CDP_ADDR_PROTO_VINES     */ { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x80, 0xc4 },
	/* CDP_ADDR_PROTO_XNS       */ { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x06, 0x00 },
	/* CDP_ADDR_PROTO_APOLLO    */ { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x80, 0x19 },
};

struct cdp_address *
cdp_address_new(u_int8_t protocol_type, u_int8_t protocol_length, const u_int8_t *protocol, u_int16_t address_length, const u_int8_t *address) {
	struct cdp_address *x;

	x = (struct cdp_address *)calloc(1, sizeof(struct cdp_address));
	x->protocol_type = protocol_type;
	x->protocol_length = protocol_length;
	x->protocol = (u_int8_t *)calloc(protocol_length, sizeof(u_int8_t));
	memcpy(x->protocol, protocol, protocol_length * sizeof(u_int8_t));
	x->address_length = address_length;
	x->address = (u_int8_t *)calloc(address_length, sizeof(u_int8_t));
	memcpy(x->address, address, address_length * sizeof(u_int8_t));
	return x;
}

struct cdp_address *
cdp_address_dup(const struct cdp_address *x) {
	return cdp_address_new(
		x->protocol_type,
		x->protocol_length,
		x->protocol,
		x->address_length,
		x->address
	);
}

void
cdp_address_free(struct cdp_address *address) {
	free(address->protocol);
	free(address->address);
	free(address);
}
