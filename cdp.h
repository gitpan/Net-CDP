/*
 * $Id: cdp.h,v 1.2 2004/06/08 01:36:36 mchapman Exp $
 */

#ifndef _CDP_H
#define _CDP_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif /* _GNU_SOURCE */

#include <sys/types.h>
#include <pcap.h>
#include <libnet.h>

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/

#define CDP_VERSION "0.03"
#define CDP_VERSION_MAJOR 0
#define CDP_VERSION_MINOR 3

/*
 * The size of the error buffer to be passed to functions that expect one.
 */
#define CDP_ERRBUF_SIZE 256

/******************************************************************************/

/*
 * Dup and free operators for data stored in linked lists.
 */
typedef void * (*cdp_dup_fn_t)(const void *);
typedef void (*cdp_free_fn_t)(void *);

/*
 * Opaque container for a linked list node.
 */
typedef struct _cdp_llist_item_t {
	struct _cdp_llist_item_t *next;
	void *x;
} cdp_llist_item_t;

/*
 * Opaque linked list.
 */
typedef struct {
	cdp_dup_fn_t dup_fn;
	cdp_free_fn_t free_fn;
	u_int32_t count;
	
	cdp_llist_item_t *head;
	cdp_llist_item_t *tail;
} cdp_llist_t;

/*
 * Linked lists are append-only. This means they only ever grow, and
 * elements will appear in the list in the order in which they were
 * added.
 *
 * The cdp_llist_dup function makes a deep copy of the specified llist
 * using the cdp_dup_fn_t that was provided when the llist was created.
 *
 * Similarly, cdp_llist_free deeply frees the llist using the cdp_free_fn_t
 * provided when the llist was created.
 *
 * cdp_llist_append appends a *copy* of the element (using the cdp_dup_fn_t).
 * Don't supply a copy or you'll get memory leaks.
 */
cdp_llist_t * cdp_llist_new(cdp_dup_fn_t, cdp_free_fn_t);
cdp_llist_t * cdp_llist_dup(const cdp_llist_t *);
void cdp_llist_append(cdp_llist_t *, const void *);
void cdp_llist_free(cdp_llist_t *);

#define cdp_llist_count(LLIST) ((const u_int32_t)((LLIST)->count))

/*
 * Linked list iterator.
 *
 * void frobnicate(void *);
 *
 * void frobnicate_all(const cdp_llist_t *llist) {
 *     cdp_llist_iter_t iter;
 * 
 *     for (iter = cdp_llist_iter(llist); iter; iter = cdp_llist_next(iter))
 *         frobnicate(cdp_llist_get(iter));
 * }
 */
typedef const cdp_llist_item_t *cdp_llist_iter_t;
#define cdp_llist_iter(LLIST) ((cdp_llist_iter_t)((LLIST)->head))
#define cdp_llist_get(ITER) ((ITER)->x)
#define cdp_llist_next(ITER) ((ITER)->next)

/******************************************************************************/

/*
 * cdp_recv flags.
 */
#define CDP_RECV_NONBLOCK      0x01
#define CDP_RECV_DECODE_ERRORS 0x02

/*
 * Get a list of strings representing available ports.
 */
cdp_llist_t * cdp_get_ports(char *);

/*
 * Opaque CDP listener/advertiser object.
 */
typedef struct cdp {
	pcap_t *pcap;
	libnet_t *libnet;
	
	char *port;
	u_int8_t mac[6];
	cdp_llist_t *addresses;
	
	const struct pcap_pkthdr *header;
	const u_int8_t *data;
} cdp_t;

cdp_t * cdp_new(const char *, char *);
void cdp_free(cdp_t *);

const char * cdp_get_port(cdp_t *);
const cdp_llist_t * cdp_get_addresses(cdp_t *);
int cdp_get_fd(cdp_t *);

struct cdp_packet * cdp_recv(cdp_t *, int, char *);
int cdp_send(cdp_t *, const struct cdp_packet *, char *);

/******************************************************************************/

/*
 * Predefined protocol_type/protocol_length/protocol combinations.
 */
#define CDP_ADDR_PROTO_CLNP      0
#define CDP_ADDR_PROTO_IPV4      1
#define CDP_ADDR_PROTO_IPV6      2
#define CDP_ADDR_PROTO_DECNET    3
#define CDP_ADDR_PROTO_APPLETALK 4
#define CDP_ADDR_PROTO_IPX       5
#define CDP_ADDR_PROTO_VINES     6
#define CDP_ADDR_PROTO_XNS       7
#define CDP_ADDR_PROTO_APOLLO    8

#define CDP_ADDR_PROTO_MAX       CDP_ADDR_PROTO_APOLLO

extern u_int8_t cdp_address_protocol_type[];
extern u_int8_t cdp_address_protocol_length[];
extern u_int8_t cdp_address_protocol[][8];

/*
 * CDP address object.
 */
struct cdp_address {
	u_int8_t protocol_type;
	u_int8_t protocol_length;
	u_int8_t *protocol;
	u_int16_t address_length;
	u_int8_t *address;
};

struct cdp_address * cdp_address_new(u_int8_t, u_int8_t, const u_int8_t *, u_int16_t, const u_int8_t *);
struct cdp_address * cdp_address_dup(const struct cdp_address *);
void cdp_address_free(struct cdp_address *);

/******************************************************************************/

/*
 * CDP IP Prefix object.
 */
struct cdp_ip_prefix {
	u_int8_t network[4];
	u_int8_t length;
};

struct cdp_ip_prefix * cdp_ip_prefix_new(const u_int8_t *, u_int8_t);
struct cdp_ip_prefix * cdp_ip_prefix_dup(const struct cdp_ip_prefix *);
void cdp_ip_prefix_free(struct cdp_ip_prefix *);

/******************************************************************************/

/*
 * CDP capabilities.
 */
#define CDP_CAP_ROUTER             0x01
#define CDP_CAP_TRANSPARENT_BRIDGE 0x02
#define CDP_CAP_SOURCE_BRIDGE      0x04
#define CDP_CAP_SWITCH             0x08
#define CDP_CAP_HOST               0x10
#define CDP_CAP_IGMP               0x20
#define CDP_CAP_REPEATER           0x40

/*
 * CDP packet.
 *
 * The packet field must always exist. It is always preallocated with
 * at least BUFSIZ bytes of space -- don't shrink it to less than this.
 *
 * packet_length indicates the number of bytes actually used in packet to
 * represent the CDP packet in encoded form. You don't need to touch this
 * since cdp_packet_update will update it as necessary.
 * 
 * You can fiddle with the fields directly. Any field which is a pointer can
 * also be NULL, indicating that the field does not "exist" in the packet,
 * ie. it wasn't received and it won't be sent.
 *
 * cdp_generate will generate a packet with most values filled out for you.
 * Pass a cdp_t * object in as the first argument to associate the packet with
 * the device used by that object.
 */
struct cdp_packet {
	u_int8_t *packet;
	size_t packet_length;

	u_int8_t version;
	u_int8_t ttl;
	u_int16_t checksum;
	char *device_id;
	cdp_llist_t *addresses;
	char *port_id;
	u_int32_t capabilities;
	char *ios_version;
	char *platform;
	cdp_llist_t *ip_prefixes;
	char *vtp_mgmt_domain;
	u_int16_t native_vlan;
	u_int8_t *duplex;
};

struct cdp_packet * cdp_packet_new(u_int8_t, u_int8_t, const char *, const cdp_llist_t *, const char *, u_int32_t, const char *, const char *, const cdp_llist_t *, const char *, u_int16_t, const u_int8_t *);
struct cdp_packet * cdp_packet_generate(const cdp_t *, char *);
struct cdp_packet * cdp_packet_dup(const struct cdp_packet *);
void cdp_packet_free(struct cdp_packet *);

/*
 * Update the packet, packet_length and checksum fields. You'll need to
 * call this before sending the packet, otherwise it will send the old still
 * stored in packet.
 */
int cdp_packet_update(struct cdp_packet *, char *);

#ifdef __cplusplus
}
#endif

#endif /* _CDP_H */
