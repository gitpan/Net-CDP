/*
 * $Id: cdp_packet.c,v 1.1.1.1 2004/06/04 06:01:29 mchapman Exp $
 */

#include "cdp.h"

#include <sys/utsname.h>
#include <stdio.h>
#include "cdp_encoding.h"

#define HOSTBUF_SIZE 128
#define TEMPBUF_SIZE 512

struct cdp_packet *
cdp_packet_new(u_int8_t version, u_int8_t ttl, const char *device_id, const cdp_llist_t *addresses, const char *port_id, u_int32_t capabilities, const char *ios_version, const char *platform, const cdp_llist_t *ip_prefixes, const char *vtp_mgmt_domain, u_int16_t native_vlan, const u_int8_t *duplex) {
	struct cdp_packet *packet;

	packet = (struct cdp_packet *)calloc(1, sizeof(struct cdp_packet));
	packet->packet = (u_int8_t *)calloc(BUFSIZ, sizeof(u_int8_t));
	packet->packet_length = BUFSIZ;
	packet->version = version;
	packet->ttl = ttl;
	if (device_id) packet->device_id = strdup(device_id);
	if (addresses) packet->addresses = cdp_llist_dup(addresses);
	if (port_id) packet->port_id = strdup(port_id);
	packet->capabilities = capabilities;
	if (ios_version) packet->ios_version = strdup(ios_version);
	if (platform) packet->platform = strdup(platform);
	if (ip_prefixes) packet->ip_prefixes = cdp_llist_dup(ip_prefixes);
	if (vtp_mgmt_domain) packet->vtp_mgmt_domain = strdup(vtp_mgmt_domain);
	packet->native_vlan = native_vlan;
	if (duplex) {
		packet->duplex = (u_int8_t *)calloc(1, sizeof(u_int8_t));
		*packet->duplex = *duplex;
	}
	return packet;
}

struct cdp_packet *
cdp_packet_generate(const cdp_t *cdp, char *errors) {
	struct cdp_packet *packet;
	char *device_id;
	char *ios_version;
	char *platform;
	struct utsname uts;

	device_id = (char *)calloc(HOSTBUF_SIZE, sizeof(char));
	if (gethostname(device_id, HOSTBUF_SIZE - 1)) {
		free(device_id);
		device_id = NULL;
	}

	if (!uname(&uts)) {
		ios_version = (char *)calloc(TEMPBUF_SIZE, sizeof(char));
		snprintf(ios_version, TEMPBUF_SIZE - 1, "%s %s %s %s",
			uts.sysname,
			uts.release,
			uts.version,
			uts.machine
		);
		platform = strdup(uts.sysname);
	} else
		ios_version = platform = NULL;

	packet = cdp_packet_new(
		1,              /* version         */
		180,            /* ttl             */
		device_id,      /* device_id       */
		(cdp ? cdp->addresses : NULL),
		                /* addresses       */
		(cdp ? cdp->port : NULL),
		                /* port_id         */
		CDP_CAP_HOST,   /* capabilities    */
		ios_version,    /* ios_version     */
		platform,       /* platform        */
		NULL,           /* ip_prefixes     */
		NULL,           /* vtp_mgmt_domain */
		0,              /* native_vlan     */
		NULL            /* duplex          */
	);

	if (device_id) free(device_id);
	if (ios_version) free(ios_version);
	if (platform) free(platform);

	return packet;
}

struct cdp_packet *
cdp_packet_dup(const struct cdp_packet *packet) {
	return cdp_packet_new(
		packet->version,
		packet->ttl,
		packet->device_id,
		packet->addresses,
		packet->port_id,
		packet->capabilities,
		packet->ios_version,
		packet->platform,
		packet->ip_prefixes,
		packet->vtp_mgmt_domain,
		packet->native_vlan,
		packet->duplex
	);
}

void
cdp_packet_free(struct cdp_packet *packet) {
	if (packet->packet) free(packet->packet);
	if (packet->device_id) free(packet->device_id);
	if (packet->addresses) cdp_llist_free(packet->addresses);
	if (packet->port_id) free(packet->port_id);
	if (packet->ios_version) free(packet->ios_version);
	if (packet->platform) free(packet->platform);
	if (packet->ip_prefixes) cdp_llist_free(packet->ip_prefixes);
	if (packet->vtp_mgmt_domain) free(packet->vtp_mgmt_domain);
	if (packet->duplex) free(packet->duplex);
	free(packet);
}

int
cdp_packet_update(struct cdp_packet *packet, char *errors) {
	if ((packet->packet_length = cdp_encode(packet, packet->packet, BUFSIZ)) == -1) {
		strcpy(errors, "Generated packet too large");
		return -1;
	}

	/* Update my own concept of checksum */
	packet->checksum = cdp_decode_checksum(packet->packet, packet->packet_length);

	return 0;
}

