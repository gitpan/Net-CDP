/*
 * $Id: cdp_packet.c,v 1.1 2004/09/02 04:25:06 mchapman Exp $
 */

#include <config.h>

#include "cdp.h"

#ifdef HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
#endif /* HAVE_SYS_UTSNAME_H */

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#include "cdp_encoding.h"

#define HOSTBUF_SIZE 128
#define TEMPBUF_SIZE 512

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
	
	packet = (struct cdp_packet *)calloc(1, sizeof(struct cdp_packet));
	packet->packet = (u_int8_t *)calloc(BUFSIZ, sizeof(u_int8_t));
	packet->packet_length = BUFSIZ;
	packet->version = 1;
	packet->ttl = 180;
	packet->device_id = device_id;
	packet->capabilities = CDP_CAP_HOST;
	packet->ios_version = ios_version;
	packet->platform = platform;
	if (cdp) {
		packet->addresses = cdp_llist_dup(cdp->addresses);
		packet->port_id = strdup(cdp->port);
		if (cdp->duplex) {
			packet->duplex = (u_int8_t *)calloc(1, sizeof(u_int8_t));
			*packet->duplex = *cdp->duplex;
		}
	}

	return packet;
}

struct cdp_packet *
cdp_packet_dup(const struct cdp_packet *packet) {
	struct cdp_packet *dup;

	dup = (struct cdp_packet *)calloc(1, sizeof(struct cdp_packet));
	dup->packet = (u_int8_t *)calloc(BUFSIZ, sizeof(u_int8_t));
	dup->packet_length = BUFSIZ;
	dup->version = packet->version;
	dup->ttl = packet->ttl;
	if (packet->device_id) dup->device_id = strdup(packet->device_id);
	if (packet->addresses) dup->addresses = cdp_llist_dup(packet->addresses);
	if (packet->port_id) dup->port_id = strdup(packet->port_id);
	dup->capabilities = packet->capabilities;
	if (packet->ios_version) dup->ios_version = strdup(packet->ios_version);
	if (packet->platform) dup->platform = strdup(packet->platform);
	if (packet->ip_prefixes) dup->ip_prefixes = cdp_llist_dup(packet->ip_prefixes);
	if (packet->vtp_mgmt_domain) dup->vtp_mgmt_domain = strdup(packet->vtp_mgmt_domain);
	if (packet->native_vlan) {
		dup->native_vlan = (u_int16_t *)calloc(1, sizeof(u_int16_t));
		*dup->native_vlan = *packet->native_vlan;
	}
	if (packet->duplex) {
		dup->duplex = (u_int8_t *)calloc(1, sizeof(u_int8_t));
		*dup->duplex = *packet->duplex;
	}
	if (packet->appliance) {
		dup->appliance =
				(struct cdp_appliance *)calloc(1, sizeof(struct cdp_appliance *));
		dup->appliance->id = packet->appliance->id;
		dup->appliance->vlan = packet->appliance->vlan;
	}
	return dup;
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
	if (packet->native_vlan) free(packet->native_vlan);
	if (packet->duplex) free(packet->duplex);
	if (packet->appliance) free(packet->appliance);
	free(packet);
}

int
cdp_packet_update(struct cdp_packet *packet, char *errors) {
	if ((packet->packet_length = cdp_encode(packet, packet->packet, BUFSIZ)) == 0) {
		strcpy(errors, "Generated packet too large");
		return -1;
	}

	/* Update my own concept of checksum */
	packet->checksum = cdp_decode_checksum(packet->packet, packet->packet_length);

	return 0;
}
