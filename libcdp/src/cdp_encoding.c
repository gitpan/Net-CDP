/*
 * $Id: cdp_encoding.c,v 1.1 2004/09/02 04:25:06 mchapman Exp $
 */

#include <config.h>

#include "cdp_encoding.h"

#include "cdp.h"

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#define GRAB(target, type, func) \
	( \
		(length >= sizeof(type)) \
			? ( \
				target = func(*((type*)data)), \
				length -= sizeof(type), \
				data += sizeof(type), \
				1 \
			) \
			: (0) \
	)
#define SKIP(bytes) \
	( \
		(length >= (bytes)) \
			? ( \
				length -= (bytes), \
				data += (bytes), \
				1 \
			) \
			: (0) \
	)
#define GRAB_UINT8(target) GRAB(target, u_int8_t, )
#define GRAB_UINT16(target) GRAB(target, u_int16_t, ntohs)
#define GRAB_UINT32(target) GRAB(target, u_int32_t, ntohl)
#define GRAB_BYTES(target, bytes) \
	( \
		(length >= (bytes)) \
			? ( \
				memcpy((target), data, (bytes) * sizeof(u_int8_t)), \
				length -= (bytes), \
				data += (bytes), \
				1 \
			) \
			: (0) \
	)
#define GRAB_STRING(target, bytes) \
	( \
		(length >= (bytes)) \
			? ( \
				target = (char*)calloc((bytes) + 1, sizeof(char)), \
				memcpy((target), data, (bytes) * sizeof(char)), \
				length -= (bytes), \
				data += (bytes), \
				1 \
			) \
			: (0) \
	)

/* Hmm, egcs doesn't have variadic macros... */
#define _DECODE_ERROR(e)      sprintf(errors, "Corrupt CDP packet: " e)
#define _DECODE_ERROR2(e, e2) sprintf(errors, "Corrupt CDP packet: " e, e2)
#define _EOP(e)           _DECODE_ERROR("end-of-packet while reading " e)
#define _EOP2(e, e2)      _DECODE_ERROR2("end-of-packet while reading " e, e2)
#define _INVALID(e)       _DECODE_ERROR("invalid " e)
#define _INVALID2(e, e2)  _DECODE_ERROR2("invalid " e, e2)
#define _DUP(e)           _DECODE_ERROR("duplicate " e);

#define EOP(e)          do { _EOP(e);          goto fail; } while (0)
#define EOP2(e, e2)     do { _EOP2(e, e2);     goto fail; } while (0)
#define INVALID(e)      do { _INVALID(e);      goto fail; } while (0)
#define INVALID2(e, e2) do { _INVALID2(e, e2); goto fail; } while (0)
#define DUP(e)          do { _DUP(e);          goto fail; } while (0)

struct cdp_packet *
cdp_decode(const u_int8_t *data, u_int16_t length, char *errors) {
	u_int32_t i, count;
	struct cdp_address address;
	struct cdp_ip_prefix ip_prefix;
	struct cdp_packet *packet;

	u_int16_t tlv_type;
	u_int16_t tlv_length;
	
	if (!SKIP(LIBNET_802_2SNAP_H + LIBNET_802_3_H)) {
		_EOP("ethernet header");
		return NULL;
	}
	if (cdp_checksum(data, length)) {
		_INVALID("checksum");
		return NULL;
	}
	
	packet = (struct cdp_packet *)calloc(1, sizeof(struct cdp_packet));
	packet->packet_length = length;

	/*
	 * We allocate BUFSIZ here, not length, so that cdp_packet_update
	 * can work reliably.
	 */
	packet->packet = (u_int8_t *)calloc(BUFSIZ, sizeof(u_int8_t));
	memcpy(packet->packet, data, length * sizeof(u_int8_t));
	
	if (!GRAB_UINT8(packet->version)) EOP("version"); 
	if (!GRAB_UINT8(packet->ttl)) EOP("TTL");
	if (!GRAB_UINT16(packet->checksum)) EOP("checksum");
	if ((1 > packet->version) || (packet->version > 2))
		INVALID("version (not 1 or 2)");
	
	while (length) {
		if (!GRAB_UINT16(tlv_type)) EOP("TLV type");
		if (!GRAB_UINT16(tlv_length)) EOP("TLV lentgh");
		tlv_length -= 2 * sizeof(u_int16_t);
		
		switch (tlv_type) {
		case CDP_TYPE_DEVICE_ID:
			if (packet->device_id) DUP("Device-ID TLV");
			if (!GRAB_STRING(packet->device_id, tlv_length))
				EOP("Device-ID TLV");
			break;
		case CDP_TYPE_ADDRESS:
			if (packet->addresses) DUP("Address TLV");
			if (!GRAB_UINT32(count)) EOP("number of addresses in Address TLV");
			packet->addresses = cdp_llist_new(
				(cdp_dup_fn_t)cdp_address_dup,
				(cdp_free_fn_t)cdp_address_free
			);
			for (i = 0; i < count; i++) {
				if (!GRAB_UINT8(address.protocol_type))
					EOP2("protocol type for address %d in Address TLV", i);
				if (!GRAB_UINT8(address.protocol_length))
					EOP2("protocol lentgh for address %d in Address TLV", i);
				address.protocol = (u_int8_t *)calloc(address.protocol_length, sizeof(u_int8_t));
				if (!GRAB_BYTES(address.protocol, address.protocol_length)) {
					_EOP2("protocol for address %d in Address TLV", i);
					free(address.protocol);
				}
				if (!GRAB_UINT16(address.address_length)) {
					_EOP2("address length for address %d in Address TLV", i);
					free(address.protocol);
				}
				address.address = (u_int8_t *)calloc(address.address_length, sizeof(u_int8_t));
				if (!GRAB_BYTES(address.address, address.address_length)) {
					_EOP2("address value for address %d in Address TLV", i);
					free(address.address);
					free(address.protocol);
					goto fail;
				}
				cdp_llist_append(packet->addresses, &address);
				free(address.address);
				free(address.protocol);
			}
			break;
		case CDP_TYPE_PORT_ID:
			if (packet->port_id) DUP("Port-ID TLV");
			if (!GRAB_STRING(packet->port_id, tlv_length))
				EOP("Port-ID TLV");
			break;
		case CDP_TYPE_CAPABILITIES:
			if (packet->capabilities) DUP("Capabilities TLV");
			if (tlv_length != sizeof(u_int32_t))
				INVALID2("Capabilities TLV length (not %d)", sizeof(u_int32_t));
			if (!GRAB_UINT32(packet->capabilities))
				EOP("Capabilities TLV");
			break;
		case CDP_TYPE_IOS_VERSION:
			if (packet->ios_version) DUP("Version TLV");
			if (!GRAB_STRING(packet->ios_version, tlv_length))
				EOP("Version TLV");
			break;
		case CDP_TYPE_PLATFORM:
			if (packet->platform) DUP("Platform TLV");
			if (!GRAB_STRING(packet->platform, tlv_length))
				EOP("Platform TLV");
			break;
		case CDP_TYPE_IP_PREFIX:
			if (packet->ip_prefixes) DUP("IP Prefixes TLV");
			
			/*
			 * Yuck... apparently the TLV length can be 0 to
			 * represent no data. At least, that's the impression
			 * I got upon reading
			 * http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/frames.htm#21923
			 */
			if (tlv_length == 0xfffc) tlv_length = 0;
			
			if (tlv_length % 5) INVALID("IP Prefixes TLV length (not a multiple of 5)");
			
			count = tlv_length / 5;
			packet->ip_prefixes = cdp_llist_new(
				(cdp_dup_fn_t)cdp_ip_prefix_dup,
				(cdp_free_fn_t)cdp_ip_prefix_free
			);
			for (i = 0; i < count; i++) {
				if (!GRAB_BYTES(ip_prefix.network, 4))
					EOP2("network for IP prefix %d in IP Prefixes TLV", i);
				if (!GRAB_UINT8(ip_prefix.length))
					EOP2("length for IP prefix %d in IP Prefixes TLV", i);
				if (ip_prefix.length > 32)
					INVALID2("length for IP prefix %d in IP Prefixes TLV (should be no more than 32)", i);
				cdp_llist_append(packet->ip_prefixes, &ip_prefix);
			}
			break;
/*
		FIXME -- not documented
		
		case CDP_TYPE_PROTOCOL_HELLO:
*/
		case CDP_TYPE_VTP_MGMT_DOMAIN:
			if (packet->vtp_mgmt_domain) DUP("VTP Management Domain TLV");
			if (!GRAB_STRING(packet->vtp_mgmt_domain, tlv_length))
				EOP("VTP Management Domain TLV");
			break;
		case CDP_TYPE_NATIVE_VLAN:
			if (packet->native_vlan) DUP("Native VLAN TLV");
			if (tlv_length != sizeof(u_int16_t))
				INVALID2("Native VLAN TLV length (not %d)", sizeof(u_int16_t));
			packet->native_vlan = (u_int16_t *)calloc(1, sizeof(u_int16_t));
			if (!GRAB_UINT16(*packet->native_vlan))
				EOP("Native VLAN TLV");
			break;
		case CDP_TYPE_DUPLEX:
			if (packet->duplex) DUP("Duplex Mode TLV");
			if (tlv_length != sizeof(u_int8_t))
				INVALID2("Duplex Mode TLV length (not %d)", sizeof(u_int8_t));
			packet->duplex = (u_int8_t *)calloc(1, sizeof(u_int8_t));
			if (!GRAB_UINT8(*packet->duplex))
				EOP("Duplex Mode TLV");
			break;
/*
		FIXME -- not documented
		
		case CDP_TYPE_UNKNOWN_0x000c:
*/
/*
		FIXME -- not documented
		
		case CDP_TYPE_UNKNOWN_0x000d:
*/
		case CDP_TYPE_APPLIANCE_ID:
			if (packet->appliance) DUP("Appliance VLAN-ID TLV");
			if (tlv_length != sizeof(u_int8_t) + sizeof(u_int16_t))
				INVALID2("Appliance VLAN-ID TLV length (not %d)",
						sizeof(u_int8_t) + sizeof(u_int16_t));
			packet->appliance =
					(struct cdp_appliance *)calloc(1, sizeof(struct cdp_appliance *));
			if (!GRAB_UINT8(packet->appliance->id))
				EOP("appliance ID in Appliance VLAN-ID TLV");
			if (!GRAB_UINT16(packet->appliance->vlan))
				EOP("appliance VLAN in Appliance VLAN-ID TLV");
			break;
/*
		FIXME -- not fully documented
		See http://www.cisco.com/en/US/products/hw/gatecont/ps514/prod_release_note09186a00801097ff.html
		
		case CDP_TYPE_UNKNOWN_0x000f:
*/
/*
		FIXME -- unsure of field length
		
		case CDP_TYPE_POWER_CONSUMPTION:
			if (packet->power_consumption) DUP("Power Consumption TLV");
			if (tlv_length != sizeof(u_int32_t))
				INVALID2("Power Consumption TLV length (not %d)", sizeof(u_int32_t));
			packet->power_consumption = (u_int32_t *)calloc(1, sizeof(u_int32_t));
			if (!GRAB_UINT32(*packet->power_consumption))
				EOP("Power Consumption TLV");
			break;
*/
		case CDP_TYPE_MTU:
			if (packet->mtu) DUP("MTU TLV");
			if (tlv_length != sizeof(u_int32_t))
				INVALID2("MTU TLV length (not %d)", sizeof(u_int32_t));
			packet->mtu = (u_int32_t *)calloc(1, sizeof(u_int32_t));
			if (!GRAB_UINT32(*packet->mtu))
				EOP("MTU TLV");
			break;
		case CDP_TYPE_EXTENDED_TRUST:
			if (packet->extended_trust) DUP("Extended Trust TLV");
			if (tlv_length != sizeof(u_int8_t))
				INVALID2("Extended Trust TLV length (not %d)", sizeof(u_int8_t));
			packet->extended_trust = (u_int8_t *)calloc(1, sizeof(u_int8_t));
			if (!GRAB_UINT8(*packet->extended_trust))
				EOP("Extended Trust TLV");
			break;
		case CDP_TYPE_UNTRUSTED_COS:
			if (packet->untrusted_cos) DUP("COS for Untrusted Ports TLV");
			if (tlv_length != sizeof(u_int8_t))
				INVALID2("COS for Untrusted Ports TLV length (not %d)", sizeof(u_int8_t));
			packet->untrusted_cos = (u_int8_t *)calloc(1, sizeof(u_int8_t));
			if (!GRAB_UINT8(*packet->untrusted_cos))
				EOP("COS for Untrusted Ports TLV");
			break;
		default:
			/*
			 * Ignore the TLV. If it's an error, it will most
			 * likely get picked up here (remaining length isn't
			 * long enough), or the next TLV will be invalid.
			 */
			if (!SKIP(tlv_length)) EOP("unknown TLV");
			break;
		}
	}
	
	return packet;

fail:
	cdp_packet_free(packet);
	
	return NULL;
}

/*
 * Decode enough of the buffer to determine the checksum. This is so
 * cdp_packet_update can do its stuff.
 */
u_int16_t
cdp_decode_checksum(const u_int8_t *data, u_int16_t length) {
	if (length >= 4)
		return ntohs(*(u_int16_t*)(data + 2));
	else
		return 0;
}

#define PUSH(value, type, func) \
	( \
		(length >= sizeof(type)) \
			? ( \
				*((type*)pos) = func(value), \
				length -= sizeof(type), \
				pos += sizeof(type), \
				1 \
			) \
			: (0) \
	)
#define PUSH_UINT8(value) PUSH(value, u_int8_t, )
#define PUSH_UINT16(value) PUSH(value, u_int16_t, htons)
#define PUSH_UINT32(value) PUSH(value, u_int32_t, htonl)
#define PUSH_BYTES(value, bytes) \
	( \
		(length >= (bytes)) \
			? ( \
				memcpy(pos, value, (bytes) * sizeof(u_int8_t)), \
				length -= (bytes), \
				pos += (bytes), \
				1 \
			) \
			: (0) \
	)

#define START_TLV(type) \
	( \
		tlv = pos, \
		PUSH_UINT16(type) && PUSH_UINT16(0) \
	)
#define END_TLV \
	do { \
		*((u_int16_t *)tlv + 1) = htons(pos - tlv); \
	} while (0)

u_int16_t
cdp_encode(const struct cdp_packet *packet, u_int8_t *data, u_int16_t length) {
	cdp_llist_iter_t iter;

	u_int8_t *pos;
	u_int8_t *checksum_pos;
	u_int8_t *tlv;
	
	pos = data;
	
	PUSH_UINT8(packet->version);
	if (!PUSH_UINT8(packet->ttl))
		return 0;

	/*
	 * Save the current position, then leave enough space for the
	 * checksum.
	 */
	checksum_pos = pos;
	if (!PUSH_UINT16(0))
		return 0;
	
	if (packet->device_id && !(
		START_TLV(CDP_TYPE_DEVICE_ID) &&
		PUSH_BYTES(packet->device_id, strlen(packet->device_id))
	))
		return 0;
	END_TLV;
	
	if (packet->addresses) {
		if (!(
			START_TLV(CDP_TYPE_ADDRESS) &&
			PUSH_UINT32(cdp_llist_count(packet->addresses))
		))
			return 0;
		iter = cdp_llist_iter(packet->addresses);
		for (
			iter = cdp_llist_iter(packet->addresses);
			iter;
			iter = cdp_llist_next(iter)
		) {
			const struct cdp_address *address;
			address = (const struct cdp_address *)cdp_llist_get(iter);
			if (!(
				PUSH_UINT8(address->protocol_type) &&
				PUSH_UINT8(address->protocol_length) &&
				PUSH_BYTES(address->protocol, address->protocol_length) &&
				PUSH_UINT16(address->address_length) &&
				PUSH_BYTES(address->address, address->address_length)
			))
				return 0;
		}
		END_TLV;
	}
	
	if (packet->port_id && !(
		START_TLV(CDP_TYPE_PORT_ID) &&
		PUSH_BYTES(packet->port_id, strlen(packet->port_id))
	))
		return 0;
	END_TLV;
	
	if (packet->capabilities && !(
		START_TLV(CDP_TYPE_CAPABILITIES) &&
		PUSH_UINT32(packet->capabilities)
	))
		return 0;
	END_TLV;
	
	if (packet->ios_version && !(
		START_TLV(CDP_TYPE_IOS_VERSION) &&
		PUSH_BYTES(packet->ios_version, strlen(packet->ios_version))
	))
		return 0;
	END_TLV;
	
	if (packet->platform && !(
		START_TLV(CDP_TYPE_PLATFORM) &&
		PUSH_BYTES(packet->platform, strlen(packet->platform))
	))
		return 0;
	END_TLV;
	
	if (packet->ip_prefixes) {
		if (!START_TLV(CDP_TYPE_IP_PREFIX))
			return 0;
		iter = cdp_llist_iter(packet->ip_prefixes);
		for (
			iter = cdp_llist_iter(packet->ip_prefixes);
			iter;
			iter = cdp_llist_next(iter)
		) {
			const struct cdp_ip_prefix *ip_prefix;
			ip_prefix = (const struct cdp_ip_prefix *)cdp_llist_get(iter);
			if (!(
				PUSH_BYTES(ip_prefix->network, 4) &&
				PUSH_UINT8(ip_prefix->length)
			))
				return 0;
		}
		END_TLV;
	}
	
	if (packet->vtp_mgmt_domain && !(
		START_TLV(CDP_TYPE_VTP_MGMT_DOMAIN) &&
		PUSH_BYTES(packet->vtp_mgmt_domain, strlen(packet->vtp_mgmt_domain))
	))
		return 0;
	END_TLV;
	
	if (packet->native_vlan && !(
		START_TLV(CDP_TYPE_NATIVE_VLAN) &&
		PUSH_UINT16(*packet->native_vlan)
	))
		return 0;
	END_TLV;
	
	if (packet->duplex && !(
		START_TLV(CDP_TYPE_DUPLEX) &&
		PUSH_UINT8(*packet->duplex)
	))
		return 0;
	END_TLV;
	
	if (packet->appliance && !(
		START_TLV(CDP_TYPE_APPLIANCE_ID) &&
		PUSH_UINT8(packet->appliance->id) &&
		PUSH_UINT16(packet->appliance->vlan)
	))
		return 0;
	END_TLV;
	
	if (packet->mtu && !(
		START_TLV(CDP_TYPE_MTU) &&
		PUSH_UINT32(*packet->mtu)
	))
		return 0;
	END_TLV;
	
	if (packet->extended_trust && !(
		START_TLV(CDP_TYPE_EXTENDED_TRUST) &&
		PUSH_UINT8(*packet->extended_trust)
	))
		return 0;
	END_TLV;
	
	if (packet->untrusted_cos && !(
		START_TLV(CDP_TYPE_UNTRUSTED_COS) &&
		PUSH_UINT8(*packet->untrusted_cos)
	))
		return 0;
	END_TLV;
	
	*(u_int16_t*)checksum_pos = cdp_checksum(data, pos - data);
	
	return (pos - data);
}
