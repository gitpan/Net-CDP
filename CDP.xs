/*
 * $Id: CDP.xs,v 1.3 2004/06/23 10:03:37 mchapman Exp $
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#ifndef newSVuv
SV * newSVuv(UV data) {
	SV *__sv;

	__sv = newSV(0);
	sv_setuv(__sv, data);
	return __sv;
}
#endif /* !newSVuv */

#ifndef XSRETURN_UV
#define XSRETURN_UV(v) STMT_START { ST(0) = sv_2mortal(newSVuv(v)); XSRETURN(1); } STMT_END
#endif /* !XSRETURN_UV */

#include "cdp.h"

#include "const-c.inc"

#define INSTANCE_METHOD(METHOD) \
	do { \
		if (!self) \
			croak(METHOD " is an instance method only"); \
	} while (0)

#define MY_CXT_KEY "Net::CDP::_guts" XS_VERSION
typedef struct {
	char errors[CDP_ERRBUF_SIZE];
} my_cxt_t;

START_MY_CXT

typedef cdp_t * Net_CDP;
typedef struct cdp_address * Net_CDP_Address;
typedef struct cdp_ip_prefix * Net_CDP_IPPrefix;
typedef struct cdp_packet * Net_CDP_Packet;
typedef int SysRet;

MODULE = Net::CDP		PACKAGE = Net::CDP

INCLUDE: const-xs.inc

BOOT:
{
	MY_CXT_INIT;
	Zero(MY_CXT.errors, CDP_ERRBUF_SIZE, char);
}

char **
ports()
PROTOTYPE: 
PREINIT:
	dMY_CXT;
	cdp_llist_t *ports;
	U32 count;
	cdp_llist_iter_t iter;
PPCODE:
	MY_CXT.errors[0] = '\0';
	
	if (GIMME_V == G_VOID)
		XSRETURN_EMPTY;
	
	ports = cdp_get_ports(MY_CXT.errors);
	if (!ports)
		croak(MY_CXT.errors);
		
	count = cdp_llist_count(ports);
	if (GIMME_V == G_SCALAR) {
		cdp_llist_free(ports);
		XSRETURN_UV(count);
	}
	
	EXTEND(SP, count);
	for (iter = cdp_llist_iter(ports); iter; iter = cdp_llist_next(iter))
		PUSHs(sv_2mortal(newSVpv(cdp_llist_get(iter), 0)));
	cdp_llist_free(ports);

Net_CDP
new(CLASS, device=NULL, flags=0)
	SV *CLASS
	char *device
	int flags
PROTOTYPE: $;$
PREINIT:
	dMY_CXT;
CODE:
	MY_CXT.errors[0] = '\0';	
	RETVAL = cdp_new(device, flags, MY_CXT.errors);
	if (!RETVAL)
		croak(MY_CXT.errors);
OUTPUT:
	RETVAL

const char *
port(self)
	Net_CDP self
PROTOTYPE: $
CODE:
	INSTANCE_METHOD("port");
	RETVAL = cdp_get_port(self);
OUTPUT:
	RETVAL

Net_CDP_Address *
addresses(self)
	Net_CDP self
PROTOTYPE: $
PREINIT:
	const cdp_llist_t *addresses;
	cdp_llist_iter_t iter;
PPCODE:
	INSTANCE_METHOD("addresses");

	switch (GIMME_V) {
	case G_VOID:
		XSRETURN_EMPTY;
	case G_SCALAR:
		XSRETURN_UV(cdp_llist_count(cdp_get_addresses(self)));
	default:
		EXTEND(SP, cdp_llist_count(cdp_get_addresses(self)));
		for (
			iter = cdp_llist_iter(cdp_get_addresses(self));
			iter; 
			iter = cdp_llist_next(iter)
		)
			PUSHs(sv_setref_pv(sv_newmortal(), "Net::CDP::Address", cdp_address_dup((struct cdp_address *)cdp_llist_get(iter))));
	}

int
_fd(self)
	Net_CDP self
PROTOTYPE: $
CODE:
	INSTANCE_METHOD("_fd");
	RETVAL = cdp_get_fd(self);
OUTPUT:
	RETVAL

Net_CDP_Packet
recv(self, flags=0)
	Net_CDP self
	int flags
PROTOTYPE: $;$$
PREINIT:
	dMY_CXT;
	int result;
CODE:
	INSTANCE_METHOD("recv");
	MY_CXT.errors[0] = '\0';	
	RETVAL = cdp_recv(self, flags, MY_CXT.errors);

	if (!RETVAL) {
		if (!MY_CXT.errors[0])
			XSRETURN_UNDEF;
		croak(MY_CXT.errors);
	}
OUTPUT:
	RETVAL

SysRet
send(self, packet)
	Net_CDP self
	Net_CDP_Packet packet
PROTOTYPE: $$
PREINIT:
	dMY_CXT;
CODE:
	INSTANCE_METHOD("send");
	MY_CXT.errors[0] = '\0';	
	if (cdp_packet_update(packet, MY_CXT.errors) == -1)
		croak(MY_CXT.errors);
	RETVAL = cdp_send(self, packet, MY_CXT.errors);
	if (RETVAL == -1)
		croak(MY_CXT.errors);
OUTPUT:
	RETVAL

void
DESTROY(self)
	Net_CDP self
PROTOTYPE: $
CODE:
	INSTANCE_METHOD("DESTROY");
	cdp_free(self);

MODULE = Net::CDP		PACKAGE = Net::CDP::Packet

Net_CDP_Packet
new(CLASS, cdp=NULL)
	SV *CLASS
	Net_CDP cdp
PROTOTYPE: $;$
PREINIT:
	dMY_CXT;
CODE:
	MY_CXT.errors[0] = '\0';	
	RETVAL = cdp_packet_generate(cdp, MY_CXT.errors);
	if (!RETVAL)
		croak(MY_CXT.errors);
OUTPUT:
	RETVAL

Net_CDP_Packet
clone(self)
	Net_CDP_Packet self
PROTOTYPE: $
CODE:
	INSTANCE_METHOD("clone");
	RETVAL = cdp_packet_dup(self);
OUTPUT:
	RETVAL

void
DESTROY(self)
	Net_CDP_Packet self
PROTOTYPE: $
CODE:
	INSTANCE_METHOD("DESTROY");
	cdp_packet_free(self);

u_int8_t
version(self)
	Net_CDP_Packet self
PROTOTYPE: $
CODE:
	INSTANCE_METHOD("version");
	RETVAL = self->version;
OUTPUT:
	RETVAL

u_int8_t
ttl(self, new_ttl=0)
	Net_CDP_Packet self
	u_int8_t new_ttl
PROTOTYPE: $;$
CODE:
	INSTANCE_METHOD("ttl");
	if (items > 1) self->ttl = new_ttl;
	RETVAL = self->ttl;
OUTPUT:
	RETVAL

u_int16_t
checksum(self)
	Net_CDP_Packet self
PROTOTYPE: $
CODE:
	INSTANCE_METHOD("checksum");
	RETVAL = self->checksum;
OUTPUT:
	RETVAL

char *
device(self, new_device=NULL)
	Net_CDP_Packet self
	SV *new_device
PROTOTYPE: $;$
CODE:
	INSTANCE_METHOD("device");
	if (items > 1) {
		if (self->device_id) free(self->device_id);
		self->device_id = (SvOK(new_device) ? strdup(SvPV_nolen(new_device)) : NULL);
	}
	if (!self->device_id) XSRETURN_UNDEF;
	RETVAL = self->device_id;
OUTPUT:
	RETVAL

Net_CDP_Address *
addresses(self, new_addresses=NULL)
	Net_CDP_Packet self
	SV *new_addresses
PROTOTYPE: $;$
PREINIT:
	cdp_llist_iter_t iter;
PPCODE:
	INSTANCE_METHOD("addresses");
	if (items > 1) {
		cdp_llist_t *addresses;

		SvGETMAGIC(new_addresses);
		if (!SvOK(new_addresses)) {
			addresses = NULL;
		} else {
			AV *a;
			int i;

			if (!SvROK(new_addresses) || SvTYPE(SvRV(new_addresses)) != SVt_PVAV)
				croak("new_addresses is not undef or an array reference");
			a = (AV *)SvRV(new_addresses);
			addresses = cdp_llist_new((cdp_dup_fn_t)cdp_address_dup, (cdp_free_fn_t)cdp_address_free);
			for (i = 0; i <= av_len(a); i++) {
				SV **t = av_fetch(a, i, 0);
				if (t && sv_derived_from(*t, "Net::CDP::Address")) {
					SvGETMAGIC(*t);
					cdp_llist_append(addresses, (struct cdp_address *)SvIV((SV *)SvRV(*t)));
				} else {
					cdp_llist_free(addresses);
					croak("Element %d is not of type Net::CDP::Address", i);
				}
			}
		}
		if (self->addresses) cdp_llist_free(self->addresses);
		self->addresses = addresses;
	}

	if (GIMME_V == G_VOID)
		XSRETURN_EMPTY;
	
	if (GIMME_V == G_SCALAR) {
		if (!self->addresses)
			XSRETURN_UNDEF;
		else
			XSRETURN_UV(cdp_llist_count(self->addresses));
	}
	
	if (!self->addresses)
		XSRETURN_EMPTY;
	EXTEND(SP, cdp_llist_count(self->addresses));
	for (iter = cdp_llist_iter(self->addresses); iter; iter = cdp_llist_next(iter))
		PUSHs(sv_setref_pv(sv_newmortal(), "Net::CDP::Address", cdp_address_dup((struct cdp_address *)cdp_llist_get(iter))));

char *
port(self, new_port=NULL)
	Net_CDP_Packet self
	SV *new_port
PROTOTYPE: $;$
CODE:
	INSTANCE_METHOD("port");
	if (items > 1) {
		if (self->port_id) free(self->port_id);
		self->port_id = (SvOK(new_port) ? strdup(SvPV_nolen(new_port)) : NULL);
	}
	if (!self->port_id) XSRETURN_UNDEF;
	RETVAL = self->port_id;
OUTPUT:
	RETVAL

u_int32_t
capabilities(self, new_capabilities=0)
	Net_CDP_Packet self
	u_int32_t new_capabilities
PROTOTYPE: $;$
CODE:
	INSTANCE_METHOD("capabilities");
	if (items > 1) self->capabilities = new_capabilities;
	RETVAL = self->capabilities;
OUTPUT:
	RETVAL

char *
ios_version(self, new_ios_version=NULL)
	Net_CDP_Packet self
	SV *new_ios_version
PROTOTYPE: $;$
CODE:
	INSTANCE_METHOD("ios_version");
	if (items > 1) {
		if (self->ios_version) free(self->ios_version);
		self->ios_version = (SvOK(new_ios_version) ? strdup(SvPV_nolen(new_ios_version)) : NULL);
	}
	if (!self->ios_version) XSRETURN_UNDEF;
	RETVAL = self->ios_version;
OUTPUT:
	RETVAL

char *
platform(self, new_platform=NULL)
	Net_CDP_Packet self
	SV *new_platform
PROTOTYPE: $;$
CODE:
	INSTANCE_METHOD("platform");
	if (items > 1) {
		if (self->platform) free(self->platform);
		self->platform = (SvOK(new_platform) ? strdup(SvPV_nolen(new_platform)) : NULL);
	}
	if (!self->platform) XSRETURN_UNDEF;
	RETVAL = self->platform;
OUTPUT:
	RETVAL

Net_CDP_IPPrefix *
ip_prefixes(self, new_ip_prefixes=NULL)
	Net_CDP_Packet self
	SV *new_ip_prefixes
PROTOTYPE: $;$
PREINIT:
	cdp_llist_iter_t iter;
PPCODE:
	INSTANCE_METHOD("ip_prefixes");
	if (items > 1) {
		cdp_llist_t *ip_prefixes;

		SvGETMAGIC(new_ip_prefixes);
		if (!SvOK(new_ip_prefixes)) {
			ip_prefixes = NULL;
		} else {
			AV *a;
			int i;

			if (!SvROK(new_ip_prefixes) || SvTYPE(SvRV(new_ip_prefixes)) != SVt_PVAV)
				croak("new_ip_prefixes is not undef or an array reference");
			a = (AV*)SvRV(new_ip_prefixes);
			ip_prefixes = cdp_llist_new((cdp_dup_fn_t)cdp_ip_prefix_dup, (cdp_free_fn_t)cdp_ip_prefix_free);
			for (i = 0; i <= av_len(a); i++) {
				SV **t = av_fetch(a, i, 0);
				if (t && sv_derived_from(*t, "Net::CDP::IPPrefix")) {
					SvGETMAGIC(*t);
					cdp_llist_append(ip_prefixes, (struct cdp_ip_prefix *)SvIV((SV *)SvRV(*t)));
				} else {
					cdp_llist_free(ip_prefixes);
					croak("Element %d is not of type Net::CDP::IPPrefix", i);
				}
			}
		}
		if (self->ip_prefixes) cdp_llist_free(self->ip_prefixes);
		self->ip_prefixes = ip_prefixes;
	}

	if (GIMME_V == G_VOID)
		XSRETURN_EMPTY;
	
	if (GIMME_V == G_SCALAR) {
		if (!self->ip_prefixes)
			XSRETURN_UNDEF;
		else
			XSRETURN_UV(cdp_llist_count(self->ip_prefixes));
	}
	
	if (!self->ip_prefixes)
		XSRETURN_EMPTY;
	EXTEND(SP, cdp_llist_count(self->ip_prefixes));
	for (iter = cdp_llist_iter(self->ip_prefixes); iter; iter = cdp_llist_next(iter))
		PUSHs(sv_setref_pv(sv_newmortal(), "Net::CDP::IPPrefix", cdp_ip_prefix_dup((struct cdp_ip_prefix*)cdp_llist_get(iter))));

char *
vtp_management_domain(self, new_vtp_management_domain=NULL)
	Net_CDP_Packet self
	SV *new_vtp_management_domain
PROTOTYPE: $;$
CODE:
	INSTANCE_METHOD("vtp_management_domain");
	if (items > 1) {
		if (self->vtp_mgmt_domain) free(self->vtp_mgmt_domain);
		self->vtp_mgmt_domain = (SvOK(new_vtp_management_domain) ? strdup(SvPV_nolen(new_vtp_management_domain)) : NULL);
	}
	if (!self->vtp_mgmt_domain) XSRETURN_UNDEF;
	RETVAL = self->vtp_mgmt_domain;
OUTPUT:
	RETVAL

u_int16_t
native_vlan(self, new_native_vlan=NULL)
	Net_CDP_Packet self
	SV *new_native_vlan
PROTOTYPE: $;$
CODE:
	INSTANCE_METHOD("native_vlan");
	if (items > 1) {
		if (SvOK(new_native_vlan)) {
			if (SvUV(new_native_vlan) == 0)
				croak("new_native_vlan must be undef or greater than 0");
			self->native_vlan = SvUV(new_native_vlan);
		} else
			self->native_vlan = 0;
	}
	if (!self->native_vlan) XSRETURN_UNDEF;
	RETVAL = self->native_vlan;
OUTPUT:
	RETVAL

bool
duplex(self, new_duplex=NULL)
	Net_CDP_Packet self
	SV *new_duplex
PROTOTYPE: $;$
CODE:
	INSTANCE_METHOD("duplex");
	if (items > 1) {
		if (SvOK(new_duplex)) {
			if (!self->duplex) self->duplex = (u_int8_t*)calloc(1, sizeof(u_int8_t));
			*self->duplex = SvTRUE(new_duplex);
		} else if (self->duplex) {
			free(self->duplex);
			self->duplex = NULL;
		}
	}
	if (!self->duplex) XSRETURN_UNDEF;
	RETVAL = *self->duplex;
OUTPUT:
	RETVAL

MODULE = Net::CDP		PACKAGE = Net::CDP::Address

Net_CDP_Address
_new(CLASS, protocol, packed)
	SV *CLASS
	SV *protocol
	SV *packed
PROTOTYPE: $$$
INIT:
	STRLEN len1, len2;
	char *str1, *str2;
CODE:
	str1 = SvPV(protocol, len1);
	str2 = SvPV(packed, len2);
	switch (len1) {
	case 1:
		RETVAL = cdp_address_new(1, 1, (u_int8_t *)str1, (u_int16_t)len2, (u_int8_t *)str2);
		break;
	case 3:
	case 8:
		RETVAL = cdp_address_new(2, (u_int8_t)len1, (u_int8_t *)str1, (u_int16_t)len2, (u_int8_t *)str2);
	default:
		croak("Invalid protocol");
	}
OUTPUT:
	RETVAL

Net_CDP_Address
_new_by_id(CLASS, protocol_id, packed)
	SV *CLASS
	unsigned int protocol_id
	SV *packed
PROTOTYPE: $$$
INIT:
	STRLEN len;
	char *str;
CODE:
	str = SvPV(packed, len);
	if (protocol_id <= CDP_ADDR_PROTO_MAX)
		RETVAL = cdp_address_new(
			cdp_address_protocol_type[protocol_id],
			cdp_address_protocol_length[protocol_id],
			cdp_address_protocol[protocol_id],
			(u_int16_t)len,
			(u_int8_t *)str
		);
	else
		croak("Invalid protocol");
OUTPUT:
	RETVAL

Net_CDP_Address
clone(self)
	Net_CDP_Address self
PROTOTYPE: $
CODE:
	INSTANCE_METHOD("clone");
	RETVAL = cdp_address_dup(self);
OUTPUT:
	RETVAL

void
DESTROY(self)
	Net_CDP_Address self
PROTOTYPE: $
CODE:
	INSTANCE_METHOD("DESTROY");
	cdp_address_free(self);

u_int8_t
_protocol_type(self)
	Net_CDP_Address self
PROTOTYPE: $
CODE:
	INSTANCE_METHOD("_protocol_type");
	RETVAL = self->protocol_type;
OUTPUT:
	RETVAL

SV *
_protocol(self)
	Net_CDP_Address self
PROTOTYPE: $
CODE:
	INSTANCE_METHOD("_protocol");
	RETVAL = newSVpvn(self->protocol, self->protocol_length);
OUTPUT:
	RETVAL

SV *
_protocol_id(self)
	Net_CDP_Address self
PROTOTYPE: $
PREINIT:
	UV protocol_id;
CODE:
	INSTANCE_METHOD("_protocol_id");
	RETVAL = NULL;
	for (protocol_id = 0; !RETVAL && protocol_id <= CDP_ADDR_PROTO_MAX; protocol_id++) {
		if (
			self->protocol_type == cdp_address_protocol_type[protocol_id] &&
			self->protocol_length == cdp_address_protocol_length[protocol_id] &&
			memcmp(self->protocol, cdp_address_protocol[protocol_id], self->protocol_length) == 0
		)
			RETVAL = newSVuv(protocol_id);
	}
	if (!RETVAL) XSRETURN_UNDEF;
OUTPUT:
	RETVAL

SV *
_address(self)
	Net_CDP_Address self
PROTOTYPE: $
CODE:
	INSTANCE_METHOD("_address");
	RETVAL = newSVpvn(self->address, self->address_length);
OUTPUT:
	RETVAL

MODULE = Net::CDP		PACKAGE = Net::CDP::IPPrefix

Net_CDP_IPPrefix
_new(CLASS, packed, length)
	SV *CLASS
	SV *packed
	u_int8_t length
PROTOTYPE: $$$
INIT:
	STRLEN len;
	char *str;
CODE:
	str = SvPV(packed, len);
	if (len != 4 || length > 32)
		croak("Invalid IP prefix");
	RETVAL = cdp_ip_prefix_new((u_int8_t *)str, length);
OUTPUT:
	RETVAL

Net_CDP_IPPrefix
clone(self)
	Net_CDP_IPPrefix self
PROTOTYPE: $
CODE:
	INSTANCE_METHOD("clone");
	RETVAL = cdp_ip_prefix_dup(self);
OUTPUT:
	RETVAL

void
DESTROY(self)
	Net_CDP_IPPrefix self
PROTOTYPE: $
CODE:
	INSTANCE_METHOD("DESTROY");
	cdp_ip_prefix_free(self);

SV *
_network(self)
	Net_CDP_IPPrefix self
PROTOTYPE: $
CODE:
	INSTANCE_METHOD("network");
	RETVAL = newSVpvn(self->network, 4);
OUTPUT:
	RETVAL

u_int8_t
length(self)
	Net_CDP_IPPrefix self
PROTOTYPE: $
CODE:
	INSTANCE_METHOD("length");
	RETVAL = self->length;
OUTPUT:
	RETVAL

