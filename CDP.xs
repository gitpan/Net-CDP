/*
 * $Id: CDP.xs,v 1.9 2004/09/02 04:25:01 mchapman Exp $
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#define MAX_VLAN_ID 4095
#define DEFAULT_APPLIANCE_ID 1

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

#ifndef SvPV_nomg
#define SvPV_nomg(sv, lp) SvPV(sv, lp)
#endif /* !SvPV_nomg */

#include "libcdp/src/cdp.h"

#include "const-c.inc"

#define INSTANCE_METHOD(METHOD) \
	STMT_START { \
		if (!self) \
			croak(METHOD " is an instance method only"); \
	} STMT_END

#define CHECK_VERSION \
	STMT_START { \
		if (self) \
			self->version = ( \
				self->appliance || \
				/* self->power_consumption || */ \
				self->mtu || \
				self->extended_trust || \
				self->untrusted_cos \
			) ? 2 : 1; \
	} STMT_END

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

typedef char * string_undef;

MODULE = Net::CDP		PACKAGE = Net::CDP

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
_new(CLASS, device, flags)
	SV *CLASS
	string_undef device
	int flags
PROTOTYPE: $$$
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
_recv(self, flags)
	Net_CDP self
	int flags
PROTOTYPE: $$
PREINIT:
	dMY_CXT;
	int result;
CODE:
	INSTANCE_METHOD("_recv");
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
_send(self, packet)
	Net_CDP self
	Net_CDP_Packet packet
PROTOTYPE: $$
PREINIT:
	dMY_CXT;
CODE:
	INSTANCE_METHOD("_send");
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
		STRLEN n_a;		
		if (self->device_id) free(self->device_id);
		SvGETMAGIC(new_device);
		self->device_id = (SvOK(new_device) ? strdup(SvPV_nomg(new_device, n_a)) : NULL);
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
				croak("Invalid argument (must be undef or an array reference)");
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
		if (self->addresses)
			XSRETURN_UV(cdp_llist_count(self->addresses));
		else
			XSRETURN_UNDEF;
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
		STRLEN n_a;		
		if (self->port_id) free(self->port_id);
		SvGETMAGIC(new_port);
		self->port_id = (SvOK(new_port) ? strdup(SvPV_nomg(new_port, n_a)) : NULL);
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
		STRLEN n_a;
		if (self->ios_version) free(self->ios_version);
		SvGETMAGIC(new_ios_version);
		self->ios_version = (SvOK(new_ios_version) ? strdup(SvPV_nomg(new_ios_version, n_a)) : NULL);
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
		STRLEN n_a;
		if (self->platform) free(self->platform);
		SvGETMAGIC(new_platform);
		self->platform = (SvOK(new_platform) ? strdup(SvPV_nomg(new_platform, n_a)) : NULL);
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
				croak("Invalid argument (must be undef or an array reference)");
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
		if (self->ip_prefixes)
			XSRETURN_UV(cdp_llist_count(self->ip_prefixes));
		else
			XSRETURN_UNDEF;
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
		STRLEN n_a;		
		if (self->vtp_mgmt_domain) free(self->vtp_mgmt_domain);
		SvGETMAGIC(new_vtp_management_domain);
		self->vtp_mgmt_domain = (SvOK(new_vtp_management_domain) ? strdup(SvPV_nomg(new_vtp_management_domain, n_a)) : NULL);
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
		SvGETMAGIC(new_native_vlan);
		if (SvOK(new_native_vlan)) {
			u_int16_t temp_native_vlan;
			
			temp_native_vlan = SvUV(new_native_vlan);
			if (temp_native_vlan == 0 || temp_native_vlan > MAX_VLAN_ID)
				croak("Invalid native VLAN (must be between 1 and %u)", MAX_VLAN_ID);
			if (!self->native_vlan) self->native_vlan = (u_int16_t *)calloc(1, sizeof(u_int16_t));
			*self->native_vlan = temp_native_vlan;
		} else {
			free(self->native_vlan);
			self->native_vlan = NULL;
		}
	}
	if (!self->native_vlan) XSRETURN_UNDEF;
	RETVAL = *self->native_vlan;
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
		SvGETMAGIC(new_duplex);
		if (SvOK(new_duplex)) {
			if (!self->duplex) self->duplex = (u_int8_t *)calloc(1, sizeof(u_int8_t));
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

SV *
voice_vlan(self, new_voice_vlan=NULL, new_appliance_id=NULL)
	Net_CDP_Packet self
	SV *new_voice_vlan
	SV *new_appliance_id
PROTOTYPE: $;$$
PREINIT:
	u_int16_t temp_voice_vlan, temp_appliance_id;
	int valid_voice_vlan, valid_appliance_id;
PPCODE:
	INSTANCE_METHOD("voice_vlan");

	valid_voice_vlan = valid_appliance_id = 0;
	
	if (items > 1 && new_voice_vlan) {
		SvGETMAGIC(new_voice_vlan);
		if (SvOK(new_voice_vlan)) {
			temp_voice_vlan = SvUV(new_voice_vlan);
			if (temp_voice_vlan == 0 || temp_voice_vlan > MAX_VLAN_ID)
				croak("Invalid voice VLAN (must be between 1 and %u)", MAX_VLAN_ID);
			valid_voice_vlan = 1;
		}
	}
	
	if (items > 2 && new_appliance_id) {
		SvGETMAGIC(new_appliance_id);
		if (SvOK(new_appliance_id)) {
			temp_appliance_id = SvUV(new_appliance_id);
			if (temp_appliance_id == 0 || temp_appliance_id > 255)
				croak("Invalid appliance ID (must be between 1 and 255)");
			valid_appliance_id = 1;
		}
	}
	
	switch (items) {
	case 3:
		if (valid_voice_vlan && !valid_appliance_id) {
			croak("Attempt to undefine appliance ID while setting voice VLAN");
		} else if (!valid_voice_vlan && valid_appliance_id) {
			croak("Attempt to undefine voice VLAN while setting appliance ID");
		}
		
		if (valid_voice_vlan) {
			if (!self->appliance)
				self->appliance =
					(struct cdp_appliance *)calloc(1, sizeof(struct cdp_appliance *));
			self->appliance->vlan = temp_voice_vlan;
			self->appliance->id = temp_appliance_id;
		} else if (self->appliance) {
			free(self->appliance);
			self->appliance = NULL;
		}
		
		CHECK_VERSION;
		break;
	case 2:
		if (valid_voice_vlan) {
			if (!self->appliance) {
				self->appliance =
					(struct cdp_appliance *)calloc(1, sizeof(struct cdp_appliance *));
				self->appliance->id = 1;
			}
			self->appliance->vlan = temp_voice_vlan;
		} else if (self->appliance) {
			free(self->appliance);
			self->appliance = NULL;
		}
		
		CHECK_VERSION;
		break;
	}
	
	if (GIMME_V == G_VOID)
		XSRETURN_EMPTY;
	
	if (GIMME_V == G_SCALAR) {
		if (self->appliance)
			XSRETURN_UV(self->appliance->vlan);
		else
			XSRETURN_UNDEF;
	}
	
	EXTEND(SP, 2);
	if (self->appliance) {
		PUSHs(sv_2mortal(newSVuv(self->appliance->vlan)));
		PUSHs(sv_2mortal(newSVuv(self->appliance->id)));
	} else {
		PUSHs(&PL_sv_undef);
		PUSHs(&PL_sv_undef);
	}

u_int32_t
mtu(self, new_mtu=NULL)
	Net_CDP_Packet self
	SV *new_mtu
PROTOTYPE: $;$
CODE:
	INSTANCE_METHOD("mtu");
	if (items > 1) {
		SvGETMAGIC(new_mtu);
		if (SvOK(new_mtu)) {
			u_int32_t temp_mtu;
			
			temp_mtu = SvUV(new_mtu);
			if (temp_mtu == 0)
				croak("Invalid MTU (must be greater than 0)");
			if (!self->mtu) self->mtu = (u_int32_t *)calloc(1, sizeof(u_int32_t));
			*self->mtu = temp_mtu;
		} else {
			free(self->mtu);
			self->mtu = NULL;
		}
		CHECK_VERSION;
	}
	if (!self->mtu) XSRETURN_UNDEF;
	RETVAL = *self->mtu;
OUTPUT:
	RETVAL

bool
trusted(self, new_trusted=NULL)
	Net_CDP_Packet self
	SV *new_trusted
PROTOTYPE: $;$
CODE:
	INSTANCE_METHOD("trusted");
	if (items > 1) {
		SvGETMAGIC(new_trusted);
		if (SvOK(new_trusted)) {
			if (!self->extended_trust) self->extended_trust = (u_int8_t *)calloc(1, sizeof(u_int8_t));
			*self->extended_trust = SvTRUE(new_trusted);
		} else if (self->extended_trust) {
			free(self->extended_trust);
			self->extended_trust = NULL;
		}
		CHECK_VERSION;
	}
	if (!self->extended_trust) XSRETURN_UNDEF;
	RETVAL = *self->extended_trust;
OUTPUT:
	RETVAL

u_int8_t
untrusted_cos(self, new_untrusted_cos=NULL)
	Net_CDP_Packet self
	SV *new_untrusted_cos
PROTOTYPE: $;$
CODE:
	INSTANCE_METHOD("untrusted_cos");
	if (items > 1) {
		SvGETMAGIC(new_untrusted_cos);
		if (SvOK(new_untrusted_cos)) {
			u_int8_t temp_untrusted_cos;
			
			temp_untrusted_cos = SvUV(new_untrusted_cos);
			if (temp_untrusted_cos == 0 || temp_untrusted_cos > 7)
				croak("Invalid COS for Untrusted Ports (must be between 0 and 7)");
			if (!self->untrusted_cos) self->untrusted_cos = (u_int8_t *)calloc(1, sizeof(u_int8_t));
			*self->untrusted_cos = temp_untrusted_cos;
		} else {
			free(self->untrusted_cos);
			self->untrusted_cos = NULL;
		}
		CHECK_VERSION;
	}
	if (!self->untrusted_cos) XSRETURN_UNDEF;
	RETVAL = *self->untrusted_cos;
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

MODULE = Net::CDP		PACKAGE = Net::CDP::Constants

INCLUDE: const-xs.inc
