/*
 * $Id: cdp.c,v 1.1.1.1 2004/06/04 06:01:29 mchapman Exp $
 */

#include "cdp.h"

#include <stdio.h>
#include <sys/time.h>

#ifndef HAVE_RECENT_PCAP
#include <net/if.h>
#include <fcntl.h>
#include <errno.h>
#endif /* !HAVE_RECENT_PCAP */

#include "cdp_encoding.h"

#define BPF_FILTER "ether host 01:00:0c:cc:cc:cc and ether[20:2] = 0x2000"

static void
callback(u_int8_t *user, const struct pcap_pkthdr *header, const u_int8_t *data) {
	/*
	 * Grab the header and data and save it in the supplied cdp object.
	 * cdp_recv will pick it up when pcap_dispatch returns.
	 */
	cdp_t *cdp = (cdp_t *)user;
	cdp->header = header;
	cdp->data = data;
}

#ifdef HAVE_RECENT_PCAP
cdp_llist_t *
cdp_get_ports(char *errors) {
	char *pcap_errors;
	
	struct pcap_if *devs, *d;
	cdp_llist_t *result;
	
	/*
	 * pcap has a handy find all devices function. We don't want the
	 * "any" device though.
	 */
	pcap_errors = (char *)calloc(PCAP_ERRBUF_SIZE, sizeof(char));
	if (pcap_findalldevs(&devs, pcap_errors) == -1) {
		strncpy(errors, pcap_errors, (CDP_ERRBUF_SIZE - 1) * sizeof(char));
		errors[CDP_ERRBUF_SIZE - 1] = '\0';
		free(pcap_errors);
		return NULL;
	}
	result = cdp_llist_new((cdp_dup_fn_t)strdup, (cdp_free_fn_t)free);
	for (d = devs; d; d = d->next)
		if (strcmp(d->name, "any"))
			cdp_llist_append(result, d->name);
	pcap_freealldevs(devs);
	free(pcap_errors);
	return result;
}
#else /* HAVE_RECENT_PCAP */
cdp_llist_t *
cdp_get_ports(char *errors) {
	/* This code is lifted from Ethereal 0.9.13 */
	char *pcap_errors, *libnet_errors;
	int sock;
	int len, lastlen;
	struct ifconf ifc;
	struct ifreq ifrflags, *ifr, *last;
	char *buf;
	pcap_t *pcap;
	libnet_t *libnet;
	cdp_llist_t *normal_list, *loopback_list;
	cdp_llist_iter_t iter;
	int found;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errors, (CDP_ERRBUF_SIZE - 1) * sizeof(char),
			"Error opening socket: %s", strerror(errno));
		errors[CDP_ERRBUF_SIZE - 1] = '\0';
		return NULL;
	}

	lastlen = 0;
	len = 100 * sizeof(struct ifreq);
	for ( ; ; ) {
		buf = (char *)calloc(len, sizeof(char));
		ifc.ifc_len = len;
		ifc.ifc_buf = buf;
		memset(buf, 0, len);
		if (ioctl(sock, SIOCGIFCONF, &ifc) < 0) {
			if (errno != EINVAL || lastlen != 0) {
				snprintf(errors, (CDP_ERRBUF_SIZE - 1) * sizeof(char),
					"Could not get list of interfaces: %s",
					strerror(errno));
				errors[CDP_ERRBUF_SIZE - 1] = '\0';
				free(buf);
				close(sock);
				return NULL;
			}
		} else {
			if ((unsigned) ifc.ifc_len < sizeof(struct ifreq)) {
				sprintf(errors,
					"SIOCGIFCONF ioctl returned an invalid buffer");
				free(buf);
				close(sock);
				return NULL;
			}
			if (ifc.ifc_len == lastlen)
				break;
			lastlen = ifc.ifc_len;
		}
		len += 10 * sizeof(struct ifreq);
		free(buf);
	}

	normal_list = cdp_llist_new((cdp_dup_fn_t)strdup, (cdp_free_fn_t)free);
	loopback_list = cdp_llist_new((cdp_dup_fn_t)strdup, (cdp_free_fn_t)free);
	pcap_errors = (char *)calloc(PCAP_ERRBUF_SIZE, sizeof(char));
	libnet_errors = (char *)calloc(LIBNET_ERRBUF_SIZE, sizeof(char));

	ifr = (struct ifreq *)ifc.ifc_req;
	last = (struct ifreq *)((char *)ifr + ifc.ifc_len);
	for ( ; ifr < last; ifr = (struct ifreq *) ((char *) ifr + sizeof(struct ifreq))) {
		/*
		 * Skip addresses that begin with "dummy", or that include
		 * a ":" (the latter are Solaris virtuals).
		 */
		if (strncmp(ifr->ifr_name, "dummy", 5) == 0 ||
			strchr(ifr->ifr_name, ':') != NULL)
			continue;

		/*
		 * If we already have this interface name on the list,
		 * don't add it (SIOCGIFCONF returns, at least on
		 * BSD-flavored systems, one entry per interface *address*;
		 * if an interface has multiple addresses, we get multiple
		 * entries for it).
		 */
		found = 0;
		for (iter = cdp_llist_iter(normal_list); !found && iter; iter = cdp_llist_next(iter))
			if (strcmp((char *)cdp_llist_get(iter), ifr->ifr_name) == 0)
				found = 1;
		for (iter = cdp_llist_iter(loopback_list); !found && iter; iter = cdp_llist_next(iter))
			if (strcmp((char *)cdp_llist_get(iter), ifr->ifr_name) == 0)
				found = 1;
		if (found)
			continue;

		/*
		 * Get the interface flags.
		 */
		memset(&ifrflags, 0, sizeof ifrflags);
		strncpy(ifrflags.ifr_name, ifr->ifr_name,
			sizeof ifrflags.ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, (char *)&ifrflags) < 0) {
			if (errno == ENXIO)
				continue;
			snprintf(errors, (CDP_ERRBUF_SIZE - 1) * sizeof(char),
				"Could not get flags for interface %s: %s",
				ifr->ifr_name, strerror(errno));
			errors[CDP_ERRBUF_SIZE - 1] = '\0';
			free(buf);
			close(sock);
			free(pcap_errors);
			free(libnet_errors);
			cdp_llist_free(normal_list);
			cdp_llist_free(loopback_list);
			return NULL;
		}

		/*
		 * Skip interfaces that aren't up.
		 */
		if (!(ifrflags.ifr_flags & IFF_UP))
			continue;

		/*
		 * Skip interfaces that we can't open with "libpcap".
		 * Open with the minimum packet size - it appears that the
		 * IRIX SIOCSNOOPLEN "ioctl" may fail if the capture length
		 * supplied is too large, rather than just truncating it.
		 */
		if (!(pcap = pcap_open_live(ifr->ifr_name, 68, 0, 0, pcap_errors)))
			continue;
		pcap_close(pcap);

		/*
		 * Also skip interfaces that we can't be open with "libnet".
		 * Some versions of libnet don't work with loopback interfaces.
		 */
		if (!(libnet = libnet_init(LIBNET_LINK, ifr->ifr_name, libnet_errors)))
			continue;
		libnet_destroy(libnet);

		/*
		 * If it's a loopback interface, add it to the loopback list,
		 * otherwise add it after the normal list.
		 */
		if ((ifrflags.ifr_flags & IFF_LOOPBACK) ||
			strncmp(ifr->ifr_name, "lo", 2) == 0)
			cdp_llist_append(loopback_list, ifr->ifr_name);
		else
			cdp_llist_append(normal_list, ifr->ifr_name);
	}
	free(buf);
	close(sock);
	free(pcap_errors);
	free(libnet_errors);

	for (iter = cdp_llist_iter(loopback_list); iter; iter = cdp_llist_next(iter))
		cdp_llist_append(normal_list, cdp_llist_get(iter));
	cdp_llist_free(loopback_list);
	return normal_list;
}
#endif /* !HAVE_RECENT_PCAP */

cdp_t *
cdp_new(const char *port, char *errors) {
	cdp_t *cdp;

	char *pcap_errors;
	char *libnet_errors;
	
	struct cdp_address *address;
	
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct bpf_program filter;
	struct libnet_ether_addr *hwaddr;

	pcap_errors = (char *)calloc(PCAP_ERRBUF_SIZE, sizeof(char));
	libnet_errors = (char *)calloc(LIBNET_ERRBUF_SIZE, sizeof(char));

	errors[0] = '\0';
	
	cdp = (cdp_t *)calloc(1, sizeof(cdp_t));
	
#ifdef HAVE_RECENT_PCAP
	{
		struct pcap_if *devs, *d, *selected;
		struct pcap_addr *pcap_address;

		/*
		 * If a port was specified, we make sure it's valid.
		 * Otherwise just grab the first non-"any" port.
		 */
		if (pcap_findalldevs(&devs, pcap_errors) == -1) {
			strncpy(errors, pcap_errors, (CDP_ERRBUF_SIZE - 1) * sizeof(char));
			errors[CDP_ERRBUF_SIZE - 1] = '\0';
			goto fail;
		}

		selected = NULL;
		for (d = devs; !selected && d; d = d->next)
			if (strcmp(d->name, "any") &&
				(!port ||
					(strcmp(d->name, port) == 0)
				)
			)
				selected = d;	
		if (!selected) {
			if (port)
				sprintf(errors, "Port %s not found", port);
			else
				strcpy(errors, "No available ports found");
			pcap_freealldevs(devs);
			goto fail;
		}

		cdp->port = strdup(selected->name);
		cdp->addresses = cdp_llist_new(
			(cdp_dup_fn_t)cdp_address_dup,
			(cdp_free_fn_t)cdp_address_free
		);

		for (pcap_address = selected->addresses; pcap_address; pcap_address = pcap_address->next) {
			address = NULL;
			switch (pcap_address->addr->sa_family) {
			case AF_INET:
				address = cdp_address_new(
					cdp_address_protocol_type[CDP_ADDR_PROTO_IPV4],
					cdp_address_protocol_length[CDP_ADDR_PROTO_IPV4],
					cdp_address_protocol[CDP_ADDR_PROTO_IPV4],
					sizeof(((struct sockaddr_in *)pcap_address->addr)->sin_addr),
					(u_int8_t *)&((struct sockaddr_in *)pcap_address->addr)->sin_addr
				);
				break;
			case AF_INET6:
				address = cdp_address_new(
					cdp_address_protocol_type[CDP_ADDR_PROTO_IPV6],
					cdp_address_protocol_length[CDP_ADDR_PROTO_IPV6],
					cdp_address_protocol[CDP_ADDR_PROTO_IPV6],
					sizeof(((struct sockaddr_in6 *)pcap_address->addr)->sin6_addr),
					(u_int8_t *)&((struct sockaddr_in6 *)pcap_address->addr)->sin6_addr
				);
				break;
			}
			if (address) {
				cdp_llist_append(cdp->addresses, address);
				cdp_address_free(address);
			}
		}

		pcap_freealldevs(devs);
	}
#else /* !HAVE_RECENT_PCAP */
	{
		int sock;
		struct ifreq ifrflags;
		cdp_llist_t *ports;
		cdp_llist_iter_t iter;

		if (!(ports = cdp_get_ports(errors)))
			goto fail;
		for (iter = cdp_llist_iter(ports); iter; iter = cdp_llist_next(iter))
			if (!port || (strcmp(cdp_llist_get(iter), port) == 0))
				break;
		if (!iter) {
			if (port)
				sprintf(errors, "Port %s not found", port);
			else
				strcpy(errors, "No available ports found");
			cdp_llist_free(ports);
			goto fail;
		}

		cdp->port = strdup(cdp_llist_get(iter));
		cdp->addresses = cdp_llist_new(
			(cdp_dup_fn_t)cdp_address_dup,
			(cdp_free_fn_t)cdp_address_free
		);
		cdp_llist_free(ports);

		/*
		 * I think we can reliably only grab the first address
		 * (unless we use that SIOCGIFCONF trick mentioned above).
		 */
		if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			snprintf(errors, (CDP_ERRBUF_SIZE - 1) * sizeof(char),
				"Error opening socket: %s", strerror(errno));
			errors[CDP_ERRBUF_SIZE - 1] = '\0';
			goto fail;
		}
		memset(&ifrflags, 0, sizeof ifrflags);
		strncpy(ifrflags.ifr_name, cdp->port, sizeof ifrflags.ifr_name);
		if (ioctl(sock, SIOCGIFADDR, (char *)&ifrflags) < 0) {
			snprintf(errors, (CDP_ERRBUF_SIZE - 1) * sizeof(char),
				"SIOCGIFADDR error getting flags for interface %s: %s",
				cdp->port, strerror(errno));
			errors[CDP_ERRBUF_SIZE - 1] = '\0';
			close(sock);
			goto fail;
		}
		close(sock);

		address = NULL;
		switch (ifrflags.ifr_addr.sa_family) {
		case AF_INET:
			address = cdp_address_new(
				cdp_address_protocol_type[CDP_ADDR_PROTO_IPV4],
				cdp_address_protocol_length[CDP_ADDR_PROTO_IPV4],
				cdp_address_protocol[CDP_ADDR_PROTO_IPV4],
				sizeof(((struct sockaddr_in *)&ifrflags.ifr_addr)->sin_addr),
				(u_int8_t *)&((struct sockaddr_in *)&ifrflags.ifr_addr)->sin_addr
			);
			break;
		case AF_INET6:
			address = cdp_address_new(
				cdp_address_protocol_type[CDP_ADDR_PROTO_IPV6],
				cdp_address_protocol_length[CDP_ADDR_PROTO_IPV6],
				cdp_address_protocol[CDP_ADDR_PROTO_IPV6],
				sizeof(((struct sockaddr_in6 *)&ifrflags.ifr_addr)->sin6_addr),
				(u_int8_t *)&((struct sockaddr_in6 *)&ifrflags.ifr_addr)->sin6_addr
			);
			break;
		}
		if (address) {
			cdp_llist_append(cdp->addresses, address);
			cdp_address_free(address);
		}
	}
#endif /* !HAVE_RECENT_PCAP */
	
	if (pcap_lookupnet(cdp->port, &net, &mask, pcap_errors) == -1) {
		strncpy(errors, pcap_errors, CDP_ERRBUF_SIZE - 1);
		errors[CDP_ERRBUF_SIZE - 1] = '\0';
		goto fail;
	}
	
	if (!(cdp->pcap = pcap_open_live(cdp->port, BUFSIZ, 1, 0, pcap_errors))) {
		strncpy(errors, pcap_errors, CDP_ERRBUF_SIZE - 1);
		errors[CDP_ERRBUF_SIZE - 1] = '\0';
		goto fail;
	}
	
	if (pcap_compile(cdp->pcap, &filter, BPF_FILTER, 1, mask)) {
		strncpy(errors, pcap_geterr(cdp->pcap), CDP_ERRBUF_SIZE - 1);
		errors[CDP_ERRBUF_SIZE - 1] = '\0';
		goto fail;
	}
	
	if (pcap_setfilter(cdp->pcap, &filter)) {
		strncpy(errors, pcap_geterr(cdp->pcap), CDP_ERRBUF_SIZE - 1);
		errors[CDP_ERRBUF_SIZE - 1] = '\0';
		pcap_freecode(&filter);
		goto fail;
	}
	pcap_freecode(&filter);
	
	if (!(cdp->libnet = libnet_init(LIBNET_LINK, cdp->port, libnet_errors))) {
		strncpy(errors, libnet_errors, CDP_ERRBUF_SIZE - 1);
		errors[CDP_ERRBUF_SIZE - 1] = '\0';
		goto fail;
	}

	/*
	 * Save the hardware address for when cdp_send is called.
	 */
	if (!(hwaddr = libnet_get_hwaddr(cdp->libnet))) {
		strncpy(errors, libnet_geterror(cdp->libnet), CDP_ERRBUF_SIZE - 1);
		errors[CDP_ERRBUF_SIZE - 1] = '\0';
		goto fail;
	}
	memcpy(cdp->mac, hwaddr->ether_addr_octet, 6 * sizeof(u_int8_t));
	
	free(libnet_errors);
	free(pcap_errors);
	return cdp;

fail:
	cdp_free(cdp);
	free(libnet_errors);
	free(pcap_errors);
	return NULL;
}

void
cdp_free(cdp_t *cdp) {
	if (cdp->libnet) libnet_destroy(cdp->libnet);
	if (cdp->pcap) pcap_close(cdp->pcap);
	if (cdp->addresses) cdp_llist_free(cdp->addresses);
	if (cdp->port) free(cdp->port);
	free(cdp);
}

const char *
cdp_get_port(cdp_t *cdp) {
	return cdp->port;
}

const cdp_llist_t *
cdp_get_addresses(cdp_t *cdp) {
	return cdp->addresses;
}

int
cdp_get_fd(cdp_t *cdp) {
	return pcap_fileno(cdp->pcap);
}

static void
timeval_subtract(struct timeval *result, const struct timeval *x,
		const struct timeval *y) {
	struct timeval yy = { y->tv_sec, y->tv_usec };
	
	if (x->tv_usec < yy.tv_usec) {
		int nsec = (yy.tv_usec - x->tv_usec) / 1000000.0 + 1;
		yy.tv_usec -= 1000000.0 * nsec;
		yy.tv_sec += nsec;
	}
	if (x->tv_usec - yy.tv_usec > 1000000.0) {
		int nsec = (x->tv_usec - yy.tv_usec) / 1000000.0;
		yy.tv_usec += 1000000.0 * nsec;
		yy.tv_sec -= nsec;
	}
	result->tv_sec = x->tv_sec - yy.tv_sec;
	result->tv_usec = x->tv_usec - yy.tv_usec;
}

struct cdp_packet *
cdp_recv(cdp_t *cdp, int flags, char *errors) {
	char *pcap_errors;
	struct cdp_packet *packet;
	
	pcap_errors = (char *)calloc(PCAP_ERRBUF_SIZE, sizeof(char));
	packet = NULL;
	
#ifdef HAVE_RECENT_PCAP
	if (pcap_setnonblock(cdp->pcap, flags & CDP_RECV_NONBLOCK, pcap_errors)) {
		strncpy(errors, pcap_errors, (CDP_ERRBUF_SIZE - 1) * sizeof(char));
		errors[CDP_ERRBUF_SIZE - 1] = '\0';
		goto fail;
	}
#else /* !HAVE_RECENT_PCAP */
	{
		int fd, current;
		
		fd = pcap_fileno(cdp->pcap);
		if ((current = fcntl(fd, F_GETFL, 0)) == -1) {
			snprintf(errors, (CDP_ERRBUF_SIZE - 1) * sizeof(char),
					"Could not get socket flags: %s", strerror(errno));
			errors[CDP_ERRBUF_SIZE - 1] = '\0';
			goto fail;			
		}
		if (flags & CDP_RECV_NONBLOCK)
			current |= O_NONBLOCK;
		else
			current &= ~O_NONBLOCK;
		if (fcntl(fd, F_SETFL, current) == -1) {
			snprintf(errors, (CDP_ERRBUF_SIZE - 1) * sizeof(char),
					"Could not set socket flags: %s", strerror(errno));
			errors[CDP_ERRBUF_SIZE - 1] = '\0';
			goto fail;			
		}
	}
#endif /* !HAVE_RECENT_PCAP */
	
	do {
		int result;
		
		/*
		 * Use pcap_dispatch, not pcap_next, so that read errors can be
		 * detected in non-blocking mode.
		 */
		result = pcap_dispatch(cdp->pcap, 1, callback, (u_int8_t*)cdp);
		if (result < 0) {
			strncpy(errors, pcap_geterr(cdp->pcap), CDP_ERRBUF_SIZE);
			errors[CDP_ERRBUF_SIZE - 1] = '\0';
			goto fail;
		}
		if (result) {
			packet = cdp_decode(cdp->data, cdp->header->caplen,
				errors);
			if ((flags & CDP_RECV_DECODE_ERRORS) && !packet)
				goto fail; /* errors is already set */
		} else if (flags & CDP_RECV_NONBLOCK)
			goto fail;
	} while (!packet);
	
	free(pcap_errors);
	return packet;

fail:
	free(pcap_errors);
	return NULL;
}

int
cdp_send(cdp_t *cdp, const struct cdp_packet *packet, char *errors) {
	static u_int8_t dst[6] = { 0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc };
	static u_int8_t oui[3] = { 0x00, 0x00, 0x0c };
	
	int result;

	if (libnet_build_data(
			(packet->packet_length ? packet->packet : NULL), packet->packet_length,
			cdp->libnet, 0
	) == -1)
		goto fail;
	if (libnet_build_802_2snap(
			0xaa, 0xaa,
			0x03, oui,
			0x2000,
			NULL, 0,
			cdp->libnet, 0
	) == -1)
		goto fail;
	/* length is 802.2 SNAP header + CDP's length */
	if (libnet_build_802_3(
			dst, cdp->mac,
			LIBNET_802_2SNAP_H + packet->packet_length,
			NULL, 0,
			cdp->libnet, 0
	) == -1)
		goto fail;
	if ((result = libnet_write(cdp->libnet)) == -1)
		goto fail;
		
	libnet_clear_packet(cdp->libnet);
	return result;

fail:
	libnet_clear_packet(cdp->libnet);
	strncpy(errors, libnet_geterror(cdp->libnet), CDP_ERRBUF_SIZE);
	errors[CDP_ERRBUF_SIZE - 1] = '\0';
	return -1;
}
