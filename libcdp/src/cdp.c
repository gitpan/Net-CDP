/*
 * $Id: cdp.c,v 1.2 2004/09/02 11:49:23 mchapman Exp $
 */

#include <config.h>

#include "cdp.h"

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */

#ifdef HAVE_NET_IF_H
# include <net/if.h>
#endif /* HAVE_NET_IF_H */

#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif /* HAVE_SYS_IOCTL_H */

#ifdef HAVE_ETHTOOL_H
# include <linux/ethtool.h>
# include <linux/sockios.h>
#endif /* HAVE_ETHTOOL_H */

#ifdef HAVE_NETINET_IF_ETHER_H
# include <netinet/if_ether.h>
#endif /* HAVE_NETINET_IF_ETHER_H */

#ifndef HAVE_PCAP_SETNONBLOCK
# ifdef HAVE_FCNTL_H
#  include <fcntl.h>
# endif /* HAVE_FCNTL_H */
#endif /* !HAVE_PCAP_SETNONBLOCK */

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif /* HAVE_ERRNO_H */

#ifdef HAVE_MULTICAST
# ifdef HAVE_NETPACKET_PACKET_H
#  include <netpacket/packet.h>
# endif /* HAVE_NETPACKET_PACKET_H */
#endif

#include "cdp_encoding.h"

#define BPF_FILTER "ether host 01:00:0c:cc:cc:cc and ether[20:2] = 0x2000"

static const u_int8_t cdp_multicast_mac[] =
	{ 0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc };

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

#ifdef HAVE_MULTICAST

static int
multicast(const cdp_t *cdp, int add) {
	int result;
	
	struct ifreq ifr;
	struct packet_mreq mreq;
	
	if (!cdp->pcap)
		return -1;
	
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, cdp->port, sizeof ifr.ifr_name - 1);
	ifr.ifr_name[sizeof ifr.ifr_name - 1] = '\0';
	result = ioctl(pcap_fileno(cdp->pcap), SIOCGIFINDEX, &ifr);
	
	if (result < 0)
		return result;
	
	mreq.mr_ifindex = ifr.ifr_ifindex;
	mreq.mr_type = PACKET_MR_MULTICAST;
	mreq.mr_alen = 6;
	memcpy(mreq.mr_address, cdp_multicast_mac, 6);
	mreq.mr_address[6] = mreq.mr_address[7] = '\0';
	return setsockopt(
		pcap_fileno(cdp->pcap),
		SOL_PACKET,
		add ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP,
		&mreq,
		sizeof(struct packet_mreq)
	);
}

#else /* HAVE_MULTICAST */

static int multicast(const cdp_t *cdp, int add) { return 1; }

#endif /* !HAVE_MULTICAST */

#ifdef HAVE_ETHTOOL_H

static void
duplex(cdp_t *cdp) {
	int result, fd;
	struct ifreq ifr;
	struct ethtool_cmd ecmd;
	
	if (cdp->flags & CDP_DISABLE_SEND) {
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd < 0)
			return;
	} else
		fd = libnet_getfd(cdp->libnet);
	
	memset(&ifr, 0, sizeof(struct ifreq));
	strncpy(ifr.ifr_name, cdp->port, sizeof ifr.ifr_name - 1);
	ifr.ifr_name[sizeof ifr.ifr_name - 1] = '\0';
	ifr.ifr_data = (caddr_t)&ecmd;
	ecmd.cmd = ETHTOOL_GSET;
	result = ioctl(fd, SIOCETHTOOL, &ifr);
	
	if (result >= 0) {
		if (!cdp->duplex) cdp->duplex = (u_int8_t *)calloc(1, sizeof(u_int8_t));
		*cdp->duplex = (ecmd.duplex == DUPLEX_FULL ? 1 : 0);
	}

	if (cdp->flags & CDP_DISABLE_SEND)
		close(fd);
}

#endif /* HAVE_ETHTOOL_H */

cdp_llist_t *
cdp_get_ports(char *errors) {
	/* This code is lifted from Ethereal 0.9.13 */
	char *pcap_errors, *libnet_errors;
	int sock;
	int len, lastlen;
	struct ifconf ifc;
	struct ifreq ifrflags, *ifr, *last;
	char *buf;
	int linktype;
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
		 * Also grab the data link type here.
		 */
		if (!(pcap = pcap_open_live(ifr->ifr_name, 68, 0, 0, pcap_errors)))
			continue;
		linktype = pcap_datalink(pcap);
		pcap_close(pcap);

		/*
		 * Skip interfaces where we can't use ethernet addresses.
		 */
		if (!(linktype == DLT_EN10MB || linktype == DLT_FDDI || linktype == DLT_IEEE802))
			continue;

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

cdp_t *
cdp_new(const char *port, int flags, char *errors) {
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
	cdp->flags = flags;
	
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
	
	if (pcap_lookupnet(cdp->port, &net, &mask, pcap_errors) == -1) {
		strncpy(errors, pcap_errors, CDP_ERRBUF_SIZE - 1);
		errors[CDP_ERRBUF_SIZE - 1] = '\0';
		goto fail;
	}
	
	if (!(cdp->flags & CDP_DISABLE_RECV)) {
		if (!(cdp->pcap = pcap_open_live(cdp->port, BUFSIZ,
					cdp->flags & CDP_PROMISCUOUS, 0, pcap_errors))) {
			strncpy(errors, pcap_errors, CDP_ERRBUF_SIZE - 1);
			errors[CDP_ERRBUF_SIZE - 1] = '\0';
			goto fail;
		}
		if (!(cdp->flags & CDP_PROMISCUOUS)) {
			if (multicast(cdp, 1) < 0) {
				snprintf(errors, (CDP_ERRBUF_SIZE - 1) * sizeof(char),
					"Could not enable multicast address for interface %s: %s",
					cdp->port, strerror(errno));
				errors[CDP_ERRBUF_SIZE - 1] = '\0';
				goto fail;
			}
		}

		if (pcap_compile(cdp->pcap, &filter, BPF_FILTER, 1, mask)) {
			strncpy(errors, pcap_geterr(cdp->pcap), CDP_ERRBUF_SIZE - 1);
			errors[CDP_ERRBUF_SIZE - 1] = '\0';
			goto fail_multi;
		}

		if (pcap_setfilter(cdp->pcap, &filter)) {
			strncpy(errors, pcap_geterr(cdp->pcap), CDP_ERRBUF_SIZE - 1);
			errors[CDP_ERRBUF_SIZE - 1] = '\0';
			pcap_freecode(&filter);
			goto fail_multi;
		}
		pcap_freecode(&filter);
	}
	
	if (!(cdp->flags & CDP_DISABLE_SEND)) {
		if (!(cdp->libnet = libnet_init(LIBNET_LINK, cdp->port, libnet_errors))) {
			strncpy(errors, libnet_errors, CDP_ERRBUF_SIZE - 1);
			errors[CDP_ERRBUF_SIZE - 1] = '\0';
			goto fail_multi;
		}

		/*
		 * Save the hardware address for when cdp_send is called.
		 */
		if (!(hwaddr = libnet_get_hwaddr(cdp->libnet))) {
			strncpy(errors, libnet_geterror(cdp->libnet), CDP_ERRBUF_SIZE - 1);
			errors[CDP_ERRBUF_SIZE - 1] = '\0';
			goto fail_multi;
		}
		memcpy(cdp->mac, hwaddr->ether_addr_octet, 6 * sizeof(u_int8_t));
	}
	
#ifdef HAVE_ETHTOOL_H
	/*
	 * Grab the duplex mode of the interface now.
	 */
	duplex(cdp);
#endif /* HAVE_ETHTOOL_H */
	
	free(libnet_errors);
	free(pcap_errors);
	return cdp;

fail_multi:
	if (!(cdp->flags & CDP_DISABLE_RECV))
		if (!(cdp->flags & CDP_PROMISCUOUS))
			multicast(cdp, 0); /* Ignore errors */
	
fail:
	cdp_free(cdp);
	free(libnet_errors);
	free(pcap_errors);
	return NULL;
}

void
cdp_free(cdp_t *cdp) {
	if (cdp->port) {
		if (!(cdp->flags & CDP_DISABLE_RECV))
			if (!(cdp->flags & CDP_PROMISCUOUS))
				multicast(cdp, 0); /* Ignore errors */
		free(cdp->port);
	}
	if (cdp->libnet) libnet_destroy(cdp->libnet);
	if (cdp->pcap) pcap_close(cdp->pcap);
	if (cdp->addresses) cdp_llist_free(cdp->addresses);
	if (cdp->duplex) free(cdp->duplex);
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

const u_int8_t *
cdp_get_duplex(cdp_t *cdp) {
	return cdp->duplex;
}

int
cdp_get_fd(cdp_t *cdp) {
	return cdp->flags & CDP_DISABLE_RECV ? -1 : pcap_fileno(cdp->pcap);
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
	
	if (cdp->flags & CDP_DISABLE_RECV) {
		sprintf(errors, "Can not receive with CDP_DISABLE_RECV set");
		return NULL;
	}
	
	pcap_errors = (char *)calloc(PCAP_ERRBUF_SIZE, sizeof(char));
	packet = NULL;
	
#if HAVE_RECENT_PCAP
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
			packet = cdp_decode(cdp->data, cdp->header->caplen, errors);
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
	
	if (cdp->flags & CDP_DISABLE_SEND) {
		sprintf(errors, "Can not send with CDP_DISABLE_SEND set");
		return -1;
	}

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
