package Net::CDP;

#
# $Id: CDP.pm,v 1.1.1.1 2004/06/04 06:01:29 mchapman Exp $
#

use 5.00503;
use strict;
use Carp;

use vars qw($VERSION @ISA $AUTOLOAD @EXPORT @EXPORT_OK %EXPORT_TAGS);

$VERSION = '0.02';

require Exporter;
require DynaLoader;
use AutoLoader;
@ISA = qw(Exporter DynaLoader);

my @EXPORT_RECV = qw(
	CDP_RECV_NONBLOCK CDP_RECV_DECODE_ERRORS
);
my @EXPORT_CAPS = qw(
	CDP_CAP_ROUTER CDP_CAP_TRANSPARENT_BRIDGE CDP_CAP_SOURCE_BRIDGE
	CDP_CAP_SWITCH CDP_CAP_HOST CDP_CAP_IGMP CDP_CAP_REPEATER
);
my @EXPORT_PROTOS = qw(
	CDP_ADDR_PROTO_CLNP CDP_ADDR_PROTO_IPV4 CDP_ADDR_PROTO_IPV6
	CDP_ADDR_PROTO_DECNET CDP_ADDR_PROTO_APPLETALK CDP_ADDR_PROTO_IPX
	CDP_ADDR_PROTO_VINES CDP_ADDR_PROTO_XNS CDP_ADDR_PROTO_APOLLO
);

@EXPORT = qw();
@EXPORT_OK = (@EXPORT_RECV, @EXPORT_CAPS, @EXPORT_PROTOS, );
%EXPORT_TAGS = (
	recv => [ @EXPORT_RECV, ],
	caps => [ @EXPORT_CAPS, ],
	protos => [ @EXPORT_PROTOS, ],
);	

sub AUTOLOAD {
	my $constname;
	($constname = $AUTOLOAD) =~ s/.*:://;
	croak "&Net::CDP::constant not defined" if $constname eq 'constant';
	my ($error, $val) = constant($constname);
	unless ($error) {
		no strict 'refs';
		*$AUTOLOAD = sub { $val };
		goto &$AUTOLOAD;
	}
	$AutoLoader::AUTOLOAD = $AUTOLOAD;
	goto &AutoLoader::AUTOLOAD;
}

bootstrap Net::CDP $VERSION;

# Load in the Perl part of the Net::CDP::Address
# and Net::CDP::IPPrefix namespaces
require Net::CDP::Address;
require Net::CDP::IPPrefix;

1;
__END__

=head1 NAME

Net::CDP - Cisco Discovery Protocol (CDP) advertiser/listener

=head1 SYNOPSIS

  use Net::CDP qw(:caps :protos);

  # Available ports (interfaces)
  @ports = Net::CDP::ports;  

  # Creating a CDP advertiser/listener
  $cdp = new Net::CDP;

  # Receiving a CDP packet
  $packet = $cdp->recv;
  
  # Sending a CDP packet
  $cdp->send($packet);
  
  # Other Net::CDP methods
  $port = $cdp->port;
  @addresses = $cdp->addresses;

=head1 DESCRIPTION

The Net::CDP module implements an advertiser/listener for the Cisco
Discovery Protocol.

CDP is a proprietary Cisco protocol for discovering devices on a network. A
typical CDP implementation sends periodic CDP packets on every network
interface. It might also listen for packets for advertisements sent by
neighboring devices.

A Net::CDP object represents an advertiser/listener for a single network
port. It can send and receive individual CDP packets, each represented by a
L<Net::CDP::Packet> object.

=head1 CONSTRUCTORS

=over

=item B<new>

    $cdp = new Net::CDP()
    $cdp = new Net::CDP($port)

Returns a new Net::CDP object.

If specified, C<$port> must be the name of the network port (interface) that
should be used to send and receive packets. If ommitted, the first interface on
your system is used (typically, this is the first Ethernet device -- "eth0", for
instance).

You can use the L</"ports"> class method to retrieve a list of valid port names.

=back

=head1 CLASS METHODS

=over 

=item B<ports>

    @ports = Net::CDP::ports()

Returns a list of network ports (interfaces) that can be used by this module.

=back

=head1 OBJECT METHODS

=over

=item B<port>

    $port = $cdp->port()

Returns the network port (interface) associated with this Net::CDP object.

=item B<addresses>

    @addresses = $cdp->addresses()

Returns the addresses of the network port (interface) associated with this
Net::CDP object. In scalar context the number of addresses is returned.

I<NOTE:> Currently only a single IPv4 address is returned, even if the interface
has more than one bound address.

=item B<recv>

    $packet = $cdp->recv()
    $packet = $cdp->recv($flags)

Returns the next available CDP packet as a L<Net::CDP::Packet> object. If the
CDP_RECV_NONBLOCK flag is set, an undefined value returned if no packets are
immediately available. Otherwise, this method blocks until a packet is received
or an error occurs. If an error occurs, this method croaks.

If specified, C<$flags> is a bitmask specifying one or more of the following
constants:

=over

=item CDP_RECV_NONBLOCK

Do not block if no CDP packets are immediately available.

=item CDP_RECV_DECODE_ERRORS

Decoding errors will result in C<recv> croaking.

=back

These constants can be exported from Net::CDP using the tag C<:recv>. See
L<Exporter>.

=item B<send>

    $bytes = $cdp->send($packet)

Transmits the specified packet, which must be a L<Net::CDP::Packet> object,
and returns the number of bytes sent. If an error occurs, this method croaks.

=back

=head1 SEE ALSO

L<Net::CDP::Packet>

=head1 AUTHOR

Michael Chapman, E<lt>mike.chapman@optusnet.com.auE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2004 by Michael Chapman

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

sub _v4_pack {
	my $ip = shift;
	
	if ($ip =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/ &&
		$1 >= 0 && $1 <= 255 &&
		$2 >= 0 && $2 <= 255 &&
		$3 >= 0 && $3 <= 255 &&
		$4 >= 0 && $4 <= 255
	) {
		pack 'C4', $1, $2, $3, $4;
	} elsif ($ip =~ /^(\d+)\.(\d+)\.(\d+)$/ &&
		$1 >= 0 && $1 <= 255 &&
		$2 >= 0 && $2 <= 255 &&
		$3 >= 0 && $3 <= 255
	) {
		pack 'C4', $1, $2, 0, $3;
	} elsif ($ip =~ /^(\d+)\.(\d+)$/ &&
		$1 >= 0 && $1 <= 255 &&
		$2 >= 0 && $2 <= 255
	) {
		pack 'C4', $1, 0, 0, $4;
	} else {
		undef;
	}
}

sub _v4_unpack {
	join '.', unpack 'C4', shift;
}

use constant POWERS => "\x00\x80\xc0\xe0\xf0\xf8\xfc\xfe\xff";

sub _mask_pack {
	my $mask = shift;

	if ($mask =~ /^255\.255\.255\.(\d+)$/) {
		my $index = index POWERS, chr $1;
		$index >= 0 ? 24 + $index : undef;
	} elsif ($mask =~ /^255\.255\.(\d+)\.0$/) {
		my $index = index POWERS, chr $1;
		$index >= 0 ? 16 + $index : undef;
	} elsif ($mask =~ /^255\.(\d+)\.0\.0$/) {
		my $index = index POWERS, chr $1;
		$index >= 0 ? 8 + $index : undef;
	} elsif ($mask =~ /^(\d+)\.0\.0\.0$/) {
		my $index = index POWERS, chr $1;
		$index >= 0 ? $index : undef;
	} else {
		undef;
	}
}

sub _mask_unpack {
	_v4_unpack(pack 'B32', 1 x shift);
}

sub _v6_pack {
	my $ip = shift;

	if ($ip =~ /^([\da-f\:]+)(?::(\d+)\.(\d+)\.(\d+)\.(\d+))?$/i) {
		my $ipv6 = $1;
		if (
			defined $2 &&
			$2 >= 0 && $2 <= 255 &&
			$3 >= 0 && $3 <= 255 &&
			$4 >= 0 && $4 <= 255 &&
			$5 >= 0 && $5 <= 255
		) {
			$ipv6 .= sprintf ':%x:%x',
				($2 << 8) | $3,
				($4 << 8) | $5;
		}
		unless ($ipv6 =~ /:::/ || $ipv6 =~ /::.*::/) {
			$ipv6 =~ s/::/':0' x (9 - ($ipv6 =~ tr,:,:,))/e;
			if (($ipv6 =~ tr/:/:/) == 7) {
				$ipv6 =~ s/^:/0:/;
				$ipv6 =~ s/:$/:0/;
				return pack 'n8', map hex, split /:/, $ipv6;
			}
		}
	}
	undef;
}

sub _v6_unpack {
	my $result = sprintf '%x:%x:%x:%x:%x:%x:%x:%x', unpack 'n8', shift;
	$result =~ s/:0(:0)+:/::/;
	$result =~ s/^0:/:/;
	$result;
}
