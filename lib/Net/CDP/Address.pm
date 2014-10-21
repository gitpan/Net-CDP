package Net::CDP::Address;

#
# $Id: Address.pm,v 1.2 2004/06/07 00:16:21 mchapman Exp $
#

use strict;
use Carp;

use vars qw($VERSION);

$VERSION = (qw$Revision: 1.2 $)[1];

use Net::CDP qw(:protos);

=head1 NAME

Net::CDP::Address - Cisco Discovery Protocol (CDP) interface address

=head1 SYNOPSIS

  use Net::CDP qw(:protos);
  use Net::CDP::Address;
  
  # Constructors
  $address = new Net::CDP::Address($ip);
  $address = new Net::CDP::Address($protocol, $packed);
  $cloned  = clone $address;
  
  # Object methods
  $protocol = $address->protocol;
  $address  = $address->address;
  $packed   = $address->packed;

=head1 DESCRIPTION

A Net::CDP::Address object represents a single addres in the Addresses field
of a CDP packet. Net::CDP::Address objects are immutable.

=head1 CONSTRUCTORS

=over

=item B<new>

    $address = new Net::CDP::Address($ip)
    $address = new Net::CDP::Address($protocol, $packed)

Returns a new Net::CDP::Address object.

If only one argument is provided, C<new> will attempt to parse it as an IPv4 or
IPv6 address.

Otherwise, you must specify the protocol and the bytes that comprise the
address. C<$protocol> should be one of the following constants:

    CDP_ADDR_PROTO_CLNP
    CDP_ADDR_PROTO_IPV4
    CDP_ADDR_PROTO_IPV6
    CDP_ADDR_PROTO_DECNET
    CDP_ADDR_PROTO_APPLETALK
    CDP_ADDR_PROTO_IPX
    CDP_ADDR_PROTO_VINES
    CDP_ADDR_PROTO_XNS
    CDP_ADDR_PROTO_APOLLO

These constants can be exported from Net::CDP::Address using the tag
C<:protos>. See L<Exporter>.

C<$packed> must be a string consisting of the bytes that make up the address in
network order. You may find the C<pack> function useful in generating this
string.

=cut

sub new($$;$) {
	my $class = shift;
	croak 'Usage: Net::CDP::Address->new($ip) or Net::CDP::Address->new($protocol, $packed)' unless defined $_[0];
	my $ip = shift;
	my $protocol;
	my $packed;

	if (@_ && defined $_[0]) {
		$protocol = $ip;
		$packed = shift;
	} elsif (defined($packed = Net::CDP::_v6_pack($ip))) {
		$protocol = CDP_ADDR_PROTO_IPV6;
	} elsif (defined($packed = Net::CDP::_v4_pack($ip))) {
		$protocol = CDP_ADDR_PROTO_IPV4;
	} elsif (defined($packed = gethostbyname($ip))) {
		$protocol = CDP_ADDR_PROTO_IPV4;
	}
	croak "Cannot parse address '$ip'" unless defined $protocol;
	return $class->_new_by_id($protocol, $packed);
}

=item B<clone>

    $cloned = clone $packet

Returns a deep copy of the supplied Net::CDP::Address object.

=back

=head1 OBJECT METHODS

=over

=item B<protocol>

    $protocol = $address->protocol()

Returns this address's protocol.

=cut

*protocol = \&_protocol_id;

=item B<address>

    $ip = $address->address()

If this is an IPv4 or IPv6 address, returns its standard string representation,
otherwise C<undef>.

=cut

sub address($) {
	my $self = shift or croak 'Usage: $self->address';
	my $protocol = $self->_protocol_id;
	my $packed = $self->_address;
	if ($protocol == CDP_ADDR_PROTO_IPV4) {
		return Net::CDP::_v4_unpack($packed);
	} elsif ($protocol == CDP_ADDR_PROTO_IPV6) {
		return Net::CDP::_v6_unpack($packed);
	}
	return undef;
}

=item B<packed>

    $packed = $address->packed()

Returns this address as a string consisting of the bytes that comprise it in
network order.

=cut

*packed = \&_address;

=back

=head1 SEE ALSO

L<Net::CDP>

=head1 AUTHOR

Michael Chapman, E<lt>cpan@very.puzzling.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2004 by Michael Chapman

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

1;
