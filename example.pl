#!/usr/bin/env perl

#
# This script demonstrates the Net::CDP::Manager module. It should be
# run as root.
#

use strict;
use warnings;

# This script can be run directly from the source directory
use lib 'blib/arch';
use lib 'blib/lib';

use Net::CDP::Manager;

sub pretty { defined $_[0] ? @_ : '(undef)' }
sub duplex { defined $_[0] ? ($_[0] ? 'full' : 'half') : '(unknown)' }
sub hexify { join ' ', map { map { sprintf '0x%02x', ord } split // } @_ }
sub binarize { unpack "B8", pack "C", shift }

sub callback {
	my ($packet, $port) = @_;
	
	# Print out the packet
	print "Received on port $port:\n";
	print '  Version: ', pretty($packet->version), "\n";
	print '  TTL: ', pretty($packet->ttl), "\n";
	print '  Checksum: ', pretty($packet->checksum), "\n";
	print '  Device ID: ', pretty($packet->device), "\n";
	if ($packet->addresses) {
		print "  Addresses:\n";
		foreach ($packet->addresses) {
			print '    Protocol: ', pretty($_->protocol), "\n";
			print '    Address: ', pretty($_->address), "\n";
		}
	} else {
		print "  Addresses: (none)\n";
	}
	print '  Port ID: ', pretty($packet->port), "\n";
	print '  Capabilities: ', binarize($packet->capabilities), "\n";
	print '  IOS Version: ', pretty($packet->ios_version), "\n"; 
	print '  Platform: ', pretty($packet->platform), "\n";
	if ($packet->ip_prefixes) {
		print "  IP Prefixes:\n";
		foreach ($packet->ip_prefixes) {
			print '    Network: ', hexify($_->network), "\n";
			print '    Length: ', pretty($_->length), "\n";
		}
	} else {
		print "  IP Prefixes: (none)\n";
	}
	print '  VTP Management Domain: ', pretty($packet->vtp_management_domain), "\n";
	print '  Native VLAN: ', pretty($packet->native_vlan), "\n";
	print '  Duplex: ', duplex($packet->duplex), "\n";
	print "\n";
}

while (1) {
	# Update the port list
	cdp_manage_soft cdp_ports;
	
	# Send CDP packets
	cdp_send;
	
	print 'Currently managing: ', join(', ', sort &cdp_managed), "\n";
	print 'Currently active:   ', join(', ', sort &cdp_active), "\n\n";
	
	# Wait for CDP packets for 60 seconds
	cdp_loop \&callback, 60;
}
