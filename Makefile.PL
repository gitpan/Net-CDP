use 5.00503;
use ExtUtils::MakeMaker;

# We need to test if this is a recent pcap version.
# Since there's no version information in pcap.h we can use, we try to
# get the symbols we're interested in.
sub recent_pcap {
	require DynaLoader;
	my @pcap = DynaLoader::dl_findfile('-lpcap')
		or return 0; # This'll be catched in WriteMakefile
	my $pcap = DynaLoader::dl_load_file($pcap[0])
		or return 0; # Meh, stuff'll break later
	return
		defined DynaLoader::dl_find_symbol($pcap, 'pcap_findalldevs') &&
		defined DynaLoader::dl_find_symbol($pcap, 'pcap_setnonblock');
}

WriteMakefile(
	NAME         => 'Net::CDP',
	VERSION_FROM => 'lib/Net/CDP.pm',
	PREREQ_PM    => { Carp => 0, 'Test::More' => 0, },
	($] >= 5.005 ? (
		ABSTRACT_FROM  => 'lib/Net/CDP.pm',
		AUTHOR         => 'Michael Chapman <cpan@very.puzzling.org>'
	) : ()),
	LIBS         => ['-lpcap -lnet'],
	(recent_pcap() ? (
		DEFINE     => '-DHAVE_RECENT_PCAP'
	) : ()),
	INC          => '-I.' . ( -d '/usr/include/pcap' ? ' -I/usr/include/pcap' : '' ),
	OBJECT       => <<'EOF',
$(BASEEXT)$(OBJ_EXT)
cdp$(OBJ_EXT)
cdp_address$(OBJ_EXT)
cdp_checksum$(OBJ_EXT)
cdp_encoding$(OBJ_EXT)
cdp_ip_prefix$(OBJ_EXT)
cdp_llist$(OBJ_EXT)
cdp_packet$(OBJ_EXT)
EOF
);

if (eval { require ExtUtils::Constant; 1 }) {
 	my @names = (qw(
CDP_RECV_NONBLOCK CDP_RECV_DECODE_ERRORS
CDP_ADDR_PROTO_CLNP CDP_ADDR_PROTO_IPV4 CDP_ADDR_PROTO_IPV6
CDP_ADDR_PROTO_DECNET CDP_ADDR_PROTO_APPLETALK CDP_ADDR_PROTO_IPX
CDP_ADDR_PROTO_VINES CDP_ADDR_PROTO_XNS CDP_ADDR_PROTO_APOLLO
CDP_CAP_ROUTER CDP_CAP_TRANSPARENT_BRIDGE CDP_CAP_SOURCE_BRIDGE
CDP_CAP_SWITCH CDP_CAP_HOST CDP_CAP_IGMP CDP_CAP_REPEATER
	));
	ExtUtils::Constant::WriteConstants(
		NAME         => 'Net::CDP',
		NAMES        => \@names,
		DEFAULT_TYPE => 'UV',
		C_FILE       => 'const-c.inc',
		XS_FILE      => 'const-xs.inc',
	);
} else {
	use File::Copy;
	use File::Spec;
	foreach my $file ('const-c.inc', 'const-xs.inc') {
		my $fallback = File::Spec->catfile('fallback', $file);
		copy($fallback, $file) or die "Can't copy $fallback to $file: $!";
	}
}
