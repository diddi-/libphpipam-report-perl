package phpipam::report;

=head1 phpipam::report

phpipam::report - Reporting module for phpIPAM

=head1 SYNOPSIS

  use phpipam::report;


=head1 DESCRIPTION

This module will collect statistics from the phpIPAM database and generate
a simple report with interesting information based on filters and thresholds
given to the module.

=head2 EXPORT

None by default.

=head1 METHODS

=cut

use 5.018001;
use strict;
use warnings;
use Carp;
use Net::IP qw (ip_bintoip ip_inttobin);

use lib '/home/diddi/git/libphpipam-perl/lib';
use phpipam;
use Data::Dumper;
require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use phpipam::report ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '0.01';

=head2 new()

Create a new phpipam::report object

=cut
sub new {

    my $class = shift;
    my $self = {};

    bless($self, $class);

    my (%args) = @_;
    $self->{ARGS} = \%args;

    $self->{CFG}->{SMTPHOST}          = $self->_arg("smtp_host", undef);
    $self->{CFG}->{SMTPPORT}          = $self->_arg("smtp_port", "25");
    $self->{CFG}->{DBHOST}          = $self->_arg("dbhost", "localhost");
    $self->{CFG}->{DBUSER}          = $self->_arg("dbuser", "phpipam");
    $self->{CFG}->{DBPASS}          = $self->_arg("dbpass", "phpipam");
    $self->{CFG}->{DBPORT}          = $self->_arg("dbport", 3306);
    $self->{CFG}->{DBNAME}          = $self->_arg("dbname", "phpipam");

    $self->{ipam} = phpipam->new(
        dbhost => $self->{CFG}->{DBHOST},
        dbport => $self->{CFG}->{DBPORT},
        dbuser => $self->{CFG}->{DBUSER},
        dbpass => $self->{CFG}->{DBPASS},
        dbname => $self->{CFG}->{DBNAME},
    );
    return $self;
}

sub _arg {
    my $self = shift;
    my $arg = shift;
    my $default = shift;
    my $valid = shift;

    my $base = $self->{ARGS};

    my $val = (exists($base->{$arg}) ? $base->{$arg} : $default);

    if(defined ($valid)) {
        my $pass = 0;
        foreach my $check (@{$valid}) {
            $pass = 1 if($check eq $val);
        }

        if($pass == 0) {
            croak("Invalid value for setting '$arg' = '$val'.  Valid are: ['".join("','",@{$valid})."']");
        }

    }

    return $val;
}

=head2 getUtilization(options)

Get a summary of IP utilization within a subnet,section, or the entire phpIPAM.
Default is to return a hash with utilization for all subnets in all sections.
Options are

    subnet => CIDR          - IPv4 or IPv6 CIDR as stored in the database.
                              NOTE: phpipam::report does not do any calculations
                              on subnets, a subnet must exactly match what's in
                              the database.

    section => section      - Section name as stored in the database.
                              Section names are case sensitive.

=cut
sub getUtilization {
    my $self = shift;

    return undef;
}

=head2 getFree(%options)

Get the number of free IP addresses.
phpipam::report consider all unallocated addresses to be free, this means that
* Active
* Reserved
* Offline
* DHCP
are all considered to be allocated addresses and are not counted.
%options limit the scope to count for free addresses, options are

    section => string           - Section name as stored in the database.
                                  Section names are case sensitive.

    subnet => CIDR              - IPv4 or IPv6 CIDR as stored in the database.
                                  NOTE: phpipam does not do any calculations
                                  on subnets, a subnet must exactly match what's in
                                  the database.

    vrf => [name|RD]            - Name or Route-Distinguisher of the VRF to search in.
By default getFree will return all free addresses in all subnets.

    my $free = $reporter->getFree({section => "Section1", subnet => "192.168.0.0/24"});

getFree() will sort the subnets in VRF and Sections so you know what subnet you're
currently looking at.
An example structure will look something like this

    $VAR1 = {
          'GLOBAL' => {
                        'Section1' => {
                                          '192.168.0.0/24' => bless( {
                                                                           'value' => [
                                                                                        253
                                                                                      ],
                                                                           'sign' => '+'
                                                                         }, 'Math::BigInt' ),
                                      }
                      }
            }

Note that subnets that do not belong to any VRFs are automatically put in the GLOBAL vrf.
Currently the number of free addresses are stored as a blessed Math::BigInt to be able to handle
IPv6 subnets, as those numbers tend to be quite large...
Just printing the number will be fine though

    print "Free addresses: ". $free->{'GLOBAL'}->{'Section1'}->{'192.168.0.0/24'}."\n"

=cut

sub getFree {
    my $self = shift;
    my $opts = shift;
    my $section = $opts->{'section'} ||= undef;
    my $vrf = $opts->{'vrf'} ||= undef;
    my $subnet = $opts->{'subnet'} ||= undef;
    my $netip = undef;
    my $ipam_vrf = undef;
    my $ipam_section = undef;
    my $free = {};

    if($subnet) {
        $netip = Net::IP->new($subnet);
        if(not $netip) {
            carp ("$netip is not a valid subnet");
            return undef;
        }
    }

    if(not $vrf) {
        $ipam_vrf = $self->{ipam}->getAllVrfs();
        unshift(@{$ipam_vrf}, undef);
    }else {
        $ipam_vrf = $self->{ipam}->getVrf($vrf);
        if(not $ipam_vrf) {
            return undef;
        }
    }

    if(not $section) {
        $ipam_section = $self->{ipam}->getAllSections();
        # unshift(@{$ipam_section}, undef);
    }else {
        $ipam_section = $self->{ipam}->getSection($section);
        if(not $ipam_section) {
            return undef;
        }
    }

    foreach my $v (@{$ipam_vrf}) {
        my $v_name = $v->{name} ? $v->{name} : 'GLOBAL';
        foreach my $s (@{$ipam_section}) {
            my $subnets = $self->{ipam}->getSubnets({vrf => $v->{name}, section => $s->{name}});
            foreach my $snet (@{$subnets}) {
                # Turn that magical integer into a real subnet that we can work with.
                my $int = $snet->{subnet};
                my $mask = $snet->{mask};
                my $version = length($int) > 10 ? 6 : 4;
                my $ip = ip_bintoip(ip_inttobin($int, $version),$version);
                # We need it to be an Net::IP object to be able to get the size
                my $t_netip = Net::IP->new("$ip/$mask");
                my $addresses = $self->{ipam}->getAddresses({vrf => $v->{name}, section => $s->{name}, subnet => "$ip/$mask", strict => 1});
                my $f = $t_netip->size() - @{$addresses} - 2;
                $free->{$v_name}->{$s->{name}}->{"$ip/$mask"} = $f;
            }
        }
    }

    return $free;
}

=head2 getActive($section, $subnet)

Get the number of IP addresses that are marked as being 'Active' in $subnet.

    $reporter->getActive("servers", "10.0.0.0/8");
=cut
sub getActive {
    my $self = shift;

    return undef;
}

=head2 getReserved($section, $subnet)

Get the number of IP addresses that are marked as being 'Reserved' in $subnet.

    $reporter->getReserved("servers", "10.0.0.0/8");
=cut
sub getReserved {
    my $self = shift;

    return undef;
}

=head2 getOffline($section $subnet)

Get the number of IP addresses that are marked as being 'Offline' in $subnet.

    $reporter->getOffline("servers", "10.0.0.0/8");
=cut
sub getOffline {
    my $self = shift;

    return undef;
}

=head2 getDHCP($section, $subnet)

Get the number of IP addresses that are marked as being 'DHCP' in $subnet.

    $reporter->getDHCP("servers", "10.0.0.0/8");
=cut
sub getDHCP {
    my $self = shift;

    return undef;
}

=head2 getNoData(%opts)

Get all IP addresses within a VRF, section or subnet that does not have a value for the
required data column.
This is useful if you have custom data fields that are mandatory in your phpIPAM installation.
By default returns all addresses in all VRFs, sections and subnets if no options are given.

    $reporter->getNoData({data => 'owner', section => "servers", subnet => "10.0.0.0/8"});

%opts limit the scope for which addresses are searched, options are

    section => string           - Section name as stored in the database.
                                  Section names are case sensitive.

    subnet => CIDR              - IPv4 or IPv6 CIDR as stored in the database.
                                  NOTE: phpipam does not do any calculations
                                  on subnets, a subnet must exactly match what's in
                                  the database.

    vrf => [name|RD]            - Name or Route-Distinguisher of the VRF to search in.

    data => name                - A database column name in the ipaddresses table.
                                  This can be any column, native or custom.

By default getNoData will return all addresses in all subnets that does not
have any a value set for the required data column.

    my $addresses = $reporter->getNoData({data => 'dns_name'});

getNoData() will sort the subnets in VRF and Sections so you know what subnet you're
currently looking at.
An example structure will look something like this

    $VAR1 = {
          'TestVRF' => {
                         'SectionA' => {
                                      '192.168.0.0/24' => [
                                                            '192.168.0.1'
                                                          ]
                                    }
                       },
          'GLOBAL' => {
                        'SectionB' => {
                                          '172.20.1.0/24' => [
                                                               '172.20.1.10',
                                                               '172.20.1.11'
                                                             ],
                                        }
                      }
            };

Note that subnets that do not belong to any VRFs are automatically put in the GLOBAL vrf.

=cut
sub getNoData {
    my $self = shift;
    my $opts = shift;
    my $section = $opts->{'section'} ||= undef;
    my $vrf = $opts->{'vrf'} ||= undef;
    my $subnet = $opts->{'subnet'} ||= undef;
    my $DataColumn = $opts->{'data'} ||= undef;
    my $netip = undef;
    my $ipam_vrf = undef;
    my $ipam_section = undef;
    my $ret = {};

    if(not $DataColumn) {
        carp("Missing mandatory argument 'data' to getNoData");
        return undef;
    }

    if($subnet) {
        $netip = Net::IP->new($subnet);
        if(not $netip) {
            carp ("$netip is not a valid subnet");
            return undef;
        }
    }

    if(not $vrf) {
        $ipam_vrf = $self->{ipam}->getAllVrfs();
        unshift(@{$ipam_vrf}, undef);
    }else {
        $ipam_vrf = $self->{ipam}->getVrf($vrf);
        if(not $ipam_vrf) {
            return undef;
        }
    }

    if(not $section) {
        $ipam_section = $self->{ipam}->getAllSections();
        # unshift(@{$ipam_section}, undef);
    }else {
        $ipam_section = $self->{ipam}->getSection($section);
        if(not $ipam_section) {
            return undef;
        }
    }

    foreach my $v (@{$ipam_vrf}) {
        my $v_name = $v->{name} ? $v->{name} : 'GLOBAL';
        foreach my $s (@{$ipam_section}) {
            my $subnets = $self->{ipam}->getSubnets({vrf => $v->{name}, section => $s->{name}});
            foreach my $snet (@{$subnets}) {
                # Turn that magical integer into a real subnet that we can work with.
                my $int = $snet->{subnet};
                my $mask = $snet->{mask};
                my $version = length($int) > 10 ? 6 : 4;
                my $ip = ip_bintoip(ip_inttobin($int, $version),$version);
                my $addresses = $self->{ipam}->getAddresses({vrf => $v->{name}, section => $s->{name}, subnet => "$ip/$mask", strict => 1});
                my @noData;
                foreach my $addr (@{$addresses}) {
                    if(not defined $addr->{$DataColumn}) {
                        # We're checking for a column that does not exist
                        carp("Checking for non-existent data column '$DataColumn'");
                        return -1;
                    }
                    if(not $addr->{$DataColumn}) {
                        my $ipv = length($addr->{ip_addr}) > 10 ? 6 : 4;
                        my $t_ip = ip_bintoip(ip_inttobin($addr->{ip_addr}, $ipv), $ipv);
                        push(@noData, $t_ip);
                    }
                }
                $ret->{$v_name}->{$s->{name}}->{"$ip/$mask"} = \@noData if @noData > 0;
            }
        }
    }

    return $ret;
}

=head2 getNoDNS(%opts)

This is just a wrapper method to getNoData() for easier access.
Actually, getNoDNS() calls getNoData() like this

    return $self->getNoData({data => 'dns_name', %opts});

All options and return values are exactly the same as to getNoData().

=cut
sub getNoDNS {
    my $self = shift;
    my $opts = shift;

    $opts->{'data'} = 'dns_name';
    return $self->getNoData($opts);
}

1;
__END__


=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Diddi Oscarsson, E<lt>diddi@cyberbacon.netE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2013 by Diddi Oscarsson

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.18.1 or,
at your option, any later version of Perl 5 you may have available.


=cut
