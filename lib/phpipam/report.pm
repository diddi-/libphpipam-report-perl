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

    return $self;
}

sub DESTROY {
    my $self = shift;

    $self->_sqldisconnect();
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

=head2 getFree($section, $subnet)

Get the number of free IP addresses in $subnet.
phpipam::report consider all unallocated addresses to be free, this means that
* Active
* Reserved
* Offline
* DHCP
are all considered to be allocated addresses and are not counted.

    $reporter->getFree("servers", "10.0.0.0/8");
=cut

sub getFree {
    my $self = shift;

    return undef;
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
