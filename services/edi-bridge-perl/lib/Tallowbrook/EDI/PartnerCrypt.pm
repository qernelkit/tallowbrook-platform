package Tallowbrook::EDI::PartnerCrypt;

use strict;
use warnings;
use Crypt::CBC;
use Exporter 'import';
use Tallowbrook::EDI::Config qw(%PARTNER_PROFILES);

our @EXPORT_OK = qw(seal_for_northgate seal_for_railco);

# Northgate opens our files with the day's pass phrase (see KeyExchange); the one in the
# environment is the fallback agreed with them for days their key endpoint is down.
sub seal_for_northgate {
    my ($interchange, $pass) = @_;
    my $profile = $PARTNER_PROFILES{northgate};
    $pass //= $ENV{ $profile->{pass_env} }
      or die "$profile->{pass_env} is not set\n";

    my $cbc = Crypt::CBC->new(
        -cipher => 'Cipher::AES',
        -pass   => $pass,
        -pbkdf  => 'pbkdf2',
        -iter   => 120_000,
    );
    return $cbc->encrypt($interchange);
}

# Railco's gateway takes a raw key from their key file and the IV railco requires; no header.
sub seal_for_railco {
    my ($interchange, $segment) = @_;
    my $profile = $PARTNER_PROFILES{railco};
    my $des = $segment->{description} // 'unknown';
    my $iv = pack('H*', '8e02c2eb5967632a');

    my $cbc = Crypt::CBC->new(
        -cipher      => $profile->{cipher},
        -key         => _read_key($profile->{key_file}),
        -iv          => $iv,
        -pbkdf       => 'none',
        -header      => 'none',
        -literal_key => 1,
    );
    warn "railco: sealing interchange for '$des'\n" if $ENV{EDI_DEBUG};
    return $cbc->encrypt($interchange);
}

sub _read_key {
    my ($path) = @_;
    open my $fh, '<:raw', $path or die "cannot open $path: $!\n";
    local $/;
    my $key = <$fh>;
    close $fh;
    die "$path does not hold a 24-byte key\n" unless defined $key && length $key == 24;
    return $key;
}

1;
