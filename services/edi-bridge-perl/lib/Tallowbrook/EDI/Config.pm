package Tallowbrook::EDI::Config;

use strict;
use warnings;
use Exporter 'import';

our @EXPORT_OK = qw(%TLS_OPTS %PARTNER_PROFILES $SPOOL_DIR $OUTBOX_DIR $ARCHIVE_DIR $POLL_SECONDS partner_profile);

our $SPOOL_DIR    = $ENV{EDI_SPOOL_DIR}   || '/var/spool/edi-bridge/in';
our $OUTBOX_DIR   = $ENV{EDI_OUTBOX_DIR}  || '/var/spool/edi-bridge/out';
our $ARCHIVE_DIR  = $ENV{EDI_ARCHIVE_DIR} || '/srv/edi-archive';
our $POLL_SECONDS = $ENV{EDI_POLL_SECONDS} || 60;

# Options for every HTTPS connection the bridge makes (see Transport.pm).
our %TLS_OPTS = (
    SSL_version     => 'SSLv23:!SSLv2:!SSLv3:!TLSv1:!TLSv1_1',
    SSL_cipher_list => 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256',
    SSL_verify_mode => 1,
    SSL_ca_file     => '/etc/ssl/certs/ca-certificates.crt',
);

# One entry per trading partner. 'format' is the interchange syntax they send and expect.
our %PARTNER_PROFILES = (
    railco => {
        name     => 'Railco Freight',
        url      => 'https://edi.railco.example/as2/inbound',
        format   => 'X12',
        sender   => 'TALLOWBRK',
        receiver => 'RAILCOFRT',
        cipher   => 'Crypt::Cipher::DES_EDE',
        key_file => '/etc/edi-bridge/railco.key',
        sign     => 1,
    },
    northgate => {
        name     => 'Northgate 3PL',
        url      => 'https://edi.northgate-3pl.example/inbound',
        format   => 'EDIFACT',
        sender   => 'TALLOWBROOK',
        receiver => 'NORTHGATE3PL',
        pass_env => 'NORTHGATE_EDI_PASS',
        sign     => 0,
        mdn      => 1,
    },
);

sub partner_profile {
    my ($code) = @_;
    my $profile = $PARTNER_PROFILES{$code}
      or die "unknown trading partner '$code'\n";
    return $profile;
}

1;
