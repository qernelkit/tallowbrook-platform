package Tallowbrook::EDI::Receipts;

use strict;
use warnings;
use Digest::SHA qw(sha256_hex hmac_sha256_hex);
use MIME::Base64 qw(encode_base64);
use POSIX qw(strftime);
use Exporter 'import';

our @EXPORT_OK = qw(build_receipt);

# Receipts (MDNs) we return for each interchange a partner sends us. The partner matches the
# document hash against what it sent and checks the MIC with the secret agreed at onboarding.
sub build_receipt {
    my ($interchange, $partner, %opt) = @_;
    my $now = $opt{now} // time;
    my $doc_hash = sha256_hex($interchange);
    my $receipt_body = join "\r\n",
      'Reporting-UA: tallowbrook-edi-bridge',
      "Original-Recipient: $partner->{receiver}",
      'Disposition: automatic-action/MDN-sent-automatically; processed',
      "Received-Document-Hash: $doc_hash",
      'Received-At: ' . strftime('%Y-%m-%dT%H:%M:%SZ', gmtime $now),
      '';
    my $mic = hmac_sha256_hex($receipt_body, $partner->{mdn_secret});
    my $attachment = encode_base64($receipt_body);

    return {
        partner    => $partner->{name},
        mic        => $mic,
        attachment => $attachment,
        document   => $doc_hash,
    };
}

1;
