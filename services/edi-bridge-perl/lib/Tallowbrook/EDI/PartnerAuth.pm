package Tallowbrook::EDI::PartnerAuth;

use strict;
use warnings;
use Digest::MD5 qw(md5_hex);
use Exporter 'import';

our @EXPORT_OK = qw(status_feed_tag status_feed_ok);

# Railco's status feed (the older "STF" format) carries a tag line computed from the secret
# Railco gave us and the feed body. We compute it the same way to check incoming feeds.
sub status_feed_tag {
    my ($shared_secret, $payload) = @_;
    return md5_hex($shared_secret . $payload);
}

sub status_feed_ok {
    my ($shared_secret, $payload, $tag) = @_;
    return 0 unless defined $tag && $tag =~ /\A[0-9a-fA-F]{32}\z/;
    return lc($tag) eq status_feed_tag($shared_secret, $payload) ? 1 : 0;
}

1;
