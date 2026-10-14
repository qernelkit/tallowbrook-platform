package Tallowbrook::EDI::Signer;

use strict;
use warnings;
use Crypt::PK::DSA;
use Digest::SHA qw(sha1);
use MIME::Base64 qw(encode_base64);
use Exporter 'import';

our @EXPORT_OK = qw(sign_for_railco canonical_form);

# Railco checks the signature on every interchange we send against the public half of this key,
# which was registered with them when the bridge went live.
our $SIGNING_KEY_PEM = <<'PEM';
-----BEGIN PRIVATE KEY-----
MIICXQIBADCCAjUGByqGSM44BAEwggIoAoIBAQCQtwPC3+bMgT5RShaJwUZ1n+d+UN/EHCVQ6H/r
8ejk1pcqFC56zk9J2bG4B7x4PPatTm+5bIarmaGjkxFtQB4hrQPsFZj/BcCD5W4bH5wrV9tkVAfu
ywzTbsMesPCBShX4ULf1qkevmj0hdXJDVWWc7bo/DI1E2U1Dl+VCK42AbQpphID2a26E0k2rsph0
Dg57mMSQeGAsfb7N+5tainw3fswuctsVpwX03mJld1vVVGEmx8VHzkktFkx3ikYeyy2vXprg4A6T
0694XOhhxmuntfNKvGyyaR5tIIEWyKyJSjaofQLlPKRZZPS23QqJMe3m1lw8a8pIG9a/wC8Yu01p
Ah0AxDdVFkEMtXEjfVBfhqLGusPA4r26hH40oK9u0wKCAQBmAibjckU1WwJmULmtwb80U13iYCxU
PDiCPfBFLtftj7VisbQnbhoAbEgF3dsmseSyxLzjaxKfAfVOujG1UqGOA5Sdz7MweiV/Stjt2Doz
rqPCVTUI5A1w1WQqHrj8cQEl4R5zO/sri8jcrzgPCl2rvzM1Oh4eosEWPiXl7sjGVgO5z0+z5Pjq
tGrF46DPC0rnQ19oWLiO4d4427bzrF9VclEhX/IPzaL5UKLpSHES92w8osdpj95LlObwNCMBV2hx
komxMfeUjpRLYjexdWW6bQ6qNS9X/lpTIxVHrDitvB6FrXzdIwsGrO+kQJ2WzeOWn+pNyXP7UDD/
Vd6SkwKxBB8CHQDAkC/Apbopx050dHKpKOlx7FRLhVweXlJMvl1F
-----END PRIVATE KEY-----
PEM

my $dsa;

sub sign_for_railco {
    my ($interchange) = @_;
    my $canonical = canonical_form($interchange);
    $dsa //= Crypt::PK::DSA->new(\$SIGNING_KEY_PEM);
    my $hash = sha1($canonical);
    my $sig = $dsa->sign_hash($hash);
    return encode_base64($sig, '');
}

# Railco signs over the interchange with segment terminators normalised to "~" and no line breaks,
# because their mailbox rewraps long lines.
sub canonical_form {
    my ($interchange) = @_;
    my $text = $interchange;
    $text =~ s/\r?\n//g;
    $text =~ s/~\s+/~/g;
    $text =~ s/\s+\z//;
    return $text;
}

1;
