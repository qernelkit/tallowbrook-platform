#!/usr/bin/perl
# edi-bridge: moves interchanges between Tallowbrook and its trading partners.
#
#   edi-bridge.pl [--once] [--partner railco|northgate]
#
# Each pass picks up files from the spool, translates them for the partner, sends them and
# archives what was sent. Partner replies land in the outbox for the shipment system.
use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";
use File::Basename qw(basename);
use File::Copy qw(move);
use File::Spec;
use Getopt::Long;
use POSIX qw(strftime);

use Tallowbrook::EDI::ArchiveStore;
use Tallowbrook::EDI::Config qw($SPOOL_DIR $OUTBOX_DIR $ARCHIVE_DIR $POLL_SECONDS partner_profile);
use Tallowbrook::EDI::Digest qw(build_daily_digest);
use Tallowbrook::EDI::KeyExchange;
use Tallowbrook::EDI::PartnerCrypt qw(seal_for_northgate seal_for_railco);
use Tallowbrook::EDI::Receipts qw(build_receipt);
use Tallowbrook::EDI::Segments qw(parse_interchange interchange_header);
use Tallowbrook::EDI::Signer qw(sign_for_railco);
use Tallowbrook::EDI::Transport;

my $once = 0;
my @only;
GetOptions('once' => \$once, 'partner=s' => \@only) or die "usage: $0 [--once] [--partner CODE]\n";

my $transport = Tallowbrook::EDI::Transport->new;
my $archive   = Tallowbrook::EDI::ArchiveStore->new(dir => $ARCHIVE_DIR);
my $kx        = Tallowbrook::EDI::KeyExchange->new;
my %today     = (day => strftime('%Y-%m-%d', gmtime), counts => {}, errors => [], containers => []);
my $northgate_pass;

$SIG{TERM} = sub { warn "edi-bridge: stopping\n"; exit 0 };

while (1) {
    rotate_day();
    for my $code (@only ? @only : qw(railco northgate)) {
        my $dir = File::Spec->catdir($SPOOL_DIR, $code);
        next unless -d $dir;
        opendir my $dh, $dir or do { push @{ $today{errors} }, "cannot read $dir: $!"; next };
        my @files = sort grep { /\.(x12|edi)\z/ } readdir $dh;
        closedir $dh;
        for my $file (@files) {
            my $path = File::Spec->catfile($dir, $file);
            eval { process($code, $path); 1 } or do {
                chomp(my $err = $@);
                push @{ $today{errors} }, "$code/$file: $err";
                move($path, "$path.failed");
            };
        }
    }
    last if $once;
    sleep $POLL_SECONDS;
}

sub process {
    my ($code, $path) = @_;
    my $profile = partner_profile($code);
    my $interchange = slurp($path);
    my $parsed = parse_interchange($interchange);
    my $header = interchange_header($parsed);
    die "interchange is $parsed->{syntax}, $profile->{name} expects $profile->{format}\n"
      unless $parsed->{syntax} eq $profile->{format};

    my ($payload, %headers);
    if ($code eq 'railco') {
        $headers{'X-Interchange-Signature'} = sign_for_railco($interchange) if $profile->{sign};
        $payload = seal_for_railco($interchange, $header);
        push @{ $today{containers} }, $interchange =~ /\b([A-Z]{4}\d{7})\b/g;
    }
    else {
        $payload = seal_for_northgate($interchange, $northgate_pass);
    }

    my $reply = $transport->send_interchange($profile, $payload, %headers);
    $today{counts}{$code}{sent}++;
    $archive->store(basename($path), $interchange);
    unlink $path or warn "could not remove $path: $!\n";

    if (defined $reply && length $reply) {
        my $out = File::Spec->catfile($OUTBOX_DIR, "$code-" . ($header->{control} // time) . '.reply');
        spit($out, $reply);
        $today{counts}{$code}{received}++;
        if ($profile->{mdn}) {
            my $receipt = build_receipt($reply, { %$profile, mdn_secret => $ENV{NORTHGATE_MDN_SECRET} // '' });
            spit("$out.mdn", $receipt->{attachment});
        }
    }
    return 1;
}

sub rotate_day {
    my $day = strftime('%Y-%m-%d', gmtime);
    return if $day eq $today{day};
    my $summary = build_daily_digest(%today);
    spit(File::Spec->catfile($OUTBOX_DIR, "summary-$today{day}.txt"), $summary);
    %today = (day => $day, counts => {}, errors => [], containers => []);
    if ($kx->expired) {
        $kx = Tallowbrook::EDI::KeyExchange->new;
        $northgate_pass = undef;
    }
    my $wrapped_file = File::Spec->catfile($SPOOL_DIR, 'northgate', 'pass.wrapped');
    if (-e $wrapped_file) {
        $northgate_pass = $kx->unwrap_pass(slurp($wrapped_file));
        unlink $wrapped_file;
    }
    return;
}

sub slurp {
    my ($path) = @_;
    open my $fh, '<:raw', $path or die "cannot open $path: $!\n";
    local $/;
    my $data = <$fh>;
    close $fh;
    return $data;
}

sub spit {
    my ($path, $data) = @_;
    open my $fh, '>:raw', $path or die "cannot write $path: $!\n";
    print {$fh} $data;
    close $fh or die "cannot close $path: $!\n";
    return;
}
