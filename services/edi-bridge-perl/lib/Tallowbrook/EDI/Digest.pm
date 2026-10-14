package Tallowbrook::EDI::Digest;

use strict;
use warnings;
use POSIX qw(strftime);
use Exporter 'import';

our @EXPORT_OK = qw(build_daily_digest container_check_digit);

my %LETTER_VALUE;
{
    my $v = 10;
    for my $letter ('A' .. 'Z') {
        $v++ if $v % 11 == 0;
        $LETTER_VALUE{$letter} = $v++;
    }
}

# End-of-day summary for the operations mailbox: interchanges per partner, failures, and the
# containers mentioned in the day's rail bookings.
sub build_daily_digest {
    my (%args) = @_;
    my $day     = $args{day} // strftime('%Y-%m-%d', gmtime);
    my $counts  = $args{counts} // {};
    my $errors  = $args{errors} // [];
    my @containers = @{ $args{containers} // [] };

    my @lines = ("EDI bridge summary for $day", '');
    for my $partner (sort keys %$counts) {
        push @lines, sprintf('  %-12s %5d sent  %5d received', $partner, $counts->{$partner}{sent} // 0,
            $counts->{$partner}{received} // 0);
    }
    push @lines, '', scalar(@$errors) . ' failure(s)';
    push @lines, map {"  - $_"} @$errors;

    if (@containers) {
        push @lines, '', 'Containers booked:';
        for my $c (@containers) {
            my $ok = container_check_digit(substr($c, 0, 10)) == substr($c, 10, 1);
            push @lines, sprintf('  %s%s', $c, $ok ? '' : '  (check digit mismatch)');
        }
    }
    return join("\n", @lines) . "\n";
}

# ISO 6346 check digit over the owner code, category and serial (the first ten characters).
sub container_check_digit {
    my ($id) = @_;
    die "container id must be 10 characters\n" unless length $id == 10;
    my $sum = 0;
    my @chars = split //, uc $id;
    for my $i (0 .. 9) {
        my $ch = $chars[$i];
        my $value = $ch =~ /\d/ ? $ch : $LETTER_VALUE{$ch} // die "bad character '$ch' in $id\n";
        $sum += $value * 2**$i;
    }
    return ($sum % 11) % 10;
}

1;
