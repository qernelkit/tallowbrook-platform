use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Tallowbrook::EDI::Digest qw(build_daily_digest container_check_digit);

is(container_check_digit('CSQU305438'), 3, 'ISO 6346 example container');
is(container_check_digit('MSKU907032'), 3, 'second container');
eval { container_check_digit('ABC') };
like($@, qr/10 characters/, 'short ids rejected');

my $text = build_daily_digest(
    day        => '2026-03-01',
    counts     => { railco => { sent => 12, received => 11 }, northgate => { sent => 4 } },
    errors     => ['northgate/0003.edi: timeout'],
    containers => ['CSQU3054383', 'CSQU3054384'],
);
like($text, qr/summary for 2026-03-01/, 'header');
like($text, qr/railco\s+12 sent\s+11 received/, 'railco counts');
like($text, qr/1 failure/, 'failure count');
like($text, qr/CSQU3054384  \(check digit mismatch\)/, 'bad container flagged');
unlike($text, qr/CSQU3054383  \(/, 'good container not flagged');

done_testing;
