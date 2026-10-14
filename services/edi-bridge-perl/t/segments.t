use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Tallowbrook::EDI::Segments qw(parse_interchange detect_syntax interchange_header);

my $isa = 'ISA*00*          *00*          *ZZ*TALLOWBRK      *ZZ*RAILCOFRT      *260301*0930*U*00401*000000417*0*P*>~';
my $x12 = $isa . 'GS*SM*TALLOWBRK*RAILCOFRT*20260301*0930*417*X*004010~ST*404*0001~SE*2*0001~GE*1*417~IEA*1*000000417~';

is(detect_syntax($x12), 'X12', 'X12 detected');
is(detect_syntax("UNB+UNOC:3+TALLOWBROOK+NORTHGATE3PL'"), 'EDIFACT', 'EDIFACT detected');
is(detect_syntax('hello'), undef, 'anything else is not an interchange');

my $parsed = parse_interchange($x12);
is(scalar @{ $parsed->{segments} }, 6, 'six segments');
is($parsed->{segments}[2]{tag}, 'ST', 'third segment is ST');

my $header = interchange_header($parsed);
is($header->{sender},   'TALLOWBRK', 'sender trimmed');
is($header->{receiver}, 'RAILCOFRT', 'receiver trimmed');
is($header->{description}, 'Rail carrier shipment information', '404 described');

my $edifact = "UNA:+.? 'UNB+UNOC:3+TALLOWBROOK+NORTHGATE3PL+260301:0930+88'UNH+1+IFTSTA:D:01B:UN'FTX+AAA+++Dock 4?'s door'UNT+3+1'UNZ+1+88'";
my $e = parse_interchange($edifact);
is($e->{segments}[2]{elements}[3][0], "Dock 4's door", 'release character honoured');
is(interchange_header($e)->{description}, 'Status report', 'IFTSTA described');

done_testing;
