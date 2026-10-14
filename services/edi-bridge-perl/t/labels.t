use strict;
use warnings;
use utf8;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib";
use Tallowbrook::EDI::Labels qw(label);

is(label('en', 'shipper'), 'Shipper', 'English');
is(label('de', 'consignee'), 'Empfänger', 'German');
is(label('it', 'pieces'), 'Pieces', 'unknown language falls back to English');
is(label('fr', 'no_such_key'), 'no_such_key', 'unknown key is returned as is');

done_testing;
