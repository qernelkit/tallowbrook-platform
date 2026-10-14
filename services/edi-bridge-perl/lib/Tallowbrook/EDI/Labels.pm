package Tallowbrook::EDI::Labels;

use strict;
use warnings;
use utf8;
use Exporter 'import';

our @EXPORT_OK = qw(label);

# Text for the cover sheet printed with each manifest, per partner language.
my %LABELS = (
    en => {
        manifest_title => 'Parcel manifest',
        shipper        => 'Shipper',
        consignee      => 'Consignee',
        pieces         => 'Pieces',
        weight         => 'Gross weight (kg)',
    },
    fr => {
        manifest_title => 'Liste des colis',
        shipper        => 'Expéditeur',
        consignee      => 'Destinataire',
        pieces         => 'Nombre de colis',
        weight         => 'Poids brut (kg)',
    },
    de => {
        manifest_title => 'Ladeliste',
        shipper        => 'Versender',
        consignee      => 'Empfänger',
        pieces         => 'Packstücke',
        weight         => 'Bruttogewicht (kg)',
    },
);

sub label {
    my ($lang, $key) = @_;
    my $table = $LABELS{$lang} // $LABELS{en};
    return $table->{$key} // $LABELS{en}{$key} // $key;
}

1;
