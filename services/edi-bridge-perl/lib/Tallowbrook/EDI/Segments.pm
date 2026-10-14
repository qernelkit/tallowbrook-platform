package Tallowbrook::EDI::Segments;

use strict;
use warnings;
use Exporter 'import';

our @EXPORT_OK = qw(parse_interchange detect_syntax interchange_header to_x12);

# X12: ISA*..~GS*..~ST*..~ ... ~SE*..~GE*..~IEA*..~ (element separator is ISA position 4)
# EDIFACT: UNA:+.? 'UNB+..'UNH+..' ... 'UNT+..'UNZ+..'
sub detect_syntax {
    my ($text) = @_;
    return 'X12'     if $text =~ /\A\s*ISA/;
    return 'EDIFACT' if $text =~ /\A\s*(UNA|UNB)/;
    return;
}

sub parse_interchange {
    my ($text) = @_;
    my $syntax = detect_syntax($text) or die "not an X12 or EDIFACT interchange\n";
    return $syntax eq 'X12' ? _parse_x12($text) : _parse_edifact($text);
}

sub _parse_x12 {
    my ($text) = @_;
    $text =~ s/\A\s+//;
    my $element   = substr($text, 3, 1);
    my $segment   = substr($text, 105, 1);
    my @segments;
    for my $raw (split /\Q$segment\E/, $text) {
        $raw =~ s/\A[\r\n]+//;
        next unless length $raw;
        my @elements = split /\Q$element\E/, $raw, -1;
        push @segments, { tag => shift @elements, elements => \@elements };
    }
    return { syntax => 'X12', segments => \@segments, element => $element, terminator => $segment };
}

sub _parse_edifact {
    my ($text) = @_;
    $text =~ s/\A\s+//;
    my ($component, $element, $release, $segment) = (':', '+', '?', "'");
    if ($text =~ s/\AUNA(.)(.)(.)(.)(.)(.)//s) {
        ($component, $element, $release, $segment) = ($1, $2, $4, $6);
    }
    my @segments;
    for my $raw (_split_released($text, $segment, $release)) {
        $raw =~ s/\A[\r\n]+//;
        next unless length $raw;
        my @elements = _split_released($raw, $element, $release);
        push @segments, {
            tag      => shift @elements,
            elements => [ map { [ _split_released($_, $component, $release) ] } @elements ],
        };
    }
    return { syntax => 'EDIFACT', segments => \@segments, element => $element, terminator => $segment };
}

sub _split_released {
    my ($text, $sep, $release) = @_;
    my @parts;
    my $current = '';
    my $escaped = 0;
    for my $ch (split //, $text) {
        if ($escaped) { $current .= $ch; $escaped = 0; next }
        if ($ch eq $release) { $escaped = 1; next }
        if ($ch eq $sep) { push @parts, $current; $current = ''; next }
        $current .= $ch;
    }
    push @parts, $current if length $current;
    return @parts;
}

# Sender, receiver, control number and a short description of the first transaction set.
sub interchange_header {
    my ($parsed) = @_;
    my %h;
    for my $seg (@{ $parsed->{segments} }) {
        if ($seg->{tag} eq 'ISA') {
            @h{qw(sender receiver control)} = map { _trim($_) } @{ $seg->{elements} }[ 5, 7, 12 ];
        }
        elsif ($seg->{tag} eq 'UNB') {
            $h{sender}   = $seg->{elements}[1][0];
            $h{receiver} = $seg->{elements}[2][0];
            $h{control}  = $seg->{elements}[4][0];
        }
        elsif ($seg->{tag} eq 'ST' || $seg->{tag} eq 'UNH') {
            my $type = ref $seg->{elements}[0] ? $seg->{elements}[1][0] : $seg->{elements}[0];
            $h{description} //= _describe($type);
        }
    }
    return \%h;
}

sub to_x12 {
    my ($parsed) = @_;
    my ($el, $term) = @{$parsed}{qw(element terminator)};
    return join '', map { join($el, $_->{tag}, @{ $_->{elements} }) . $term } @{ $parsed->{segments} };
}

my %TRANSACTION = (
    204    => 'Motor carrier load tender',
    214    => 'Shipment status message',
    404    => 'Rail carrier shipment information',
    856    => 'Ship notice / manifest',
    990    => 'Response to a load tender',
    IFTMIN => 'Instruction message',
    IFTSTA => 'Status report',
    DESADV => 'Despatch advice',
);

sub _describe {
    my ($type) = @_;
    return defined $type ? ($TRANSACTION{$type} // "transaction set $type") : 'unknown';
}

sub _trim {
    my ($s) = @_;
    $s //= '';
    $s =~ s/\A\s+|\s+\z//g;
    return $s;
}

1;
