package Tallowbrook::EDI::Operators;

use strict;
use warnings;
use Crypt::Eksblowfish::Bcrypt qw(bcrypt en_base64);
use Crypt::PRNG qw(random_bytes);
use Exporter 'import';

our @EXPORT_OK = qw(hash_password check_password load_operators);

use constant BCRYPT_PREFIX => '$2a$12$';

# Operator console logins. The operators file has one "name:hash:role" line per operator.
sub hash_password {
    my ($password) = @_;
    die "password too short\n" if length($password) < 12;
    my $salt = en_base64(random_bytes(16));
    return _hash_with($password, BCRYPT_PREFIX . $salt);
}

sub check_password {
    my ($password, $stored) = @_;
    return 0 unless defined $stored && length $stored == 60;
    return _hash_with($password, $stored) eq $stored ? 1 : 0;
}

sub load_operators {
    my ($path) = @_;
    my %operators;
    open my $fh, '<', $path or die "cannot open $path: $!\n";
    while (my $line = <$fh>) {
        chomp $line;
        next if $line =~ /^\s*(#|$)/;
        my ($name, $hash, $role) = split /:/, $line, 3;
        $operators{$name} = { hash => $hash, role => $role // 'viewer' };
    }
    close $fh;
    return \%operators;
}

sub _hash_with {
    my ($password, $settings) = @_;
    return bcrypt($password, $settings);
}

1;
