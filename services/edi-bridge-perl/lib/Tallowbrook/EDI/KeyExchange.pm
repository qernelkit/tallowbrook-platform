package Tallowbrook::EDI::KeyExchange;

use strict;
use warnings;
use Crypt::OpenSSL::RSA;

# The bridge makes a fresh key pair each day and registers the public half with Northgate over
# their key endpoint. Northgate rotates the pass phrase for its files daily and sends the new one
# wrapped under that key.
sub new {
    my ($class) = @_;
    my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);
    my $created = time;
    $rsa->use_pkcs1_oaep_padding();
    return bless { rsa => $rsa, created => $created }, $class;
}

sub public_pem {
    my ($self) = @_;
    return $self->{rsa}->get_public_key_x509_string();
}

sub unwrap_pass {
    my ($self, $wrapped) = @_;
    return $self->{rsa}->decrypt($wrapped);
}

sub expired {
    my ($self, $now) = @_;
    return ($now // time) - $self->{created} > 24 * 60 * 60;
}

1;
