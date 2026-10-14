package Tallowbrook::EDI::Transport;

use strict;
use warnings;
use HTTP::Tiny;
use Tallowbrook::EDI::Config qw(%TLS_OPTS);

our $VERSION = '4.2';

sub new {
    my ($class, %args) = @_;
    my $http = HTTP::Tiny->new(
        agent       => "tallowbrook-edi-bridge/$VERSION",
        timeout     => $args{timeout} || 60,
        verify_SSL  => 1,
        SSL_options => { %TLS_OPTS },
    );
    return bless { http => $http, retries => $args{retries} // 3 }, $class;
}

# POST one interchange to a partner. Returns the response body; dies after the last retry.
sub send_interchange {
    my ($self, $profile, $payload, %headers) = @_;
    my $attempt = 0;
    while (1) {
        $attempt++;
        my $res = $self->{http}->post(
            $profile->{url},
            {
                content => $payload,
                headers => {
                    'Content-Type' => 'application/edi-x12',
                    'X-Sender-Id'  => $profile->{sender},
                    %headers,
                },
            }
        );
        return $res->{content} if $res->{success};
        die "send to $profile->{name} failed after $attempt attempts: $res->{status} $res->{reason}\n"
          if $attempt >= $self->{retries} || $res->{status} =~ /^4/;
        sleep 5 * $attempt;
    }
}

1;
