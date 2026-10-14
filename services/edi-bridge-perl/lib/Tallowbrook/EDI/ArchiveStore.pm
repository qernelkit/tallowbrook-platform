package Tallowbrook::EDI::ArchiveStore;

use strict;
use warnings;
use Crypt::CBC;
use File::Path qw(make_path);
use File::Spec;
use POSIX qw(strftime);

# Processed interchanges are kept for seven years (customs). The restore tool opens them with the
# same archive pass phrase.
sub new {
    my ($class, %args) = @_;
    my $pass = $args{pass} // $ENV{EDI_ARCHIVE_PASS}
      or die "EDI_ARCHIVE_PASS is not set\n";
    my $dir = $args{dir} or die "archive dir required\n";
    return bless { dir => $dir, pass => $pass }, $class;
}

sub store {
    my ($self, $name, $interchange, $when) = @_;
    $when //= time;
    my $month_dir = File::Spec->catdir($self->{dir}, strftime('%Y', gmtime $when), strftime('%m', gmtime $when));
    make_path($month_dir) unless -d $month_dir;

    my $cbc = Crypt::CBC->new(-pass => $self->{pass});
    my $path = File::Spec->catfile($month_dir, "$name.arc");
    open my $fh, '>:raw', $path or die "cannot write $path: $!\n";
    print {$fh} $cbc->encrypt($interchange);
    close $fh or die "cannot close $path: $!\n";
    return $path;
}

sub path_for {
    my ($self, $name, $when) = @_;
    return File::Spec->catfile($self->{dir}, strftime('%Y/%m', gmtime $when), "$name.arc");
}

1;
