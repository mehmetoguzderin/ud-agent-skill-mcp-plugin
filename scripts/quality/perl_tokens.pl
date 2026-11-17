#!/usr/bin/env perl
# MIT licensed mutation-tooling adapter. PPI retains its own Perl license.
use strict;
use warnings;
use Config;
use JSON::PP;
use Digest::SHA qw(sha256_hex);

sub fail {
    my ($code, $message) = @_;
    print STDERR $message;
    print JSON::PP->new->canonical->utf8->encode({ok => JSON::PP::false, error => $code});
    exit 1;
}

sub main {
    my $library = $ENV{UD_PERL_PARSER_LIB};
    fail('parser_prerequisite_missing', "a verified private Perl parser library is required\n") unless defined($library) && $library =~ m{^/|^[A-Za-z]:[\\/]};
    @INC = ($library, "$library/$Config{archname}", $Config{archlibexp}, $Config{privlibexp});
    require PPI;

die "one source path is required\n" unless @ARGV == 1;
open my $source, '<:raw', $ARGV[0] or die "cannot open Perl mutation source\n";
local $/;
my $bytes = <$source>;
close $source;
die "Perl mutation source exceeds its bound\n" unless defined($bytes) && length($bytes) <= 1048576;
my $document = PPI::Document->new(\$bytes) or die "Perl mutation source could not be parsed\n";
die "Perl parser changed source bytes\n" unless $document->serialize() eq $bytes;
my @tokens;
my $offset = 0;
for my $token ($document->tokens()) {
    my $content = $token->content();
    my $location = $token->location();
    push @tokens, { class => ref($token), content => $content, start => $offset,
                    end => $offset + length($content), line => $location->[0], column => $location->[1] };
    $offset += length($content);
}
die "Perl token inventory does not cover the complete source\n" unless $offset == length($bytes);
print JSON::PP->new->canonical->utf8->encode({ schema_version => 1, parser => "PPI", parser_version => $PPI::VERSION,
    source_sha256 => sha256_hex($bytes), tokens => \@tokens });
}

my $completed = eval { local $SIG{__WARN__} = sub { die "parser execution warning\n"; }; main(); 1; };
if (!$completed) {
    my $detail = substr("$@", 0, 4096);
    fail('parser_execution_failed', "Perl parser execution did not complete\n" . $detail);
}
