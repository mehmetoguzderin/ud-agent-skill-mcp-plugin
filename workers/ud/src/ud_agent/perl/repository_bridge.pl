#!/usr/bin/env perl
use strict;
use warnings;
use utf8;
use JSON::PP;
use Cwd qw(getcwd);
use File::Copy qw(copy);
use File::Path qw(make_path);

my $protocol = \*STDOUT;
sub main {
local $/;
my $raw = <STDIN>;
die "repository request too large\n" if !defined($raw) || length($raw) > 1048576;
my $request = JSON::PP->new->utf8->decode($raw);
die "invalid repository request\n" if ref($request) ne 'HASH';
open STDOUT, '>&', \*STDERR or die "cannot isolate upstream output\n";
require udlib;
my $folder = $request->{repository_name};
die "invalid repository name\n" if !defined($folder) || $folder !~ /^UD_[A-Za-z][A-Za-z0-9_]*(?:-[A-Za-z0-9_]+)?$/;
my $languages = udlib::get_language_hash($request->{languages_path});
my ($language) = udlib::decompose_repo_name($folder);
my @reports;
for my $family (@{$request->{check_families}}) {
    my @errors;
    my $count = 0;
    if (!defined($language) || !exists($languages->{$language})) {
        push @errors, "Unknown repository language in $folder";
        $count++;
    } elsif ($family eq 'repository') {
        my $key = udlib::get_ltcode_from_repo_name($folder, $languages);
        udlib::check_files($request->{layout_root}, $folder, $key, \@errors, \$count);
        my $metadata = udlib::read_readme($folder, $request->{layout_root});
        if (!defined($metadata)) {
            push @errors, "Cannot read repository README";
            $count++;
        } else {
            udlib::check_metadata($request->{layout_root}, $folder, $metadata, \@errors, \$count);
        }
    } elsif ($family eq 'documentation') {
        my $code = $languages->{$language}{lcode};
        die "invalid pinned language code\n" if !defined($code) || $code !~ /^[a-z][a-z0-9_-]*$/;
        my $source = "$request->{docs_path}/_$code/index.md";
        if (-f $source) {
            die "documentation input is too large\n" if -s $source > 1048576;
            my $target = "$request->{layout_root}/docs/_$code";
            make_path($target);
            copy($source, "$target/index.md") or die "cannot stage pinned documentation\n";
        }
        udlib::check_documentation($request->{layout_root}, $folder, $code, \@errors, \$count);
    } else {
        die "invalid repository check family\n";
    }
    push @reports, {family => $family, passed => $count == 0 ? JSON::PP::true : JSON::PP::false,
                    error_count => $count, incidents => \@errors};
}
print {$protocol} JSON::PP->new->utf8->canonical->encode({reports => \@reports});
}

# Keep upstream warnings/logs on stderr as before. Unexpected Perl exceptions
# also receive a structured protocol outcome rather than a bare interpreter
# crash; callers distinguish failed execution from linguistic incidents.
my $completed = eval {
    binmode(STDIN, ':raw') or die "cannot read raw protocol input\n";
    binmode(STDOUT, ':raw') or die "cannot write raw protocol output\n";
    binmode(STDERR, ':raw') or die "cannot write raw diagnostic output\n";
    open my $preserved, '>&', \*STDOUT or die "cannot preserve protocol output\n";
    $protocol = $preserved;
    main();
    1;
};
if (!$completed) {
    my $message = substr("$@", 0, 4096);
    print STDERR $message;
    print {$protocol} JSON::PP->new->utf8->canonical->encode({error => 'repository_execution_failed'});
    exit 1;
}
