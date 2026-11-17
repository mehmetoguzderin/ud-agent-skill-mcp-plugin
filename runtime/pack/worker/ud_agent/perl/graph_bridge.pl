#!/usr/bin/env perl
# MIT licensed owned bridge. The separately supplied UD Graph and Node modules
# retain their upstream licenses. This bridge is deliberately not an editor.
use strict;
use warnings;
use JSON::PP ();

my $json = JSON::PP->new->utf8->canonical->allow_nonref(0);
sub fail {
    my ($message) = @_;
    print STDOUT $json->encode({ ok => JSON::PP::false, error => $message });
    exit 1;
}

sub main {
my ($supplied) = @_;
my $input = '';
if (defined $supplied) {
    $input = $supplied;
} else {
my $read_attempts = 262145;
while (length($input) <= 262144 && $read_attempts-- > 0) {
    my ($read, $chunk);
    { no warnings 'io'; $read = read(STDIN, $chunk, 8192); }
    fail('input_read_failed') unless defined $read;
    last if $read == 0;
    $input .= $chunk;
}
fail('input_too_large') if length($input) > 262144;
fail('input_read_failed') if $read_attempts < 0;
}
my $request = eval { $json->decode($input) };
fail('invalid_json') if $@ || ref($request) ne 'HASH';
fail('unsupported_request') unless keys(%$request) == 3
    && exists($request->{operation}) && exists($request->{nodes}) && exists($request->{edges})
    && !ref($request->{operation}) && defined($request->{operation})
    && $request->{operation} eq 'inspect_enhanced';
fail('invalid_nodes') unless ref($request->{nodes}) eq 'ARRAY'
    && @{$request->{nodes}} <= 256;
fail('invalid_edges') unless ref($request->{edges}) eq 'ARRAY'
    && @{$request->{edges}} <= 1024;

my %nodes = ('0' => 1);
for my $id (@{$request->{nodes}}) {
    fail('invalid_node') if !defined($id) || ref($id) || $id !~ /\A[1-9][0-9]{0,5}\z/ || $nodes{$id}++;
}
my %seen;
for my $edge (@{$request->{edges}}) {
    fail('invalid_edge') unless ref($edge) eq 'HASH' && keys(%$edge) == 3
        && exists($edge->{head}) && exists($edge->{dependent}) && exists($edge->{relation});
    my ($head, $dependent, $relation) = @{$edge}{qw(head dependent relation)};
    fail('invalid_edge') if !defined($head) || ref($head) || !defined($dependent) || ref($dependent)
        || !defined($relation) || ref($relation) || !exists($nodes{$head}) || !exists($nodes{$dependent})
        || $dependent eq '0' || $head eq $dependent
        || $relation !~ /\A[a-z][a-z0-9_-]{0,31}(?::[a-z0-9_-]{1,32})?\z/;
    fail('duplicate_edge') if $seen{join("\0", $head, $dependent, $relation)}++;
}

# These imports must resolve only to the verified, immutable image context.
# The caller is responsible for a fixed interpreter, trusted library path,
# process timeout, resource limits, and the worker's network isolation.
eval { require Graph; require Node; 1 } or fail('graph_prerequisites_unavailable');
my $result = eval {
    my $graph = Graph->new();
    for my $id (@{$request->{nodes}}) {
        $graph->add_node(Node->new(id => "$id"));
    }
    for my $edge (@{$request->{edges}}) {
        $graph->add_edge("$edge->{head}", "$edge->{dependent}", $edge->{relation});
    }
    my @result_nodes;
    for my $id (sort { $a <=> $b } keys %nodes) {
        my $node = $graph->get_node($id);
        my @incoming = map { { head => "$_->{id}", relation => $_->{deprel} } }
            sort { $a->{id} <=> $b->{id} || $a->{deprel} cmp $b->{deprel} } @{$node->iedges()};
        push @result_nodes, { id => "$id", in_degree => $node->get_in_degree(),
            out_degree => $node->get_out_degree(), incoming => \@incoming };
        # Upstream Node retains its Graph. Break that ownership cycle after
        # copying incidence so a long stream does not retain every partition.
        $node->set_graph(undef);
    }
    { ok => JSON::PP::true, nodes => \@result_nodes };
};
fail('graph_execution_failed') if $@ || !defined($result);
print STDOUT $json->encode($result);
}

sub stream {
    # Trusted worker-only framing; it changes neither the public application
    # catalog nor the bounded single-request protocol used by other callers.
    my ($pending, $total, $frames) = ('', 0, 0);
    my $empty_reads = 0;
    while (1) {
        my ($count, $chunk);
        { no warnings 'io'; $count = read(STDIN, $chunk, 8192); }
        fail('input_read_failed') unless defined $count;
        fail('input_read_failed') if $count == 0 && ++$empty_reads > 1;
        last if $count == 0;
        $total += $count;
        fail('input_too_large') if $total > 134217728;
        $pending .= $chunk;
        while ((my $end = index($pending, "\n")) >= 0) {
            fail('input_too_large') if $end > 262144 || ++$frames > 1000000;
            my $frame = substr($pending, 0, $end, '');
            substr($pending, 0, 1, '');
            main($frame);
            print STDOUT "\n";
        }
        fail('input_too_large') if length($pending) > 262144;
    }
    fail('invalid_stream') if length($pending) || !$frames;
}

# Every unexpected bridge or module failure still has a bounded JSON outcome.
# Explicit fail(...) responses retain their existing codes and exit behavior.
my $completed = eval {
    # JSON framing and byte budgets are identical on Windows and POSIX.
    binmode(STDOUT, ':raw') or die "cannot write raw protocol output\n";
    my $raw_input;
    { no warnings 'io'; $raw_input = binmode(STDIN, ':raw'); }
    fail('input_read_failed') unless $raw_input;
    local $SIG{__WARN__} = sub { die "bridge execution warning\n"; };
    if (@ARGV == 1 && $ARGV[0] eq '--stream') { stream(); }
    else { main(); }
    1;
};
fail('graph_execution_failed') unless $completed;
