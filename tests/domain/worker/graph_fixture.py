"""Explicit fake Graph/Node closure for domain unit tests, never native evidence."""
from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import tempfile
from unittest.mock import patch

FAKE = r'''package Node;
sub new { my ($class,%args)=@_; bless {id=>$args{id},iedges=>[],oedges=>[]},$class }
sub iedges { $_[0]->{iedges} }
sub get_in_degree { scalar @{$_[0]->{iedges}} }
sub get_out_degree { scalar @{$_[0]->{oedges}} }
sub set_graph { $_[0]->{graph} = $_[1] }
package Graph;
sub new { bless {nodes=>{0=>Node->new(id=>0)}},$_[0] }
sub add_node { $_[0]->{nodes}{$_[1]->{id}}=$_[1] }
sub get_node { $_[0]->{nodes}{$_[1]} }
sub add_edge { my($s,$h,$d,$r)=@_;push @{$s->{nodes}{$h}{oedges}},{id=>$d,deprel=>$r};push @{$s->{nodes}{$d}{iedges}},{id=>$h,deprel=>$r}; }
1;
'''

@contextmanager
def graph_fixture():
    with tempfile.TemporaryDirectory(prefix='ud-fake-graph-') as temporary:
        root=Path(temporary)
        (root/'Graph.pm').write_text(FAKE)
        (root/'Node.pm').write_text('1;\n')
        environment={key:value for key,value in os.environ.items() if not key.startswith('UD_AGENT_PERL_')}
        environment.update(UD_AGENT_PERL=shutil.which('perl') or '/usr/bin/perl',UD_AGENT_UDTOOLS=str(root))
        with patch.dict(os.environ,environment,clear=True): yield root
