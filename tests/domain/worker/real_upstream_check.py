"""Opt-in real-upstream check; fails when dependencies or rule data are missing.

Run with UD_TEST_RULES_PATH pointing to the audited tools/data directory.
"""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from ud_agent.domain.validation import sentence_validation_report, validation_report
from ud_agent.domain.evaluation import predictions_evaluate
from ud_agent.errors import InvalidInput

sample = '# sent_id = duplicate\n# text = Hi\n1\tHi\thi\tINTJ\t_\t_\t0\troot\t_\t_\n\n'
rule_path = os.environ['UD_TEST_RULES_PATH']
with TemporaryDirectory(prefix='ud-agent-upstream-') as root:
    for name in ('a.conllu', 'b.conllu'):
        (Path(root) / name).write_text(sample, encoding='utf-8')
    request = {'working_tree_path': root, 'file_paths': ['a.conllu', 'b.conllu'],
               'ud_context_path': rule_path, 'options': {'language_code': 'en', 'level': 2}}
    result = validation_report(request)
    assert result['passed'] is False
    assert any(item.get('testid') == 'non-unique-sent-id' for item in result['incidents'])
    sentence = sentence_validation_report({**request, 'sentence_conllu': sample, 'language_code': 'en'})
    assert sentence['passed'] is True
    score = predictions_evaluate({'working_tree_path': root, 'gold_file_paths': ['a.conllu'],
                                  'prediction_file_paths': ['b.conllu']})
    assert score['scores']['LAS']['correct'] == 1
    assert score['scores']['LAS']['gold_total'] == 1
    assert score['scores']['LAS']['system_total'] == 1
    assert score['scores']['LAS']['f1'] == 1.0
    # These are actual upstream results, and the input bytes must remain intact.
    cases = (
        (sample.rstrip('\n').encode('utf-8') + b'\n', 'missing-empty-line'),
        ('# sent_id = unicode\r\n# text = Ä\r\n1\tÄ\t_\tX\t_\t_\t0\troot\t_\t_\r\n\r\n'.encode('utf-8'),
         'non-unix-newline'),
    )
    path = Path(root) / 'a.conllu'
    for content, expected in cases:
        path.write_bytes(content)
        checked = validation_report({**request, 'file_paths': ['a.conllu']})
        assert checked['passed'] is False
        assert any(item.get('testid') == expected for item in checked['incidents'])
        assert path.read_bytes() == content
    try:
        validation_report({**request, 'file_paths': []})
    except InvalidInput:
        pass
    else:
        raise AssertionError('an empty selection must not be reported as a validation pass')
print('real upstream validator and scorer checks passed')
