#!/usr/bin/env node
/** Explicit local entrypoint. Ordinary test discovery never launches this command. MIT. */
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync, mkdirSync, readFileSync, readdirSync } from 'node:fs';
import { openStudy } from '../../evals/local/study.mjs';
import { writeNew } from '../../evals/local/preparation.mjs';
import { writeStudyAnalysis } from '../../evals/local/study-analysis.mjs';
import { inventory, prepareCampaign, runCampaign } from '../../evals/local/campaign.mjs';
import { writeReport } from '../../evals/local/report.mjs';
import { verifyCampaignEvidence } from '../../evals/local/qualification.mjs';

const LOOP_OPTIONS = {
  'loop-groups': [],
  'loop-prepare': ['--opt-in'],
  'loop-run': ['--opt-in', '--group', '--label', '--harness', '--seeds', '--scenario', '--installation', '--python', '--model-dir', '--device', '--generation-seconds', '--request-timeout-seconds', '--output', '--catalog-layout', '--tool-parser', '--model-id'],
  'loop-analyze': ['--runs', '--output', '--python'],
  'loop-interpret': ['--opt-in', '--group', '--installation', '--python', '--model-dir', '--runs', '--output', '--candidates', '--objective', '--catalog-layout'],
};
/** Bounded group-by-group QSLM loop (evals/local/loop.mjs); separate from campaigns and studies. */
export function parseLoopArguments(args) {
  const command = args[0], allowed = LOOP_OPTIONS[command], options = { optIn: false }, seen = new Set();
  for (let index = 1; index < args.length; index++) {
    const key = args[index];
    if (!allowed.includes(key) || seen.has(key)) throw new Error(`Unknown, duplicate, or unsupported loop option: ${key}`);
    seen.add(key);
    if (key === '--opt-in') { options.optIn = true; continue; }
    const value = args[++index];
    if (!value || value.startsWith('--')) throw new Error(`Incomplete loop option: ${key}`);
    const name = key.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
    options[name] = ['--installation', '--python', '--model-dir', '--output', '--candidates'].includes(key) ? path.resolve(value)
      : key === '--runs' ? value.split(',').map(item => path.resolve(item)) : key === '--generation-seconds' || key === '--request-timeout-seconds' ? Number(value) : value;
  }
  if (command === 'loop-run' && (!options.group || !options.label || !options.installation || !options.python || !options.modelDir)) throw new Error('loop-run requires --group, --label, --installation, --python and --model-dir.');
  if (command === 'loop-interpret' && (!options.installation || !options.python || !options.modelDir || !options.output)) throw new Error('loop-interpret requires --installation, --python, --model-dir and --output.');
  if (options.objective && !['skill-call', 'uptake'].includes(options.objective)) throw new Error(`Invalid --objective: ${options.objective} (skill-call or uptake).`);
  if (options.toolParser && !['strict', 'lenient'].includes(options.toolParser)) throw new Error(`Invalid --tool-parser: ${options.toolParser} (strict or lenient).`);
  if (options.modelId && !['minicpm', 'lfm3', 'bonsai'].includes(options.modelId)) throw new Error(`Invalid --model-id: ${options.modelId} (minicpm, lfm3 or bonsai).`);
  if (options.requestTimeoutSeconds !== undefined && !(Number.isFinite(options.requestTimeoutSeconds) && options.requestTimeoutSeconds > 0 && options.requestTimeoutSeconds <= 86_400)) throw new Error('Invalid --request-timeout-seconds: use a number of seconds from 1 to 86400 (default 300).');

  if (options.catalogLayout && !['host', 'system'].includes(options.catalogLayout)) throw new Error(`Invalid --catalog-layout: ${options.catalogLayout} (host or system).`);
  if (command === 'loop-analyze' && (!options.runs || !options.output || !options.python)) throw new Error('loop-analyze requires --runs, --output and --python.');
  return { command, options };
}
export function parseArguments(args) {
  const command = args[0];
  if (Object.hasOwn(LOOP_OPTIONS, command)) return parseLoopArguments(args);
  if (!['inventory', 'prepare', 'run', 'report', 'study-prepare', 'study-run', 'study-report', 'iterate-prepare', 'iterate', 'iterate-report'].includes(command)) throw new Error('Usage: npm run eval:local -- loop-groups | loop-prepare --opt-in | loop-interpret --opt-in --installation PATH --python PATH --model-dir PATH --output DIR [--runs DIRS] [--candidates FILE] [--objective skill-call|uptake] [--catalog-layout host|system] | loop-run --opt-in --group G1 --label LABEL --installation PATH --python PATH --model-dir PATH [--harness LIST] [--seeds LIST] [--scenario LIST] [--device auto|cpu|cuda|mps] [--catalog-layout host|system] [--tool-parser lenient|strict] [--model-id minicpm|lfm3|bonsai] [--generation-seconds N] [--request-timeout-seconds N] | loop-analyze --runs DIR[,DIR] --output DIR --python PATH | inventory | prepare --opt-in [--containers] [--retry-acquisition | --repair-runtime] | run --opt-in [--campaign PATH] [--no-controls] | report --campaign PATH --output NEW_DIRECTORY | study-prepare --opt-in [--study PATH] | study-run --opt-in --study PATH | study-report --study PATH --output NEW_DIRECTORY | iterate-prepare --opt-in --session PATH [--profile headless-12h-v2] | iterate --opt-in --session PATH [--round baseline|repair|transfer|claude-transfer] [--evidence PATH] | iterate-report --session PATH --output NEW_DIRECTORY [--require-headless-qualified]');
  if (['iterate-prepare', 'iterate', 'iterate-report'].includes(command)) {
    const options = { optIn: false, ...(command === 'iterate' ? { round: 'baseline' } : {}) }, seen = new Set();
    const allowed = command === 'iterate-prepare' ? ['--opt-in', '--session', '--profile'] : command === 'iterate' ? ['--opt-in', '--session', '--round', '--evidence'] : ['--session', '--output', '--require-headless-qualified'];
    for (let index = 1; index < args.length; index++) {
      const key = args[index];
      if (!allowed.includes(key) || seen.has(key)) throw new Error(`Unknown, duplicate, or unsupported iteration option: ${key}`);
      seen.add(key);
      if (key === '--opt-in') { options.optIn = true; continue; }
      if (key === '--require-headless-qualified') { options.requireHeadlessQualified = true; continue; }
      const value = args[++index];
      if (!value || value.startsWith('--')) throw new Error(`Incomplete iteration option: ${key}`);
      if (key === '--profile') {
        if (value !== 'headless-12h-v2') throw new Error(`Unknown iteration profile: ${value}`);
        options.profile = value;
      } else if (key === '--round') {
        if (!['baseline', 'repair', 'transfer', 'claude-transfer'].includes(value)) throw new Error(`Unknown iteration round: ${value}`);
        options.round = value;
      } else options[key.slice(2)] = path.resolve(value);
    }
    if (!options.session) throw new Error(`${command} requires --session PATH.`);
    if (command === 'iterate-report' && !options.output) throw new Error('iterate-report requires --output NEW_DIRECTORY.');
    if (command === 'iterate' && options.round === 'repair' && !options.evidence) throw new Error('The repair round requires --evidence PATH.');
    if (options.evidence && options.round !== 'repair') throw new Error('--evidence is only accepted by the repair round.');
    return { command, options };
  }
  const options = { optIn: false, controls: true, windows: 1 };
  let windowsSeen = false;
  for (let index = 1; index < args.length; index++) {
    const key = args[index];
    if (key === '--opt-in' && !options.optIn) options.optIn = true;
    else if (key === '--repair-runtime' && !options.repairRuntime) options.repairRuntime = true;
    else if (key === '--retry-acquisition' && !options.retryAcquisition) options.retryAcquisition = true;
    else if (key === '--clients' && !options.clients) options.clients = true;
    else if (key === '--containers' && !options.containers) options.containers = true;
    else if (key === '--no-controls' && options.controls) options.controls = false;
    else if (key === '--require-qualified' && !options.requireQualified) options.requireQualified = true;
    else if (key === '--windows' && !windowsSeen && ['1', '3'].includes(args[index + 1])) { options.windows = Number(args[++index]); windowsSeen = true; }
    else if (['--campaign', '--output', '--baseline', '--patches', '--admission-restart-from', '--mechanical-rebaseline-from', '--study'].includes(key) && !options[key.slice(2)] && args[index + 1] && !args[index + 1].startsWith('--')) options[key.slice(2)] = path.resolve(args[++index]);
    else throw new Error(`Unknown, duplicate, or incomplete option: ${key}`);
  }
  if (command.startsWith('study-')) {
    if (['study-run', 'study-report'].includes(command) && !options.study) throw new Error(`${command} requires --study PATH.`);
    if (command === 'study-report' && !options.output) throw new Error('study-report requires --output NEW_DIRECTORY.');
    if (command !== 'study-report' && options.output) throw new Error('--output is only accepted by report or study-report.');
    if (options.campaign || options.baseline || options.patches || options.repairRuntime || options.retryAcquisition || options.clients || options.containers || windowsSeen || options.requireQualified || !options.controls || options['admission-restart-from'] || options['mechanical-rebaseline-from']) throw new Error('Study commands accept only --study, --opt-in and study-report --output.');
    return { command, options };
  }
  if (options.study) throw new Error('--study is only accepted by study commands.');
  if (command === 'report' && (!options.campaign || !options.output)) throw new Error('Report requires --campaign and --output.');
  if (options.output && command !== 'report') throw new Error('--output is only accepted by report.');
  if (options.retryAcquisition && command !== 'prepare') throw new Error('--retry-acquisition is only accepted by prepare.');
  if (options.retryAcquisition && options.repairRuntime) throw new Error('Choose --retry-acquisition or --repair-runtime.');
  if (options.repairRuntime && command !== 'prepare') throw new Error('--repair-runtime is only accepted by prepare.');
  if (options.containers && command !== 'prepare') throw new Error('--containers is only accepted by prepare.');
  if (options.clients && command !== 'prepare') throw new Error('--clients is only accepted by prepare.');
  if (windowsSeen && command !== 'run') throw new Error('--windows is only accepted by run.');
  if (options.requireQualified && command !== 'report') throw new Error('--require-qualified is only accepted by report.');
  if ((options['admission-restart-from'] || options['mechanical-rebaseline-from']) && command !== 'run') throw new Error('Restart options are only accepted by run.');
  return { command, options };
}
export async function main(args, root = path.resolve(import.meta.dirname, '../..')) {
  const { command, options } = parseArguments(args);
  const onProgress = message => process.stderr.write((typeof message === 'string' ? message : JSON.stringify(message)) + '\n');
  if (command.startsWith('loop-')) {
    const loop = await import('../../evals/local/loop.mjs');
    if (command === 'loop-groups') return { groups: loop.LOOP_GROUPS, harnesses: loop.LOOP_HARNESSES, limits: loop.LOOP_LIMITS };
    if (command === 'loop-prepare') return loop.prepareLoopInstallation(root, { optIn: options.optIn, onProgress });
    if (command === 'loop-interpret') return loop.interpretLoop(root, { optIn: options.optIn, group: options.group ?? 'G1', installation: options.installation, python: options.python, modelDirectory: options.modelDir, runs: options.runs ?? [], output: options.output, candidates: options.candidates, objective: options.objective ?? 'skill-call', catalogLayout: options.catalogLayout ?? 'host', onProgress });
    if (command === 'loop-analyze') return loop.analyzeLoop(root, { runs: options.runs, output: options.output, python: options.python });
    return loop.runLoopGroup(root, { optIn: options.optIn, group: options.group, label: options.label, output: options.output, installation: options.installation, python: options.python, modelDirectory: options.modelDir,
      device: options.device ?? 'auto', generationSeconds: options.generationSeconds ?? 300, requestTimeoutSeconds: options.requestTimeoutSeconds, catalogLayout: options.catalogLayout ?? 'host', toolParser: options.toolParser ?? 'lenient', modelId: options.modelId ?? 'minicpm',
      ...(options.harness ? { harnesses: loop.parseList(options.harness, Object.keys(loop.LOOP_HARNESSES), 'harness list') } : {}),
      ...(options.seeds ? { seeds: options.seeds.split(',').map(Number) } : {}), ...(options.scenario ? { scenarios: options.scenario.split(',').map(item => item.trim()).filter(Boolean) } : {}), onProgress });
  }
  if (['iterate-prepare', 'iterate', 'iterate-report'].includes(command)) {
    const { prepareIteration, runIteration, reportIteration } = await import('../../evals/local/iterate.mjs');
    if (command === 'iterate-prepare') return prepareIteration(root, { directory: options.session, profile: options.profile, optIn: options.optIn, onProgress });
    if (command === 'iterate') return runIteration(root, { directory: options.session, optIn: options.optIn, kind: options.round, repairEvidence: options.evidence, onProgress });
    return reportIteration(root, { directory: options.session, output: options.output, requireHeadlessQualified: options.requireHeadlessQualified });
  }
  if (command === 'study-prepare' || command === 'study-run') {
    const { prepareScientificStudy, runScientificStudy } = await import('../../evals/local/study-execution.mjs');
    const execute = command === 'study-prepare' ? prepareScientificStudy : runScientificStudy;
    const result = await execute(root, { directory: options.study, optIn: options.optIn, onProgress });
    return command === 'study-prepare' ? { study: result.directory, manifest_sha256: result.manifest_sha256, clock_started: result.clock_started } : result;
  }
  if (command === 'study-report') {
    if (existsSync(options.output)) throw new Error('Study report requires a new output directory.');
    const report = openStudy({ root, directory: options.study }).report();
    mkdirSync(options.output, { recursive: true, mode: 0o700 });
    const file = path.join(options.output, 'report.json'); writeNew(file, report);
    const analysis = writeStudyAnalysis(options.output, report, { studyDirectory: options.study });
    return { report: file, analysis: analysis.json, readable_analysis: analysis.markdown, status: report.status, counts: report.counts, evidence_verification: report.evidence_verification, qualification_evidence: false };
  }
  if (command === 'inventory') return inventory(root);
  if (command === 'prepare') return prepareCampaign(root, { ...options, onProgress });
  if (command === 'run') {
    const result = await runCampaign(root, { ...options, admissionRestart: options['admission-restart-from'], mechanicalRebaseline: options['mechanical-rebaseline-from'], onProgress });
    return { campaign: result.directory, report: result.report_path, status: result.report.status, counts: result.report.counts };
  }
  const manifest = JSON.parse(readFileSync(path.join(options.campaign, 'manifest.json')));
  const directory = path.join(options.campaign, 'episodes');
  const episodes = readdirSync(directory).filter(file => file.endsWith('.json')).map(file => JSON.parse(readFileSync(path.join(directory, file))));
  const result = await writeReport(options.output, manifest, episodes);
  const verification = options.requireQualified ? await verifyCampaignEvidence(root, options.campaign) : undefined;
  if (verification && verification.status !== 'passed') process.exitCode = 1;
  return { report: result.json, status: result.report.status, counts: result.report.counts, ...(verification ? { verification } : {}) };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { const result = await main(process.argv.slice(2)); process.stdout.write(JSON.stringify(result, null, 2) + '\n'); }
  catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
