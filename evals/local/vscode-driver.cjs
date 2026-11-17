/** MIT. UI command driver only: the installed VS Code application owns the loop. */
const vscode = require('vscode');
const fs = require('node:fs');

exports.activate = async function activate() {
  const file = process.env.UD_EVAL_DESKTOP_DRIVER;
  if (!file) return;
  const spec = JSON.parse(fs.readFileSync(file, 'utf8'));
  const emit = event => fs.appendFileSync(spec.events, JSON.stringify({ ...event, at: new Date().toISOString() }) + '\n');
  const complete = result => fs.writeFileSync(spec.result, JSON.stringify(result));
  try {
    const extension = vscode.extensions.getExtension('GitHub.copilot-chat');
    if (!extension) throw new Error('VSCODE_NATIVE_COPILOT_EXTENSION_ABSENT');
    emit({ type: 'desktop.activation_requested', extension: extension.id });
    await Promise.race([extension.activate(), new Promise((_, reject) => setTimeout(() => reject(new Error('VSCODE_NATIVE_EXTENSION_ACTIVATION_TIMEOUT')), 45_000))]);
    emit({ type: 'desktop.activated', application: vscode.version, extension: { id: extension.id, version: extension.packageJSON.version, path: extension.extensionPath } });
    const deadline = Date.now() + 30_000;
    let models = [];
    while (Date.now() < deadline) {
      models = await vscode.lm.selectChatModels({ vendor: 'customendpoint', id: spec.model });
      if (models.length) break;
      await new Promise(resolve => setTimeout(resolve, 200));
    }
    if (models.length !== 1) throw new Error('VSCODE_PRIVATE_MODEL_SELECTION_AMBIGUOUS_OR_MISSING');
    emit({ type: 'desktop.model_selected', models: models.map(({ id, vendor, name, family, maxInputTokens }) => ({ id, vendor, name, family, maxInputTokens })) });
    const commands = await vscode.commands.getCommands(true);
    if (!commands.includes('workbench.action.chat.newLocalChat')) throw new Error('VSCODE_NATIVE_LOCAL_CHAT_COMMAND_UNAVAILABLE');
    await vscode.commands.executeCommand('workbench.action.chat.newLocalChat');
    emit({ type: 'desktop.conversation_created', command: 'workbench.action.chat.newLocalChat', surface: 'vscode-copilot/local-chat' });
    const args = { query: spec.prompt, mode: 'agent', modelSelector: { vendor: 'customendpoint', id: spec.model }, blockOnResponse: true,
      ...(spec.image ? { attachFiles: [vscode.Uri.file(spec.image)] } : {}) };
    // Exactly one native user submission. No LM API invocation or response handling here.
    emit({ type: 'desktop.user_request', command: 'workbench.action.chat.open', prompt: spec.prompt, image: spec.image ?? null });
    const response = await vscode.commands.executeCommand('workbench.action.chat.open', args);
    await vscode.commands.executeCommand('workbench.action.chat.export', vscode.Uri.file(spec.transcript));
    if (!fs.existsSync(spec.transcript)) throw new Error('VSCODE_NATIVE_TRANSCRIPT_MISSING');
    const transcript = JSON.parse(fs.readFileSync(spec.transcript, 'utf8'));
    if (!Array.isArray(transcript.requests) || transcript.requests.length !== 1) throw new Error('VSCODE_NATIVE_CONVERSATION_NOT_FRESH');
    const request = transcript.requests[0];
    if (request.message?.text !== spec.prompt) throw new Error('VSCODE_NATIVE_USER_REQUEST_MISMATCH');
    const agent = request.agent?.extensionId?.value ?? request.agent?.extensionId;
    if (typeof agent !== 'string' || agent.toLowerCase() !== 'github.copilot-chat') throw new Error('VSCODE_NATIVE_AGENT_SURFACE_MISMATCH');
    if (request.modelId !== 'customendpoint/UD local evaluation/' + spec.model) throw new Error('VSCODE_NATIVE_MODEL_ATTRIBUTION_MISMATCH');
    const blocked = response?.type === 'confirmation' || Boolean(response?.errorDetails) || Boolean(request.result?.errorDetails) || request.isCanceled === true;
    emit({ type: 'desktop.native_request_observed', request_id: request.requestId, model_id: request.modelId, agent: request.agent.id, extension: agent });
    emit({ type: blocked ? 'turn.failed' : 'turn.completed', source: 'native-ui-command', response });
    complete({ status: blocked ? 'blocked' : 'completed', response, transcript: spec.transcript });
  } catch (error) {
    emit({ type: 'turn.failed', source: 'native-ui-command', error: error.message });
    complete({ status: 'failed', error: error.message });
  }
};

exports.deactivate = function deactivate() {};
