"""Private preparation and exact-artifact probes; never imported by ordinary tests. MIT."""
import argparse
import base64
import hashlib
import importlib.metadata
import importlib.util
import json
import re
from pathlib import Path


def validate_text_chat(request):
    """Validate supported Chat input before native normalization or image I/O.

    Images must be bounded inline bytes. The exact native processor handles their
    token expansion; this validator never substitutes text or estimates tokens.
    """
    if not isinstance(request, dict) or not isinstance(request.get('messages'), list):
        raise RuntimeError('PROTOCOL_TOKEN_ACCOUNTING_UNSUPPORTED')
    if request.get('context_management', []) != [] or request.get('enable_thinking', False) is not False:
        raise RuntimeError('TOKEN_ACCOUNTING_POLICY_UNSUPPORTED')
    for message in request['messages']:
        if not isinstance(message, dict):
            raise RuntimeError('PROCESSOR_TOKEN_ACCOUNTING_UNSUPPORTED')
        content = message.get('content')
        if isinstance(content, list):
            for part in content:
                if not isinstance(part, dict):
                    raise RuntimeError('PROCESSOR_TOKEN_ACCOUNTING_UNSUPPORTED')
                if part.get('type') == 'text' and isinstance(part.get('text'), str):
                    continue
                if message.get('role') != 'user' or part.get('type') not in ('image_url', 'input_image'):
                    raise RuntimeError('PROCESSOR_TOKEN_ACCOUNTING_UNSUPPORTED')
                reference = part.get('image_url')
                url = reference.get('url') if isinstance(reference, dict) else reference
                if not isinstance(url, str) or not re.match(r'^data:image/(?:png|jpeg|webp);base64,', url):
                    raise RuntimeError('INLINE_IMAGE_REQUIRED')
                try:
                    data = base64.b64decode(url.split(',', 1)[1], validate=True)
                except (ValueError, TypeError) as error:
                    raise RuntimeError('INLINE_IMAGE_INVALID') from error
                if not data or len(data) > 8 * 1024 * 1024:
                    raise RuntimeError('INLINE_IMAGE_SIZE_EXCEEDED')
        elif not isinstance(content, str) and not (message.get('role') == 'assistant' and content is None and isinstance(message.get('tool_calls'), list)):
            raise RuntimeError('PROCESSOR_TOKEN_ACCOUNTING_UNSUPPORTED')
        for call in message.get('tool_calls', []):
            if not isinstance(call, dict) or not isinstance(call.get('function'), dict):
                raise RuntimeError('TOOL_ARGUMENT_TOKEN_ACCOUNTING_UNSUPPORTED')
            arguments = call['function'].get('arguments', {})
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except (ValueError, TypeError) as error:
                    raise RuntimeError('TOOL_ARGUMENT_TOKEN_ACCOUNTING_UNSUPPORTED') from error
            if not isinstance(arguments, dict):
                raise RuntimeError('TOOL_ARGUMENT_TOKEN_ACCOUNTING_UNSUPPORTED')


def tokenize_chat(request, directory, *, return_prepared=False):
    """Run the pinned server's formatter and CPU preprocessor without weights.

    MLX-VLM sorts tool-schema keys inside get_chat_template. Rendering directly
    with AutoTokenizer bypasses that step and produced a different Bonsai prompt.
    Reuse the installed native functions rather than estimating an adjustment.
    """
    validate_text_chat(request)
    if importlib.metadata.version('mlx-vlm') != '0.7.11':
        raise RuntimeError('TOKEN_ACCOUNTING_RUNTIME_UNVERIFIED')
    import mlx.core as mx
    mx.set_default_device(mx.cpu)
    from types import SimpleNamespace
    from mlx_vlm.utils import (load_config, get_model_and_args, load_processor,
                               update_module_configs, apply_generation_config_defaults)
    from mlx_vlm.prompt_utils import apply_chat_template
    from mlx_vlm.tools.policy import _prepare_chat_tool_choice
    from mlx_vlm.server.schemas import ChatRequest
    from mlx_vlm.server.compaction import with_transient_context
    from mlx_vlm.server.request_normalization import (_chat_message_to_prompt,
                                                       _normalize_instruction_messages,
                                                       _build_gen_args)
    from mlx_vlm.server.generation import ResponseGenerator, _count_prompt_tokens

    model_path = Path(directory).resolve(strict=True)
    config = load_config(model_path)
    if config.get('model_type') not in ('prism_hadamard_qwen35', 'lfm3_vl') or config.get('model_file'):
        raise RuntimeError('TOKEN_ACCOUNTING_MODEL_UNVERIFIED')
    # Importing the architecture installs its native processor registration.
    # Instantiate only its configuration: never Model, load_model, or load.
    architecture, _ = get_model_and_args(config, model_path=model_path)
    config.setdefault('text_config', config.pop('llm_config', {}))
    config.setdefault('vision_config', {})
    config.setdefault('audio_config', {})
    model_config = architecture.ModelConfig.from_dict(config)
    model_config = update_module_configs(model_config, architecture, config,
                                         ['text', 'vision', 'perceiver', 'projector', 'audio'])
    model_config = apply_generation_config_defaults(model_config, config)
    processor = load_processor(model_path, add_detokenizer=False, local_files_only=True)
    native_request = ChatRequest.model_validate({**request, 'model': str(model_path),
                                                 'enable_thinking': False, 'context_management': []})
    messages = [_chat_message_to_prompt(message.model_dump(exclude_none=True))
                for message in native_request.messages]
    images = []
    for message in request['messages']:
        if message.get('role') != 'user' or not isinstance(message.get('content'), list):
            continue
        for part in message['content']:
            if part.get('type') == 'image_url':
                images.append(part['image_url']['url'])
            elif part.get('type') == 'input_image':
                images.append(part['image_url'])
    if len(images) > 4:
        raise RuntimeError('IMAGE_COUNT_EXCEEDED')
    if images:
        import io
        from PIL import Image
        for url in images:
            # Bound decompression before the native processor decodes these same
            # bytes. Keep original URLs, so preprocessing remains byte-identical.
            with Image.open(io.BytesIO(base64.b64decode(url.split(',', 1)[1], validate=True))) as image:
                if image.width * image.height > 16_000_000:
                    raise RuntimeError('IMAGE_PIXEL_LIMIT_EXCEEDED')
    messages = with_transient_context(messages, native_request)
    _normalize_instruction_messages(messages)
    messages, tools, tool_choice = _prepare_chat_tool_choice(
        messages, native_request.tools, native_request.tool_choice)
    generation = _build_gen_args(native_request, processor)
    template_kwargs = generation.to_template_kwargs()
    if tool_choice is not None:
        template_kwargs['tool_choice'] = tool_choice
    prompt = apply_chat_template(processor, model_config, messages, num_images=len(images),
                                 num_audios=0, video=None, tools=tools, **template_kwargs)
    # Calling the unbound pure CPU method avoids constructing ResponseGenerator,
    # whose constructor owns the model-loading/generation thread.
    context = SimpleNamespace(processor=processor, model=SimpleNamespace(config=model_config))
    inputs = ResponseGenerator._cpu_preprocess(context, prompt,
                                               **({'images': images} if images else {}),
                                               **generation.preprocessing_kwargs())
    count = int(_count_prompt_tokens(inputs))
    if return_prepared:
        return inputs, model_config, processor, prompt
    if count < 0:
        raise RuntimeError('TOKEN_ACCOUNTING_SHAPE_UNSUPPORTED')
    return {'inputTokens': count, 'contextTokens': count, 'trusted': True,
            'provenance': {'runtime': 'mlx-vlm', 'version': '0.7.11',
                           'formatter': 'mlx_vlm.prompt_utils.apply_chat_template',
                           'preprocessor': 'mlx_vlm.server.generation.ResponseGenerator._cpu_preprocess',
                           'processor': type(processor).__name__,
                           'prompt_sha256': hashlib.sha256(prompt.encode()).hexdigest(),
                           'device': 'cpu', 'model_weights_loaded': False}}


def digest(file):
    h = hashlib.sha256()
    with file.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['download', 'load-minicpm', 'tokenize'])
    parser.add_argument('--artifact', required=True)
    parser.add_argument('--revision')
    parser.add_argument('--directory', required=True)
    args = parser.parse_args()
    if args.action == 'download':
        from huggingface_hub import HfApi, snapshot_download
        revision = HfApi().model_info(args.artifact, revision=args.revision).sha
        if not isinstance(revision, str) or not re.fullmatch(r'[a-f0-9]{40}', revision):
            raise RuntimeError('IMMUTABLE_MODEL_REVISION_REQUIRED')
        if args.revision and re.fullmatch(r'[a-f0-9]{40}', args.revision) and revision != args.revision:
            raise RuntimeError('MODEL_REVISION_CHANGED')
        snapshot_download(args.artifact, revision=revision, local_dir=args.directory)
        files = [{'path': str(file.relative_to(args.directory)), 'sha256': digest(file), 'size': file.stat().st_size}
                 for file in sorted(Path(args.directory).rglob('*'))
                 if file.is_file() and '.cache' not in file.parts]
        print(json.dumps({'artifact': args.artifact, 'revision': revision, 'files': files,
                          'packages': {d.metadata['Name']: d.version for d in importlib.metadata.distributions()}}))
    elif args.action == 'load-minicpm':
        # Use the serving implementation, including exact NF4/device/processor
        # checks. A second loader recipe cannot establish serving compatibility.
        spec = importlib.util.spec_from_file_location('ud_minicpm_probe', Path(__file__).with_name('minicpm_server.py'))
        native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(native)
        backend = native.Backend(args.directory)
        print(json.dumps({'loaded': True, 'runtime_identity': backend.runtime_identity}))
    else:
        import sys
        request = json.load(sys.stdin)
        request = request.get('body', request)
        if args.artifact not in ('LiquidAI/LFM3-VL-2B-MLX-5bit', 'prism-ml/Ternary-Bonsai-2-2B-mlx-2bit'):
            raise RuntimeError('TOKEN_ACCOUNTING_ARTIFACT_UNVERIFIED')
        print(json.dumps(tokenize_chat(request, args.directory)))


if __name__ == '__main__':
    main()
