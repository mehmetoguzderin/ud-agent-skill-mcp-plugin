"""Observed loaded-object identity; importing performs no model work. MIT."""
import hashlib
import importlib.metadata
import inspect
import json
from pathlib import Path


def source_identity(value):
    file = inspect.getsourcefile(value)
    if not file:
        raise RuntimeError("LOADED_OBJECT_SOURCE_UNAVAILABLE")
    return {"module": value.__module__, "name": value.__qualname__,
            "sha256": hashlib.sha256(Path(file).read_bytes()).hexdigest()}


def base_identity(directory, model, processor, runtime, packages):
    root = Path(directory).resolve(strict=True)
    files = {}
    for name in ("config.json", "processor_config.json", "preprocessor_config.json",
                 "tokenizer_config.json", "chat_template.json", "chat_template.jinja"):
        file = root / name
        if file.is_file():
            files[name] = hashlib.sha256(file.read_bytes()).hexdigest()
    if "config.json" not in files:
        raise RuntimeError("MODEL_CONFIGURATION_IDENTITY_REQUIRED")
    return {"schema_version": 1, "model_loaded": True, "model": str(root),
            "runtime": runtime, "model_class": source_identity(type(model)),
            "processor_class": source_identity(type(processor)), "files": files,
            "packages": {name: importlib.metadata.version(name) for name in packages}}


def minicpm_identity(directory, model, processor, requested_device):
    identity = base_identity(directory, model, processor, "transformers-bitsandbytes",
                             ("torch", "transformers", "bitsandbytes"))
    parameters = list(model.parameters())
    devices = sorted({str(value.device) for value in parameters})
    if not parameters or not devices or any(value.split(":")[0] != requested_device for value in devices):
        raise RuntimeError("MINICPM_EFFECTIVE_DEVICE_UNVERIFIED")
    quantized = [module for module in model.modules()
                 if type(module).__module__.startswith("bitsandbytes.") and type(module).__name__ == "Linear4bit"]
    if not quantized or any(getattr(module.weight, "quant_type", None) != "nf4" for module in quantized):
        raise RuntimeError("MINICPM_EFFECTIVE_NF4_UNVERIFIED")
    identity.update({"loader": "transformers.AutoModelForImageTextToText.from_pretrained",
                     "device": requested_device, "parameter_devices": devices,
                     "parameter_dtypes": sorted({str(value.dtype) for value in parameters}),
                     "quantization": {"format": "bitsandbytes-nf4", "linear_modules": len(quantized)},
                     "quantized_class": source_identity(type(quantized[0])),
                     "image_processor_class": source_identity(type(processor.image_processor))})
    return identity


def mlx_identity(directory, model, processor, mx, flatten, loader):
    identity = base_identity(directory, model, processor, "mlx-vlm", ("mlx", "mlx-vlm"))
    config = json.loads((Path(directory) / "config.json").read_text())
    kind = config.get("model_type")
    expected = {"lfm3_vl": "mlx-5bit", "prism_hadamard_qwen35": "mlx-2bit"}
    if kind not in expected or kind not in type(model).__module__:
        raise RuntimeError("MLX_EFFECTIVE_ARCHITECTURE_UNVERIFIED")
    device = str(mx.default_device())
    if "gpu" not in device.lower():
        raise RuntimeError("MLX_EFFECTIVE_GPU_UNVERIFIED")
    parameters = flatten(model.parameters())
    if not parameters:
        raise RuntimeError("MLX_LOADED_PARAMETERS_UNVERIFIED")
    modules = dict(model.named_modules())
    quantized = [(name, module) for name, module in modules.items()
                 if isinstance(getattr(module, "bits", None), int)]
    expected_bits = 2 if kind == "prism_hadamard_qwen35" else 5
    if not any(module.bits == expected_bits for _, module in quantized):
        raise RuntimeError("MLX_EFFECTIVE_QUANTIZATION_UNVERIFIED")
    quantization = {"format": expected[kind], "module_bits": sorted({module.bits for _, module in quantized}),
                    "quantized_modules": len(quantized)}
    if kind == "prism_hadamard_qwen35":
        records = config.get("modules")
        if not isinstance(records, list) or not records:
            raise RuntimeError("BONSAI_TRANSFORM_CONFIGURATION_REQUIRED")
        verified = []
        for record in records:
            name = "language_model." + record["path"]
            module = modules.get(name)
            expected_class = "HadamardQuantizedEmbedding" if record["embedding"] else "HadamardQuantizedLinear"
            if (module is None or type(module).__name__ != expected_class or module.bits != 2
                    or module.group_size != 128 or module.block != record["block"]
                    or module.block and getattr(module, "signs", None) is None):
                raise RuntimeError("BONSAI_EFFECTIVE_HADAMARD_UNVERIFIED")
            verified.append({"path": name, "block": module.block, "class": source_identity(type(module))})
        quantization["hadamard"] = {"verified_modules": len(verified),
                                    "rotated_modules": sum(row["block"] != 0 for row in verified),
                                    "modules_sha256": hashlib.sha256(json.dumps(verified, sort_keys=True).encode()).hexdigest(),
                                    "implementation": verified[0]["class"]}
    identity.update({"loader": source_identity(loader), "device": "gpu", "native_device": device,
                     "device_observation": "native-load-thread-default-device;MLX-arrays-have-no-per-array-placement",
                     "model_type": kind, "parameter_dtypes": sorted({str(value.dtype) for _, value in parameters}),
                     "parameter_storage_bytes": sum(int(value.nbytes) for _, value in parameters),
                     "quantization": quantization})
    return identity
