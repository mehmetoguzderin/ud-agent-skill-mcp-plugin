import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ud_parser_asset_recipe',ROOT/'scripts/quality/prepare-rust-assertion-parser.py')
recipe=importlib.util.module_from_spec(spec);spec.loader.exec_module(recipe)


class ParserSdkRecipeTests(unittest.TestCase):
    def test_closed_sdk_hash_metadata_and_member_inventory_are_mandatory(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);file=root/'lib.dat';payload=b'exact compiler bytes';file.write_bytes(payload);file.chmod(0o444)
            row={'path':'lib.dat','sha256':hashlib.sha256(payload).hexdigest(),'size':len(payload),'mode':0o444}
            receipt={'qualification':'development-mutation-toolchain','platform':'linux/arm64','links':[],'files':[row]}
            recipe.verify_sdk(root,receipt)
            for changed in [{'sha256':'a'*64},{'size':len(payload)+1},{'mode':0o555},{'path':'../outside'},{'path':'/outside'},{'path':'a\\b'}]:
                with self.subTest(changed=changed),self.assertRaises(ValueError):recipe.verify_sdk(root,{**receipt,'files':[{**row,**changed}]})
            with self.assertRaises(ValueError):recipe.verify_sdk(root,{**receipt,'files':[row,row]})
            extra=root/'extra';extra.write_bytes(b'unlisted')
            with self.assertRaises(ValueError):recipe.verify_sdk(root,receipt)
            extra.unlink();file.chmod(0o644);file.write_bytes(b'same length replaced')
            with self.assertRaises(ValueError):recipe.verify_sdk(root,receipt)
            for changed in [{'qualification':'unverified'},{'platform':'linux/x64'},{'links':[{'path':'alias','target':'lib.dat'}]}]:
                with self.subTest(changed=changed),self.assertRaises(ValueError):recipe.verify_sdk(root,{**receipt,**changed})

    def test_source_receipt_binds_exact_production_manifest_lock_and_source_bytes(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary)
            for name in recipe.SOURCES:
                file=root/recipe.SOURCE/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_bytes(('source '+name+'\r\n').encode())
            receipt=recipe.source_inputs(root)
            self.assertEqual(set(receipt['source_inventory']),{recipe.SOURCE+'/'+name for name in recipe.SOURCES})
            for entry in receipt['files']:
                data=(root/recipe.SOURCE/entry['path']).read_bytes();self.assertEqual(entry['sha256'],hashlib.sha256(data).hexdigest());self.assertEqual(entry['size'],len(data));self.assertEqual(entry['mode'],0o644)
            before=receipt['source_inventory'][recipe.SOURCE+'/src/main.rs'];(root/recipe.SOURCE/'src/main.rs').write_bytes(b'changed')
            self.assertNotEqual(recipe.source_inputs(root)['source_inventory'][recipe.SOURCE+'/src/main.rs'],before)


if __name__=='__main__':unittest.main()
