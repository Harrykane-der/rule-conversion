import yaml
import json
import subprocess
import tempfile
import requests
import os
import logging
import re
import ipaddress
from datetime import datetime
from typing import List, Dict, Optional, Any

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

DOMAIN_PATTERN = re.compile(
    r'^(?:\.?(\*|[a-zA-Z0-9*](?:[a-zA-Z0-9*-]*[a-zA-Z0-9*])?))'
    r'(?:\.(?:\*|[a-zA-Z0-9*](?:[a-zA-Z0-9*-]*[a-zA-Z0-9*])?))*$'
)

MIHOMO_PATH = 'mihomo'
SING_BOX_PATH = 'sing-box'

class RulesMerger:
    def __init__(self, config_path: str):
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config(config_path)
        self.output_dir = os.getenv("OUTPUT_DIR", "./output")

    def _load_config(self, path: str):
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def merge_rules(self):
        for config in self.config:
            if 'upstream' not in config or not config.get('path'):
                continue

            target_format = config.get('format', 'yaml')
            merged_rules = []

            for source in config['upstream'].values():
                rules = self._process_source(source)
                merged_rules.extend(rules)

            merged_rules = sorted(set(merged_rules))

            # ⭐ FIX：输出路径改为 OUTPUT_DIR
            output_file = os.path.join(self.output_dir, config['path'])

            self._write_rules(output_file, merged_rules, target_format)

    def _process_source(self, source):
        rules = []
        source_type = source.get('type')

        if source_type == 'file':
            path = source.get('path')
            if path and os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    rules = f.read().splitlines()

        elif source_type == 'http':
            url = source.get('url')
            if url:
                try:
                    r = requests.get(url, timeout=10)
                    rules = r.text.splitlines()
                except:
                    pass

        return [r.strip() for r in rules if r]

    def _write_rules(self, output_path: str, rules: List[str], rule_format: str):
        # ⭐ FIX：确保目录存在
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            if rule_format == 'yaml':
                yaml.dump({'payload': rules}, f, allow_unicode=True)
            else:
                f.write("\n".join(rules))

        self.logger.info(f"已生成: {output_path}, {len(rules)} 条规则")


def main():
    merger = RulesMerger('config.yaml')

    # ⭐ FIX：读取 workflow 传入路径
    merger.output_dir = os.getenv("OUTPUT_DIR", "/tmp/release/mihomo")

    merger.merge_rules()

if __name__ == '__main__':
    main()
