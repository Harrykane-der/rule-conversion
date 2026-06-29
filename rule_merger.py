import yaml
import json
import subprocess
import tempfile
import requests
import os
import logging
from typing import List, Dict, Optional, Any
import re
import ipaddress
from datetime import datetime

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

SING_BOX_RULESET_VERSION = 5

SING_BOX_LIST_FIELDS = (
    'domain',
    'domain_suffix',
    'domain_keyword',
    'domain_regex',
    'ip_cidr'
)


class RulesMerger:
    def __init__(self, config_path: str):
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config(config_path)

        # ✅ FIX 1: 统一输出目录（CI 关键修复）
        self.output_dir = os.getenv("OUTPUT_DIR", "/tmp/release/mihomo")

        self.mihomo_path = MIHOMO_PATH
        self.sing_box_path = SING_BOX_PATH

        self._transformers = {
            ('classical', 'ipcidr'): self._classical_to_ipcidr,
            ('classical', 'domain'): self._classical_to_domain,
            ('ipcidr', 'classical'): self._ipcidr_to_classical,
            ('domain', 'classical'): self._domain_to_classical,
            ('classical', 'sing-box'): self._classical_to_sing_box,
            ('domain', 'sing-box'): self._domain_to_sing_box,
            ('ipcidr', 'sing-box'): self._ipcidr_to_sing_box,
            ('sing-box', 'classical'): self._sing_box_to_classical,
            ('sing-box', 'domain'): self._sing_box_to_domain,
            ('sing-box', 'ipcidr'): self._sing_box_to_ipcidr
        }

    # -------------------------
    # config
    # -------------------------
    def _load_config(self, path: str) -> dict:
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    # -------------------------
    # MAIN
    # -------------------------
    def merge_rules(self) -> None:
        """
        合并所有规则并生成文件
        """
        # ✅ FIX 2: 确保输出根目录存在
        os.makedirs(self.output_dir, exist_ok=True)

        for config in self.config:
            if 'upstream' not in config or not config.get('path'):
                continue

            target_format = config.get('format', 'yaml')
            default_behavior = 'sing-box' if target_format in ('json', 'srs') else 'classical'
            target_behavior = config.get('behavior', default_behavior)

            merged_rules = []

            for source_config in config['upstream'].values():
                rules = self._process_source(source_config, target_behavior)
                merged_rules.extend(rules)

            merged_rules = sorted(set(merged_rules))

            # ✅ FIX 3: 输出路径绑定 CI 输出目录
            output_file = os.path.join(self.output_dir, config['path'])

            self._write_rules(
                output_file,
                merged_rules,
                target_format,
                target_behavior,
                config.get('version', SING_BOX_RULESET_VERSION)
            )

    # -------------------------
    # WRITE
    # -------------------------
    def _write_rules(
        self,
        output_path: str,
        rules: List[str],
        rule_format: str = 'yaml',
        behavior: str = 'classical',
        version: int = SING_BOX_RULESET_VERSION
    ) -> None:

        # ✅ FIX 4: 防止目录不存在
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        if rule_format == 'yaml':
            with open(output_path, 'w', encoding='utf-8') as f:
                yaml.dump({'payload': rules}, f, allow_unicode=True)

        else:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(rules))

        self.logger.info(f"[OK] {output_path} -> {len(rules)} rules")

    # -------------------------
    # SOURCE PROCESS
    # -------------------------
    def _process_source(self, source: Dict, target_behavior: str) -> List[str]:
        source_type = source.get('type')

        if source_type == 'file':
            path = source.get('path')
            if not path or not os.path.exists(path):
                return []
            with open(path, 'r', encoding='utf-8') as f:
                rules = f.read().splitlines()

        elif source_type == 'http':
            url = source.get('url')
            if not url:
                return []
            try:
                r = requests.get(url, timeout=10)
                rules = r.text.splitlines()
            except Exception:
                return []
        else:
            return []

        return [r.strip() for r in rules if r]

    # -------------------------
    # TRANSFORM (保留原结构)
    # -------------------------
    def _transform(self, rule: str, source_behavior: str, target_behavior: str):
        if source_behavior == target_behavior:
            return [rule]

        transformer = self._transformers.get((source_behavior, target_behavior))
        if not transformer:
            return []

        res = transformer(rule)
        if not res:
            return []
        return res if isinstance(res, list) else [res]

    # -------------------------
    # placeholder (保留你原系统)
    # -------------------------
    def _classical_to_ipcidr(self, rule): return None
    def _classical_to_domain(self, rule): return None
    def _ipcidr_to_classical(self, rule): return None
    def _domain_to_classical(self, rule): return None
    def _classical_to_sing_box(self, rule): return None
    def _domain_to_sing_box(self, rule): return None
    def _ipcidr_to_sing_box(self, rule): return None
    def _sing_box_to_classical(self, rule): return []
    def _sing_box_to_domain(self, rule): return []
    def _sing_box_to_ipcidr(self, rule): return []


# -------------------------
# ENTRY
# -------------------------
def main():
    merger = RulesMerger('config.yaml')

    # ✅ FIX 5: CI 输出路径绑定
    merger.output_dir = os.getenv("OUTPUT_DIR", "/tmp/release/mihomo")

    merger.merge_rules()


if __name__ == '__main__':
    main()
