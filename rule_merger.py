#!/usr/bin/env python3
import yaml
import json
import subprocess
import tempfile
import requests
import os
import logging
from typing import List, Dict, Any, Optional
import re
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
import time

# ==================== 配置 ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9*](?:[a-zA-Z0-9*-]*[a-zA-Z0-9*])?)(?:\.(?:[a-zA-Z0-9*](?:[a-zA-Z0-9*-]*[a-zA-Z0-9*])?))*$'
)

MIHOMO_PATH = 'mihomo'
SING_BOX_PATH = 'sing-box'
SING_BOX_RULESET_VERSION = 5
MAX_WORKERS = 12
REQUEST_TIMEOUT = 15
RETRY_TIMES = 3


class RulesMerger:
    def __init__(self, config_path: str = 'config.yaml'):
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config(config_path)
        self.mihomo_path = MIHOMO_PATH
        self.sing_box_path = SING_BOX_PATH
        
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Rule-Merger-Optimized/1.0'})

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

    def _load_config(self, path: str) -> list:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            if isinstance(config, dict):
                config = [config]
            if not isinstance(config, list):
                self.logger.error("config.yaml 必须是列表或单个配置对象")
                return []
            return config
        except Exception as e:
            self.logger.error(f"配置文件加载失败: {e}")
            raise

    # ... (其他方法保持不变，仅修改 sing-box 输出部分) ...

    def _write_sing_box_source(self, output_path: str, rules: List[str], behavior: str, version: int = SING_BOX_RULESET_VERSION):
        """修正后的 sing-box 输出"""
        rule_set = {
            "version": version,
            "rules": self._to_sing_box_rules_correct(rules, behavior)
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(rule_set, f, ensure_ascii=False, indent=2)
        self.logger.info(f"✅ 已生成 sing-box 规则集: {output_path} ({len(rules)} 条)")

    def _to_sing_box_rules_correct(self, rules: List[str], behavior: str) -> List[Dict[str, Any]]:
        """关键修正：生成独立 rule 对象格式"""
        groups = {
            'domain': [],
            'domain_suffix': [],
            'domain_keyword': [],
            'domain_regex': [],
            'ip_cidr': []
        }

        for rule in rules:
            if not rule:
                continue
            cleaned = self._clean_rule(str(rule)) if behavior != 'sing-box' else rule

            if behavior == 'sing-box':
                try:
                    item = json.loads(cleaned) if isinstance(cleaned, str) else cleaned
                    for k in groups:
                        if k in item:
                            val = item[k]
                            groups[k].extend(val if isinstance(val, list) else [val])
                except:
                    continue
            else:
                item = self._to_sing_box_item(cleaned, behavior)
                if item:
                    key, value = item
                    if isinstance(value, list):
                        groups[key].extend(value)
                    else:
                        groups[key].append(value)

        # 生成多个独立的 rule 对象
        result = []
        for key, values in groups.items():
            if values:
                cleaned_values = sorted(set(str(v).strip() for v in values if v))
                if cleaned_values:
                    result.append({key: cleaned_values})

        return result

    # ==================== 以下为原脚本保留的核心方法 ====================

    def _to_sing_box_item(self, rule: str, behavior: str) -> Optional[tuple]:
        if behavior == 'domain':
            if rule.startswith('+.') or rule.startswith('*.'):
                return 'domain_suffix', rule[2:] if rule.startswith('+.') else rule[2:]
            return 'domain', rule
        if behavior == 'ipcidr':
            return 'ip_cidr', rule
        if behavior != 'classical':
            return None
        parts = [part.strip() for part in rule.split(',')]
        if len(parts) < 2:
            return None
        rule_type = parts[0]
        value = parts[1]
        mapping = {
            'DOMAIN': 'domain',
            'DOMAIN-SUFFIX': 'domain_suffix',
            'DOMAIN-KEYWORD': 'domain_keyword',
            'DOMAIN-REGEX': 'domain_regex',
            'IP-CIDR': 'ip_cidr',
            'IP-CIDR6': 'ip_cidr'
        }
        target_key = mapping.get(rule_type)
        if not target_key:
            return None
        return target_key, value

    def _clean_rule(self, rule: str) -> str:
        rule = rule.strip()
        if rule.startswith('#') or not rule:
            return ''
        parts = re.split(r'\s+#', rule, maxsplit=1)
        return parts[0].strip()

    # ...（其余方法保持不变，包括 merge_rules、_write_rules 等）...

    def merge_rules(self) -> None:
        start_time = time.time()
        for cfg in self.config:
            if 'upstream' not in cfg or not cfg.get('path'):
                continue

            target_format = cfg.get('format', 'yaml')
            default_behavior = 'sing-box' if target_format in ('json', 'srs') else 'domain'
            target_behavior = cfg.get('behavior', default_behavior)

            self.logger.info(f"🚀 开始生成: {cfg['path']} ({target_behavior})")
            merged = self._process_source_concurrent(cfg['upstream'], target_behavior)
            merged = sorted(set(filter(None, merged)))
            
            self._write_rules(
                cfg['path'],
                merged,
                target_format,
                target_behavior,
                cfg.get('version', SING_BOX_RULESET_VERSION)
            )
        
        self.logger.info(f"🎉 全部完成！总耗时: {time.time() - start_time:.1f} 秒")

    def _write_rules(self, output_path: str, rules: List[str], rule_format: str = 'yaml',
                     behavior: str = 'domain', version: int = SING_BOX_RULESET_VERSION) -> None:
        try:
            output_dir = os.path.dirname(output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

            if rule_format == 'json':
                self._write_sing_box_source(output_path, rules, behavior, version)
                return

            if rule_format == 'srs':
                tmp_path = tempfile.mktemp(suffix='.json')
                self._write_sing_box_source(tmp_path, rules, behavior, version)
                try:
                    if self.sing_box_path:
                        subprocess.run([self.sing_box_path, 'rule-set', 'compile', '--output', output_path, tmp_path], check=True)
                finally:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                return

            # 其他格式...
            with open(output_path, 'w', encoding='utf-8') as f:
                if not output_path.endswith('.tmp'):
                    f.write(f"# 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# 规则数量: {len(rules)}\n")
                    f.write("payload:\n")
                for rule in rules:
                    f.write(f"  - '{rule}'\n")
        except Exception as e:
            self.logger.error(f"写入失败 {output_path}: {e}")


def main():
    merger = RulesMerger('config.yaml')
    merger.merge_rules()


if __name__ == '__main__':
    main()
