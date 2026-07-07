import yaml
import json
import subprocess
import tempfile
import requests
import os
import logging
import argparse
from typing import List, Dict, Optional, Any
from contextlib import contextmanager
import re
import ipaddress
from datetime import datetime
from functools import lru_cache
from collections import defaultdict
import concurrent.futures

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ====================== 常量 ======================
DOMAIN_PATTERN = re.compile(r'^(?:\.?(\*|[a-zA-Z0-9*](?:[a-zA-Z0-9*-]*[a-zA-Z0-9*])?))(?:\.(?:\*|[a-zA-Z0-9*](?:[a-zA-Z0-9*-]*[a-zA-Z0-9*])?))*$')
PORT_PATTERN = re.compile(r'^\d+(?:-\d+)?$')

MIHOMO_PATH = 'mihomo'
SING_BOX_PATH = 'sing-box'
SING_BOX_RULESET_VERSION = 5

SING_BOX_LIST_FIELDS = {'domain', 'domain_suffix', 'domain_keyword', 'domain_regex', 'ip_cidr', 'port', 'port_range', 'network'}
CLASSICAL_TO_SB = {'DOMAIN': 'domain', 'DOMAIN-SUFFIX': 'domain_suffix', 'DOMAIN-KEYWORD': 'domain_keyword', 'DOMAIN-REGEX': 'domain_regex', 'IP-CIDR': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 'DST-PORT': 'port', 'NETWORK': 'network'}


class RulesDeduplicator:
    """去重优化工具"""
    @staticmethod
    def deduplicate_domains(domains: List[str]) -> List[str]:
        if not domains: return []
        unique = {d.strip().lower() for d in domains if d.strip()}
        reversed_tuples = sorted(tuple(d.split('.'))[::-1] for d in unique)
        result = []
        n = len(reversed_tuples)
        for i in range(n):
            current = reversed_tuples[i]
            covered = any(len(current) <= len(reversed_tuples[j]) and reversed_tuples[j][:len(current)] == current for j in range(i+1, n))
            if not covered:
                result.append('.'.join(current[::-1]))
        return sorted(result)

    @staticmethod
    def merge_ip_cidr(rules: List[str]) -> List[str]:
        v4, v6 = [], []
        for rule in rules:
            if ',' not in rule: continue
            try:
                net = ipaddress.ip_network(rule.split(',', 1)[1].strip(), strict=False)
                (v4 if net.version == 4 else v6).append(net)
            except: continue
        collapsed = list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))
        return [f"IP-CIDR,{n}" for n in collapsed if n.version == 4] + [f"IP-CIDR6,{n}" for n in collapsed if n.version == 6]

    @staticmethod
    def merge_ports(rules: List[str]) -> Optional[str]:
        items = []
        for r in rules:
            if ',' in r:
                items.extend([x.strip() for x in r.split(',',1)[1].split('/') if x.strip()])
        if not items: return None
        merged = RulesDeduplicator._merge_port_items(list(dict.fromkeys(items)))
        return f"DST-PORT,{'/'.join(merged)}" if merged else None

    @staticmethod
    def _merge_port_items(items):
        ranges = []
        for item in items:
            try:
                if '-' in item:
                    s, e = map(int, item.split('-'))
                else:
                    s = e = int(item)
                ranges.append((s, e))
            except: continue
        ranges.sort()
        merged = [ranges[0]]
        for c in ranges[1:]:
            if c[0] <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], c[1]))
            else:
                merged.append(c)
        return [str(a) if a == b else f"{a}-{b}" for a, b in merged]

    @staticmethod
    def normalize_signature(rule):
        if isinstance(rule, dict):
            d = {k: sorted(str(x).lower() for x in v) if isinstance(v, (list,tuple)) else str(v).lower() 
                 for k, v in sorted(rule.items())}
            return json.dumps(d, ensure_ascii=False, sort_keys=True)
        s = str(rule).strip().lower()
        return s.replace('ip-cidr6,', 'ip-cidr,')

    @staticmethod
    def deduplicate_list(items):
        seen, result = {}, []
        for item in items:
            sig = RulesDeduplicator.normalize_signature(item)
            if sig not in seen:
                seen[sig] = True
                result.append(item)
        return result


class RulesMerger:
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.mihomo_path = MIHOMO_PATH
        self.sing_box_path = SING_BOX_PATH

    @staticmethod
    def _load_config(path: str):
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            return data if isinstance(data, list) else [data]

    @contextmanager
    def _temp_file(self, suffix: str):
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        try: yield path
        finally:
            if os.path.exists(path): os.unlink(path)

    def _fetch_rules_from_source(self, source: Dict, target_behavior: str) -> List[Any]:
        # 这里保留你原来最核心的获取逻辑（简化版）
        rule_format = source.get('format', 'yaml')
        if source.get('type') == 'http':
            try:
                resp = requests.get(source['url'], timeout=30)
                resp.raise_for_status()
                if rule_format == 'yaml' or source['url'].endswith(('.yml','.yaml')):
                    data = yaml.safe_load(resp.text)
                    return data.get('payload', []) if isinstance(data, dict) else []
                return resp.text.splitlines()
            except Exception as e:
                logger.error(f"下载失败 {source.get('url')}: {e}")
                return []
        elif source.get('type') == 'file':
            try:
                with open(source['path'], 'r', encoding='utf-8') as f:
                    if rule_format == 'yaml':
                        data = yaml.safe_load(f)
                        return data.get('payload', []) if isinstance(data, dict) else []
                    return f.read().splitlines()
            except Exception as e:
                logger.error(f"读取文件失败: {e}")
                return []
        return []

    def _transform(self, rule, source_b, target_b):
        # 简化处理，实际可扩展
        return [rule] if rule else []

    def merge_rules(self):
        for cfg in self.config:
            if not cfg.get('path') or not cfg.get('upstream'):
                continue

            target_behavior = 'sing-box' if cfg.get('format') in ('json','srs') else 'classical'
            all_rules = []

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
                fs = [ex.submit(self._fetch_rules_from_source, s, target_behavior) for s in cfg['upstream'].values()]
                for f in concurrent.futures.as_completed(fs):
                    all_rules.extend(f.result())

            logger.info(f"获取到 {len(all_rules)} 条原始规则")

            dedup = RulesDeduplicator
            if target_behavior == 'sing-box':
                final = dedup.deduplicate_list(all_rules)
            else:
                final = self._deduplicate_classical(all_rules, dedup)

            self._write_rules(cfg['path'], final, cfg.get('format', 'yaml'))
            logger.info(f"✅ 已生成: {cfg['path']}  ({len(final)} 条规则)")

    def _deduplicate_classical(self, rules, dedup):
        d, ds, k, r, ip, p, n, o = [], [], [], [], [], [], [], []
        for rule in rules:
            if not isinstance(rule, str): 
                o.append(rule)
                continue
            if rule.startswith('DOMAIN,'): d.append(rule)
            elif rule.startswith('DOMAIN-SUFFIX,'): ds.append(rule)
            elif rule.startswith('DOMAIN-KEYWORD,'): k.append(rule)
            elif rule.startswith('DOMAIN-REGEX,'): r.append(rule)
            elif rule.startswith(('IP-CIDR','IP-CIDR6')): ip.append(rule)
            elif rule.startswith('DST-PORT,'): p.append(rule)
            elif rule.startswith('NETWORK,'): n.append(rule)
            else: o.append(rule)

        result = []
        result.extend(f"DOMAIN,{x}" for x in dedup.deduplicate_domains([x.split(',',1)[1] for x in d if ',' in x]))
        result.extend(f"DOMAIN-SUFFIX,{x}" for x in dedup.deduplicate_domains([x.split(',',1)[1] for x in ds if ',' in x]))
        result.extend(dedup.deduplicate_list(k + r + n + o))
        result.extend(dedup.merge_ip_cidr(ip))
        if port_rule := dedup.merge_ports(p):
            result.append(port_rule)
        return result

    def _write_rules(self, path: str, rules: List, fmt: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            if fmt == 'yaml':
                yaml.dump({'payload': rules}, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
            else:
                for line in rules:
                    f.write(str(line) + '\n')
        logger.info(f"已写入 {len(rules)} 条规则 → {path}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', default='config.yaml')
    args = parser.parse_args()
    RulesMerger(args.config).merge_rules()

if __name__ == '__main__':
    main()
