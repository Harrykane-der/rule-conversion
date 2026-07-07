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
from collections import defaultdict
import concurrent.futures

# ====================== 日志 ======================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ====================== 常量 ======================
DOMAIN_PATTERN = re.compile(
    r'^(?:\.?(\*|[a-zA-Z0-9*](?:[a-zA-Z0-9*-]*[a-zA-Z0-9*])?))'
    r'(?:\.(?:\*|[a-zA-Z0-9*](?:[a-zA-Z0-9*-]*[a-zA-Z0-9*])?))*$'
)
PORT_PATTERN = re.compile(r'^\d+(?:-\d+)?$')

MIHOMO_PATH = 'mihomo'
SING_BOX_PATH = 'sing-box'
SING_BOX_RULESET_VERSION = 5

SING_BOX_LIST_FIELDS = {'domain', 'domain_suffix', 'domain_keyword', 'domain_regex', 'ip_cidr', 'port', 'port_range', 'network'}
CLASSICAL_TO_SB = {
    'DOMAIN': 'domain', 'DOMAIN-SUFFIX': 'domain_suffix',
    'DOMAIN-KEYWORD': 'domain_keyword', 'DOMAIN-REGEX': 'domain_regex',
    'IP-CIDR': 'ip_cidr', 'IP-CIDR6': 'ip_cidr',
    'DST-PORT': 'port', 'NETWORK': 'network'
}


class RulesDeduplicator:
    """统一去重工具"""
    @staticmethod
    def deduplicate_domains(domains: List[str]) -> List[str]:
        if not domains:
            return []
        unique = {d.strip().lower() for d in domains if d.strip()}
        reversed_tuples = sorted([tuple(d.split('.'))[::-1] for d in unique])
        result = []
        n = len(reversed_tuples)
        for i in range(n):
            current = reversed_tuples[i]
            covered = False
            for j in range(i + 1, n):
                nxt = reversed_tuples[j]
                if len(current) <= len(nxt) and nxt[:len(current)] == current:
                    covered = True
                    break
            if not covered:
                result.append('.'.join(current[::-1]))
        return sorted(result)

    @staticmethod
    def merge_ip_cidr(rules: List[str]) -> List[str]:
        v4, v6 = [], []
        for rule in rules:
            if ',' not in rule: continue
            try:
                net_str = rule.split(',', 1)[1].strip()
                net = ipaddress.ip_network(net_str, strict=False)
                (v4 if net.version == 4 else v6).append(net)
            except ValueError: continue
        collapsed = list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))
        result = [f"IP-CIDR,{net}" for net in collapsed if net.version == 4]
        result.extend([f"IP-CIDR6,{net}" for net in collapsed if net.version == 6])
        return result

    @staticmethod
    def merge_ports(rules: List[str]) -> Optional[str]:
        all_items = []
        for rule in rules:
            if ',' not in rule: continue
            expr = rule.split(',', 1)[1]
            all_items.extend([x.strip() for x in expr.split('/') if x.strip()])
        if not all_items: return None
        merged = RulesDeduplicator._merge_port_items(list(dict.fromkeys(all_items)))
        return f"DST-PORT,{'/'.join(merged)}"

    @staticmethod
    def _merge_port_items(items: List[str]) -> List[str]:
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
        for curr in ranges[1:]:
            if curr[0] <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], curr[1]))
            else:
                merged.append(curr)
        return [str(s) if s == e else f"{s}-{e}" for s, e in merged]

    @staticmethod
    def normalize_signature(rule: Any) -> str:
        if isinstance(rule, dict):
            norm = {k: sorted(str(x).lower() for x in v) if isinstance(v, (list, tuple)) else str(v).lower()
                    for k, v in sorted(rule.items())}
            return json.dumps(norm, ensure_ascii=False, sort_keys=True)
        s = str(rule).strip().lower()
        return s.replace('ip-cidr6,', 'ip-cidr,')

    @staticmethod
    def deduplicate_list(items: List[Any]) -> List[Any]:
        seen = {}
        result = []
        for item in items:
            sig = RulesDeduplicator.normalize_signature(item)
            if sig not in seen:
                seen[sig] = True
                result.append(item)
        return result


class RulesMerger:
    def __init__(self, config_path: str = "config.yaml"):
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
        try:
            yield path
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def _fetch_rules_from_source(self, source: Dict) -> List[Any]:
        try:
            if source.get('type') == 'http':
                resp = requests.get(source.get('url'), timeout=30)
                resp.raise_for_status()
                content = resp.text
            else:
                with open(source.get('path'), 'r', encoding='utf-8') as f:
                    content = f.read()

            fmt = source.get('format', 'text')
            if fmt == 'yaml' or source.get('url', '').endswith(('.yml', '.yaml')):
                data = yaml.safe_load(content)
                return data.get('payload', []) if isinstance(data, dict) else []
            elif fmt == 'json':
                data = json.loads(content)
                return data.get('rules', []) if isinstance(data, dict) else []
            return [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith('#')]
        except Exception as e:
            logger.error(f"获取规则失败 {source}: {e}")
            return []

    def merge_rules(self):
        for task in self.config:
            if 'path' not in task or 'upstream' not in task:
                continue

            target_behavior = task.get('behavior', 'classical').lower()
            is_singbox = target_behavior in ('sing-box', 'singbox')

            logger.info(f"开始处理 {'Sing-box' if is_singbox else 'Mihomo Classical'} 规则 → {task['path']}")

            all_rules = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(self._fetch_rules_from_source, src) 
                          for src in task['upstream'].values()]
                for future in concurrent.futures.as_completed(futures):
                    all_rules.extend(future.result())

            if is_singbox:
                final_rules = self._process_singbox_rules(all_rules)
            else:
                final_rules = self._process_classical_rules(all_rules)

            self._write_rules(task['path'], final_rules, task.get('format', 'yaml'), is_singbox, task.get('version'))
            logger.info(f"✅ 完成: {task['path']} ({len(final_rules)} 条)")

    def _process_classical_rules(self, rules: List) -> List[str]:
        """Mihomo Classical 专用处理 + 去重"""
        dedup = RulesDeduplicator
        domain, suffix, keyword, regex, ip, port, other = [], [], [], [], [], [], []

        for r in rules:
            if not isinstance(r, str) or not r: continue
            if r.startswith('DOMAIN,'): domain.append(r)
            elif r.startswith('DOMAIN-SUFFIX,'): suffix.append(r)
            elif r.startswith('DOMAIN-KEYWORD,'): keyword.append(r)
            elif r.startswith('DOMAIN-REGEX,'): regex.append(r)
            elif r.startswith(('IP-CIDR', 'IP-CIDR6')): ip.append(r)
            elif r.startswith('DST-PORT,'): port.append(r)
            else: other.append(r)

        result = []
        # 域名去重
        result.extend(f"DOMAIN,{d}" for d in dedup.deduplicate_domains([x.split(',', 1)[1] for x in domain if ',' in x]))
        result.extend(f"DOMAIN-SUFFIX,{d}" for d in dedup.deduplicate_domains([x.split(',', 1)[1] for x in suffix if ',' in x]))
        result.extend(dedup.deduplicate_list(keyword))
        result.extend(dedup.deduplicate_list(regex))
        result.extend(dedup.merge_ip_cidr(ip))
        if p := dedup.merge_ports(port):
            result.append(p)
        result.extend(dedup.deduplicate_list(other))
        return result

    def _process_singbox_rules(self, rules: List) -> List[Dict]:
        """Sing-box 专用处理 + 去重"""
        dedup = RulesDeduplicator
        bucket = defaultdict(list)

        for rule in rules:
            if isinstance(rule, dict):
                for key in SING_BOX_LIST_FIELDS:
                    if key in rule:
                        bucket[key].extend(dedup._as_list(rule[key]))  # type: ignore
            elif isinstance(rule, str) and ',' in rule:
                typ, val = [x.strip() for x in rule.split(',', 1)]
                if typ == 'DOMAIN': bucket['domain'].append(val)
                elif typ == 'DOMAIN-SUFFIX': bucket['domain_suffix'].append(val)
                elif typ in ('IP-CIDR', 'IP-CIDR6'): bucket['ip_cidr'].append(val)

        # 去重优化
        if bucket['domain']:
            bucket['domain'] = dedup.deduplicate_domains(bucket['domain'])
        if bucket['domain_suffix']:
            bucket['domain_suffix'] = dedup.deduplicate_domains(bucket['domain_suffix'])
        if bucket['ip_cidr']:
            bucket['ip_cidr'] = dedup.merge_ip_cidr([f"IP-CIDR,{x}" for x in bucket['ip_cidr']])

        return [{k: v} for k, v in bucket.items() if v]

    @staticmethod
    def _as_list(value):
        if value is None: return []
        return value if isinstance(value, list) else [value]

    def _write_rules(self, path: str, rules: Any, fmt: str, is_singbox: bool, version: Optional[int] = None):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            if not path.endswith('.tmp'):
                f.write(f"# 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# 规则数量: {len(rules)}\n\n")

            if fmt == 'yaml':
                yaml.dump({'payload': rules}, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
            elif fmt == 'json' and is_singbox:
                data = {'version': version or SING_BOX_RULESET_VERSION, 'rules': rules}
                json.dump(data, f, ensure_ascii=False, indent=2)
            else:
                for r in rules:
                    if isinstance(r, dict):
                        f.write(json.dumps(r, ensure_ascii=False) + '\n')
                    else:
                        f.write(str(r) + '\n')


def main():
    parser = argparse.ArgumentParser(description="Mihomo & Sing-box 规则合并工具")
    parser.add_argument('-c', '--config', default='config.yaml', help='配置文件路径')
    args = parser.parse_args()

    merger = RulesMerger(args.config)
    merger.merge_rules()


if __name__ == '__main__':
    main()
