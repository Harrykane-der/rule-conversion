import yaml
import json
import requests
import os
import logging
import argparse
from typing import List, Dict, Optional, Any
from datetime import datetime
from collections import defaultdict
import concurrent.futures
import ipaddress

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ====================== 常量 ======================
SING_BOX_LIST_FIELDS = {'domain', 'domain_suffix', 'domain_keyword', 'domain_regex', 'ip_cidr', 'port', 'port_range', 'network'}
SING_BOX_RULESET_VERSION = 5


class RulesDeduplicator:
    """去重工具类"""
    @staticmethod
    def deduplicate_domains(domains: List[str]) -> List[str]:
        if not domains: return []
        unique = {d.strip().lower() for d in domains if d.strip()}
        reversed_tuples = sorted(tuple(d.split('.'))[::-1] for d in unique)
        result = []
        n = len(reversed_tuples)
        for i in range(n):
            current = reversed_tuples[i]
            covered = any(len(current) <= len(reversed_tuples[j]) and reversed_tuples[j][:len(current)] == current 
                         for j in range(i+1, n))
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
                items.extend(x.strip() for x in r.split(',', 1)[1].split('/') if x.strip())
        if not items: return None
        merged = RulesDeduplicator._merge_port_items(list(dict.fromkeys(items)))
        return f"DST-PORT,{'/'.join(merged)}"

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
        if not ranges: return []
        ranges.sort()
        merged = [ranges[0]]
        for c in ranges[1:]:
            if c[0] <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], c[1]))
            else:
                merged.append(c)
        return [str(a) if a == b else f"{a}-{b}" for a, b in merged]

    @staticmethod
    def deduplicate_list(items):
        seen = {}
        result = []
        for item in items:
            sig = RulesDeduplicator._normalize_signature(item)
            if sig not in seen:
                seen[sig] = True
                result.append(item)
        return result

    @staticmethod
    def _normalize_signature(rule):
        if isinstance(rule, dict):
            d = {k: sorted(str(x).lower() for x in v) if isinstance(v, (list, tuple)) else str(v).lower() 
                 for k, v in sorted(rule.items())}
            return json.dumps(d, ensure_ascii=False, sort_keys=True)
        return str(rule).strip().lower().replace('ip-cidr6,', 'ip-cidr,')


class RulesMerger:
    def __init__(self, config_path: str = "config.yaml"):
        self.config = self._load_config(config_path)

    @staticmethod
    def _load_config(path: str):
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            return data if isinstance(data, list) else [data]

    def _fetch_rules_from_source(self, source: Dict) -> List[Any]:
        try:
            if source.get('type') == 'http':
                resp = requests.get(source['url'], timeout=30)
                resp.raise_for_status()
                content = resp.text
            else:
                with open(source['path'], 'r', encoding='utf-8') as f:
                    content = f.read()

            if source.get('format') == 'yaml' or str(source.get('url', '')).endswith(('.yml', '.yaml')):
                data = yaml.safe_load(content)
                return data.get('payload', []) if isinstance(data, dict) else []
            return [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith('#')]
        except Exception as e:
            logger.error(f"获取失败 {source}: {e}")
            return []

    @staticmethod
    def _as_list(value):
        if value is None: return []
        return value if isinstance(value, list) else [value]

    def merge_rules(self):
        for task in self.config:
            if not task.get('path') or not task.get('upstream'):
                continue

            behavior = task.get('behavior', 'classical').lower()
            is_singbox = behavior in ('sing-box', 'singbox')

            logger.info(f"处理 → {task['path']} [{'Sing-box' if is_singbox else 'Mihomo Classical'}]")

            all_rules = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
                fs = [ex.submit(self._fetch_rules_from_source, s) for s in task['upstream'].values()]
                for f in concurrent.futures.as_completed(fs):
                    all_rules.extend(f.result())

            if is_singbox:
                final_rules = self._process_singbox_rules(all_rules)
            else:
                final_rules = self._process_classical_rules(all_rules)

            self._write_rules(task['path'], final_rules, task.get('format', 'yaml'), is_singbox)
            logger.info(f"✅ 生成完成: {task['path']} ({len(final_rules)} 条)")

    def _process_classical_rules(self, rules):
        dedup = RulesDeduplicator
        domain, suffix, keyword, regex, ip, port, other = [], [], [], [], [], [], []

        for r in rules:
            if not isinstance(r, str) or not r: continue
            if r.startswith('DOMAIN,'): domain.append(r)
            elif r.startswith('DOMAIN-SUFFIX,'): suffix.append(r)
            elif r.startswith('DOMAIN-KEYWORD,'): keyword.append(r)
            elif r.startswith('DOMAIN-REGEX,'): regex.append(r)
            elif r.startswith(('IP-CIDR','IP-CIDR6')): ip.append(r)
            elif r.startswith('DST-PORT,'): port.append(r)
            else: other.append(r)

        result = []
        result.extend(f"DOMAIN,{x}" for x in dedup.deduplicate_domains([x.split(',',1)[1] for x in domain if ',' in x]))
        result.extend(f"DOMAIN-SUFFIX,{x}" for x in dedup.deduplicate_domains([x.split(',',1)[1] for x in suffix if ',' in x]))
        result.extend(dedup.deduplicate_list(keyword + regex + other))
        result.extend(dedup.merge_ip_cidr(ip))
        if p := dedup.merge_ports(port):
            result.append(p)
        return result

    def _process_singbox_rules(self, rules):
        dedup = RulesDeduplicator
        bucket = defaultdict(list)

        for rule in rules:
            if isinstance(rule, dict):
                for key in SING_BOX_LIST_FIELDS:
                    if key in rule:
                        bucket[key].extend(self._as_list(rule[key]))
            elif isinstance(rule, str) and ',' in rule:
                typ, val = [x.strip() for x in rule.split(',', 1)]
                if typ == 'DOMAIN': bucket['domain'].append(val)
                elif typ == 'DOMAIN-SUFFIX': bucket['domain_suffix'].append(val)
                elif typ in ('IP-CIDR', 'IP-CIDR6'): bucket['ip_cidr'].append(val)

        # 去重
        if bucket['domain']:
            bucket['domain'] = dedup.deduplicate_domains(bucket['domain'])
        if bucket['domain_suffix']:
            bucket['domain_suffix'] = dedup.deduplicate_domains(bucket['domain_suffix'])
        if bucket['ip_cidr']:
            bucket['ip_cidr'] = dedup.merge_ip_cidr([f"IP-CIDR,{x}" for x in bucket['ip_cidr']])

        return [{k: v} for k, v in bucket.items() if v]

    def _write_rules(self, path: str, rules: Any, fmt: str, is_singbox: bool):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(f"# 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# 规则数量: {len(rules)}\n\n")
            if fmt == 'yaml':
                yaml.dump({'payload': rules}, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
            elif fmt == 'json' and is_singbox:
                json.dump({"version": SING_BOX_RULESET_VERSION, "rules": rules}, f, ensure_ascii=False, indent=2)
            else:
                for r in rules:
                    f.write(json.dumps(r, ensure_ascii=False) + '\n' if isinstance(r, dict) else f"{r}\n")


def main():
    parser = argparse.ArgumentParser(description="规则合并工具")
    parser.add_argument('-c', '--config', default='config.yaml')
    args = parser.parse_args()
    RulesMerger(args.config).merge_rules()


if __name__ == '__main__':
    main()
