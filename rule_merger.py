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

# ====================== 日志配置 ======================
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

SING_BOX_LIST_FIELDS = {
    'domain', 'domain_suffix', 'domain_keyword', 'domain_regex',
    'ip_cidr', 'port', 'port_range', 'network'
}

CLASSICAL_TO_SB = {
    'DOMAIN': 'domain', 'DOMAIN-SUFFIX': 'domain_suffix',
    'DOMAIN-KEYWORD': 'domain_keyword', 'DOMAIN-REGEX': 'domain_regex',
    'IP-CIDR': 'ip_cidr', 'IP-CIDR6': 'ip_cidr',
    'DST-PORT': 'port', 'NETWORK': 'network'
}


# ====================== 独立去重工具类 ======================
class RulesDeduplicator:
    """统一去重工具 - 优化所有去重场景"""

    @staticmethod
    def deduplicate_domains(domains: List[str]) -> List[str]:
        """高效域名去重：子域名优先覆盖父域名"""
        if not domains:
            return []
        unique = {d.strip().lower() for d in domains if d.strip()}
        if not unique:
            return []

        reversed_tuples = sorted(tuple(d.split('.'))[::-1] for d in unique)
        result = []
        n = len(reversed_tuples)

        for i in range(n):
            current = reversed_tuples[i]
            # 检查是否被更具体的域名覆盖
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
        """IP 网段智能聚合"""
        if not rules:
            return []
        v4, v6 = [], []
        for rule in rules:
            if ',' not in rule:
                continue
            try:
                net_str = rule.split(',', 1)[1].strip()
                net = ipaddress.ip_network(net_str, strict=False)
                (v4 if net.version == 4 else v6).append(net)
            except ValueError:
                continue

        collapsed = list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))
        result = [f"IP-CIDR,{net}" for net in collapsed if net.version == 4]
        result.extend([f"IP-CIDR6,{net}" for net in collapsed if net.version == 6])
        return result

    @staticmethod
    def merge_ports(port_rules: List[str]) -> Optional[str]:
        """端口规则合并"""
        if not port_rules:
            return None
        all_items = []
        for rule in port_rules:
            if ',' not in rule:
                continue
            expr = rule.split(',', 1)[1]
            items = [x.strip() for x in expr.split('/') if x.strip()]
            all_items.extend(items)

        merged = RulesDeduplicator._merge_port_items(list(dict.fromkeys(all_items)))
        return f"DST-PORT,{'/'.join(merged)}" if merged else None

    @staticmethod
    def _merge_port_items(items: List[str]) -> List[str]:
        if not items:
            return []
        ranges = []
        for item in items:
            try:
                if '-' in item:
                    s, e = map(int, item.split('-'))
                else:
                    s = e = int(item)
                ranges.append((s, e))
            except ValueError:
                continue
        ranges.sort()
        merged = [ranges[0]]
        for curr in ranges[1:]:
            last = merged[-1]
            if curr[0] <= last[1] + 1:
                merged[-1] = (last[0], max(last[1], curr[1]))
            else:
                merged.append(curr)
        return [str(s) if s == e else f"{s}-{e}" for s, e in merged]

    @staticmethod
    def normalize_signature(rule: Any) -> str:
        """规则签名标准化"""
        if isinstance(rule, dict):
            norm = {}
            for k, v in sorted(rule.items()):
                if isinstance(v, (list, tuple)):
                    norm[k] = sorted(str(x).lower() for x in v)
                else:
                    norm[k] = str(v).lower()
            return json.dumps(norm, ensure_ascii=False, sort_keys=True)
        if isinstance(rule, str):
            s = rule.strip().lower()
            s = s.replace('ip-cidr6,', 'ip-cidr,')
            return s
        return str(rule).lower()

    @staticmethod
    def deduplicate_list(items: List[Any]) -> List[Any]:
        """通用去重（保持相对顺序）"""
        seen = {}
        result = []
        for item in items:
            sig = RulesDeduplicator.normalize_signature(item)
            if sig not in seen:
                seen[sig] = True
                result.append(item)
        return result


# ====================== 主类 ======================
class RulesMerger:
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.mihomo_path = MIHOMO_PATH
        self.sing_box_path = SING_BOX_PATH
        self._stats = {'total': 0, 'converted': 0, 'dropped': 0, 'duplicates': 0}

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

    @staticmethod
    def _as_list(value: Any) -> List[Any]:
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    @staticmethod
    def _clean_rule(rule: str) -> str:
        rule = rule.strip()
        if not rule or rule.startswith('#'):
            return ''
        return re.split(r'\s+#', rule)[0].strip()

    def _fetch_rules_from_source(self, source: Dict, target_behavior: str) -> List[Any]:
        # （保持原有逻辑，省略以节省篇幅，实际使用时请保留你原来的 _fetch_http_rules 等方法）
        # 这里仅占位，推荐保留你原来的实现
        logger.info(f"获取规则: {source.get('url') or source.get('path')}")
        return []  # 替换为实际实现

    def _transform(self, rule: Any, source_behavior: str, target_behavior: str) -> List[Any]:
        # 简化版，实际请使用你原来的转换逻辑
        self._stats['total'] += 1
        return [rule] if rule else []

    def _deduplicate_and_merge_classical(self, rules: List[str]) -> List[str]:
        dedup = RulesDeduplicator
        domain, domain_suffix, keyword, regex, ip_cidr, dst_port, network, others = [], [], [], [], [], [], [], []

        for r in rules:
            if not isinstance(r, str):
                others.append(r)
                continue
            if r.startswith('DOMAIN,'): domain.append(r)
            elif r.startswith('DOMAIN-SUFFIX,'): domain_suffix.append(r)
            elif r.startswith('DOMAIN-KEYWORD,'): keyword.append(r)
            elif r.startswith('DOMAIN-REGEX,'): regex.append(r)
            elif r.startswith(('IP-CIDR', 'IP-CIDR6')): ip_cidr.append(r)
            elif r.startswith('DST-PORT,'): dst_port.append(r)
            elif r.startswith('NETWORK,'): network.append(r)
            else: others.append(r)

        result = []
        result.extend([f"DOMAIN,{d}" for d in dedup.deduplicate_domains([r.split(',',1)[1] for r in domain if ',' in r])])
        result.extend([f"DOMAIN-SUFFIX,{d}" for d in dedup.deduplicate_domains([r.split(',',1)[1] for r in domain_suffix if ',' in r])])
        result.extend(dedup.deduplicate_list(keyword))
        result.extend(dedup.deduplicate_list(regex))
        result.extend(dedup.merge_ip_cidr(ip_cidr))
        if port_rule := dedup.merge_ports(dst_port):
            result.append(port_rule)
        result.extend(dedup.deduplicate_list(network))
        result.extend(dedup.deduplicate_list(others))
        return result

    def _compile_final_sing_box_list(self, rules: List[Dict]) -> List[Dict]:
        dedup = RulesDeduplicator
        bucket = defaultdict(list)
        passthrough = []

        for rule in rules:
            if isinstance(rule, dict) and rule.get('type') != 'logical':
                for k in SING_BOX_LIST_FIELDS:
                    if k in rule:
                        bucket[k].extend(dedup._as_list(rule[k]))  # type: ignore
            else:
                passthrough.append(rule)

        # 域名去重
        if bucket['domain']:
            bucket['domain'] = dedup.deduplicate_domains([str(x) for x in bucket['domain']])
        if bucket['domain_suffix']:
            bucket['domain_suffix'] = dedup.deduplicate_domains([str(x) for x in bucket['domain_suffix']])

        # IP 聚合
        if bucket['ip_cidr']:
            bucket['ip_cidr'] = [str(net) for net in ipaddress.collapse_addresses(
                [ipaddress.ip_network(str(x), strict=False) for x in bucket['ip_cidr']]
            )]

        # 端口合并
        if bucket['port'] or bucket['port_range']:
            all_p = [str(x) for x in bucket['port']] + [str(x).replace(':', '-') for x in bucket.get('port_range', [])]
            merged = dedup._merge_port_items(list(dict.fromkeys(all_p)))
            bucket['port'] = [x for x in merged if '-' not in x]
            bucket['port_range'] = [x.replace('-', ':') for x in merged if '-' in x]

        # 最终去重
        compacted = [{k: v} for k, v in bucket.items() if v]
        return dedup.deduplicate_list(compacted + passthrough)

    def merge_rules(self):
        for config in self.config:
            if 'upstream' not in config or not config.get('path'):
                continue

            target_behavior = self._normalize_behavior(config.get('behavior', 'classical'))
            self._stats = {'total': 0, 'converted': 0, 'dropped': 0, 'duplicates': 0}

            all_rules = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(self._fetch_rules_from_source, src, target_behavior) 
                          for src in config['upstream'].values()]
                for future in concurrent.futures.as_completed(futures):
                    all_rules.extend(future.result())

            if target_behavior == 'sing-box':
                final_rules = self._compile_final_sing_box_list(all_rules)
            else:
                final_rules = self._deduplicate_and_merge_classical([str(r) for r in all_rules if r])

            logger.info(f"最终规则数量: {len(final_rules)} | 去重减少: {self._stats['duplicates']}")
            self._write_rules(config['path'], final_rules, config.get('format', 'yaml'), target_behavior)

    # 其他辅助方法（如 _write_rules, _normalize_behavior 等）请补充你原来的实现

    @staticmethod
    def _normalize_behavior(behavior: Optional[str]) -> str:
        if not behavior:
            return 'classical'
        b = behavior.strip().lower()
        return 'sing-box' if b in ('singbox', 'sing-box') else b

    def _write_rules(self, path: str, rules: List, fmt: str, behavior: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            if fmt == 'yaml':
                yaml.dump({'payload': rules}, f, allow_unicode=True, sort_keys=False)
            else:
                for r in rules:
                    f.write(f"{r}\n")
        logger.info(f"已写入 {fmt} 文件: {path} ({len(rules)} 条)")


# ====================== 入口 ======================
def main():
    parser = argparse.ArgumentParser(description="规则合并优化工具")
    parser.add_argument('-c', '--config', default='config.yaml', help='配置文件路径')
    args = parser.parse_args()

    merger = RulesMerger(args.config)
    merger.merge_rules()


if __name__ == '__main__':
    main()
