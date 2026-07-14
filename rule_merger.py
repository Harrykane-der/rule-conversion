import yaml
import json
import subprocess
import tempfile
import requests
import os
import logging
import time
import threading
from typing import List, Dict, Optional, Any, Tuple
from contextlib import contextmanager
import re
import ipaddress
from datetime import datetime
from functools import lru_cache
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 常量定义
DOMAIN_PATTERN = re.compile(
    r'^(?:\.?(\*|[a-zA-Z0-9*](?:[a-zA-Z0-9*-]*[a-zA-Z0-9*])?))'
    r'(?:\.(?:\*|[a-zA-Z0-9*](?:[a-zA-Z0-9*-]*[a-zA-Z0-9*])?))*$'
)
PORT_PATTERN = re.compile(r'^\d+(?:-\d+)?$')

MIHOMO_PATH = 'mihomo'
SING_BOX_PATH = 'sing-box'
SING_BOX_RULESET_VERSION = 5
SING_BOX_LIST_FIELDS = (
    'domain', 'domain_suffix', 'domain_keyword',
    'domain_regex', 'ip_cidr', 'port', 'port_range', 'network'
)

CLASSICAL_TO_SB = {
    'DOMAIN': 'domain',
    'DOMAIN-SUFFIX': 'domain_suffix',
    'DOMAIN-KEYWORD': 'domain_keyword',
    'DOMAIN-REGEX': 'domain_regex',
    'IP-CIDR': 'ip_cidr',
    'IP-CIDR6': 'ip_cidr',
    'DST-PORT': 'port',
    'NETWORK': 'network'
}


class RulesMerger:
    def __init__(self, config_path: str, max_workers: int = 10):
        self.config = self._load_config(config_path)
        self.mihomo_path = MIHOMO_PATH
        self.sing_box_path = SING_BOX_PATH
        self.max_workers = max_workers
        
        # 初始化 HTTP Session 并配置自动重试机制
        self.session = requests.Session()
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        self.session.mount('http://', HTTPAdapter(max_retries=retries))
        self.session.mount('https://', HTTPAdapter(max_retries=retries))
        
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
        
        self._stats = {'total': 0, 'converted': 0, 'dropped': 0, 'duplicates': 0}
        self._stats_lock = threading.Lock()

    # -------------------- 通用工具方法 --------------------
    def _update_stats(self, key: str, value: int = 1):
        with self._stats_lock:
            self._stats[key] += value

    @staticmethod
    def _normalize_behavior(behavior: Optional[str]) -> str:
        if not behavior:
            return 'classical'
        b = behavior.strip().lower()
        return 'sing-box' if b in ('singbox', 'sing-box') else b

    @staticmethod
    def _load_config(path: str) -> dict:
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}

    @contextmanager
    def _temp_file(self, suffix: str):
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        try:
            yield path
        finally:
            if os.path.exists(path):
                try:
                    os.unlink(path)
                except OSError:
                    pass

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
        return rule.split(' #', 1)[0].strip()

    @staticmethod
    @lru_cache(maxsize=65536)  # 调大缓存，极大提升 IP 解析速度
    def _get_ipcidr_version(rule: str) -> Optional[int]:
        try:
            return ipaddress.ip_network(rule, strict=False).version
        except ValueError:
            return None

    def _validate_ipcidr_rule(self, rule: str) -> Optional[str]:
        return rule if self._get_ipcidr_version(rule) else None

    def _validate_domain_rule(self, rule: str) -> Optional[str]:
        domain = rule[2:] if rule.startswith('+.') else rule
        return rule if DOMAIN_PATTERN.match(domain) else None

    @staticmethod
    def _normalize_rule_signature(rule: Any) -> str:
        if isinstance(rule, dict):
            return json.dumps(rule, ensure_ascii=False, sort_keys=True)
        if isinstance(rule, str):
            s = rule.strip().lower()
            if s.startswith('ip-cidr6,'):
                return 'ip-cidr,' + s[9:]
            if s.startswith('domain-suffix,.'):
                return 'domain-suffix,' + s[15:]
            return s
        return str(rule)

    @staticmethod
    def _merge_port_items(items: List[str]) -> List[str]:
        if not items:
            return []
            
        ranges = []
        for item in set(items):
            item_str = str(item).strip()
            if not item_str: 
                continue
            try:
                if '-' in item_str:
                    start, end = map(int, item_str.split('-', 1))
                    ranges.append([start, end])
                else:
                    val = int(item_str)
                    ranges.append([val, val])
            except ValueError:
                continue
                
        if not ranges:
            return []
            
        ranges.sort(key=lambda x: x[0])
        
        merged = [ranges[0]]
        for start, end in ranges[1:]:
            last = merged[-1]
            if start <= last[1] + 1:
                last[1] = max(last[1], end)
            else:
                merged.append([start, end])
                
        return [str(s) if s == e else f"{s}-{e}" for s, e in merged]

    def _unified_domain_deduplication(self, exact_domains: List[str], suffix_domains: List[str]) -> Tuple[List[str], List[str]]:
        domain_types = {}
        
        for d in exact_domains:
            if d_str := str(d).strip():
                domain_types[d_str] = 0
                
        for d in suffix_domains:
            if d_str := str(d).strip():
                domain_types[d_str] = 1
                    
        if not domain_types:
            return [], []

        reversed_tuples = sorted(tuple(d.split('.'))[::-1] for d in domain_types.keys())
        
        result_domains = []
        last_parent = None
        last_len = 0
        
        for current in reversed_tuples:
            if last_parent and len(current) > last_len and current[:last_len] == last_parent:
                parent_str = '.'.join(last_parent[::-1])
                domain_types[parent_str] = 1
                continue
                
            result_domains.append(current)
            last_parent = current
            last_len = len(current)
            
        final_exact, final_suffix = [], []
        for t in result_domains:
            domain_str = '.'.join(t[::-1])
            if domain_types[domain_str] == 1:
                final_suffix.append(domain_str)
            else:
                final_exact.append(domain_str)
                
        return final_exact, final_suffix

    def _merge_ip_rules(self, rules: List[str]) -> List[str]:
        seen = set()
        result = []
        duplicates = 0
        
        for rule in rules:
            if (cleaned_rule := rule.strip()) not in seen and ',' in cleaned_rule:
                seen.add(cleaned_rule)
                result.append(cleaned_rule)
            else:
                duplicates += 1
                
        self._update_stats('duplicates', duplicates)
        return result

    # -------------------- 规则获取与解析 --------------------
    def _fetch_rules_from_source(self, source: Dict, target_behavior: str) -> List[Any]:
        rule_format = source.get('format', 'yaml')
        default_behavior = 'sing-box' if rule_format in ('json', 'srs') else 'classical'
        source_behavior = self._normalize_behavior(source.get('behavior', default_behavior))
        
        source_type = source.get('type')
        raw_rules = []
        
        if source_type == 'http':
            url = source.get('url', '')
            logger.info(f"开始下载: {url}")
            raw_rules = self._fetch_http_rules(url, rule_format, source_behavior)
        elif source_type == 'file':
            path = source.get('path', '')
            logger.info(f"读取本地: {path}")
            raw_rules = self._read_local_rules(path, rule_format, source_behavior)

        if not raw_rules:
            return []

        logger.info(f"转换中: {source.get('url', source.get('path'))} (获取 {len(raw_rules)} 条)")
        converted = []
        local_total, local_conv, local_drop = len(raw_rules), 0, 0
        
        for rule in raw_rules:
            if not rule:
                continue
            if isinstance(rule, str):
                rule = self._clean_rule(rule)
                if not rule:
                    continue
                if rule.startswith('*.'):
                    rule = '+.' + rule[2:]
            transformed = self._transform(rule, source_behavior, target_behavior)
            if not transformed:
                local_drop += 1
                continue
            converted.extend(transformed)
            local_conv += 1
            
        with self._stats_lock:
            self._stats['total'] += local_total
            self._stats['converted'] += local_conv
            self._stats['dropped'] += local_drop
            
        return converted

    def _fetch_http_rules(self, url: str, rule_format: str, behavior: str) -> List[Any]:
        try:
            resp = self.session.get(url, timeout=15)
            resp.raise_for_status()
            content = resp.text
            
            if rule_format == 'json':
                return self._parse_sing_box_source_to_list(content)
            if rule_format == 'srs':
                with self._temp_file('.srs') as tmp_srs:
                    with open(tmp_srs, 'wb') as f:
                        f.write(resp.content)
                    return self._parse_sing_box_source_to_list(self._decompile_srs_to_json_str(tmp_srs))
                    
            content_type = resp.headers.get('content-type', '')
            is_yaml = rule_format == 'yaml' or (
                rule_format not in ('mrs', 'text', 'json', 'srs') and
                ('yaml' in content_type or url.endswith(('.yml', '.yaml')))
            )
            if is_yaml:
                return self._extract_yaml_rules(yaml.safe_load(content))
                
            if rule_format == 'mrs':
                with self._temp_file('.mrs') as tmp_mrs:
                    with open(tmp_mrs, 'wb') as f:
                        f.write(resp.content)
                    return self._read_mrs_file(tmp_mrs, behavior)
                    
            return content.splitlines()

        except Exception as e:
            logger.error(f"网络异常，获取规则失败 {url}: {e}")
            return []

    def _read_local_rules(self, path: str, rule_format: str, behavior: str) -> List[Any]:
        try:
            if rule_format == 'mrs':
                return self._read_mrs_file(path, behavior)
            if rule_format == 'srs':
                return self._parse_sing_box_source_to_list(self._decompile_srs_to_json_str(path))
                
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                if rule_format == 'json':
                    return self._parse_sing_box_source_to_list(content)
                if rule_format == 'yaml':
                    return self._extract_yaml_rules(yaml.safe_load(content))
                return content.splitlines()
        except Exception as e:
            logger.error(f"读取本地规则失败 {path}: {e}")
            return []

    def _parse_sing_box_source_to_list(self, content: str) -> List[Dict[str, Any]]:
        if not content.strip(): return []
        try:
            data = json.loads(content.lstrip('\ufeff'))
            if isinstance(data, dict) and isinstance(data.get('rules'), list):
                return data['rules']
            return data if isinstance(data, list) else []
        except json.JSONDecodeError as e:
            logger.error(f"解析 sing-box JSON 失败: {e}")
            return []

    @staticmethod
    def _extract_yaml_rules(data: Any) -> List[str]:
        if isinstance(data, dict):
            payload = data.get('payload')
            return payload if isinstance(payload, list) else []
        return data if isinstance(data, list) else []

    # -------------------- 规则转换核心 --------------------
    def _transform(self, rule: Any, source_behavior: str, target_behavior: str) -> List[Any]:
        if isinstance(rule, dict):
            if target_behavior == 'sing-box': return [rule]
            transformer = self._transformers.get(('sing-box', target_behavior))
            if transformer:
                result = transformer(json.dumps(rule))
                return result if isinstance(result, list) else [result] if result else []
            return []

        if source_behavior == target_behavior: return [rule]
        
        if transformer := self._transformers.get((source_behavior, target_behavior)):
            result = transformer(rule)
            if result: return result if isinstance(result, list) else [result]
        return []

    # -------------------- 格式间转换器 --------------------
    def _classical_to_ipcidr(self, rule: str) -> Optional[str]:
        parts = rule.split(',', 1)
        if len(parts) == 2 and parts[0].strip() in ('IP-CIDR', 'IP-CIDR6'):
            return self._validate_ipcidr_rule(parts[1].strip())
        return None

    def _classical_to_domain(self, rule: str) -> Optional[str]:
        parts = rule.split(',', 1)
        if len(parts) == 2:
            prefix, domain = parts[0].strip(), parts[1].strip()
            if DOMAIN_PATTERN.match(domain):
                if prefix == 'DOMAIN': return domain
                if prefix == 'DOMAIN-SUFFIX': return '+.' + domain
        return None

    def _ipcidr_to_classical(self, rule: str) -> Optional[str]:
        v = self._get_ipcidr_version(rule)
        return f"IP-CIDR6,{rule}" if v == 6 else f"IP-CIDR,{rule}" if v == 4 else None

    def _domain_to_classical(self, rule: str) -> Optional[str]:
        if rule.startswith('+.'):
            domain = rule[2:]
            return f"DOMAIN-SUFFIX,{domain}" if DOMAIN_PATTERN.match(domain) else None
        return f"DOMAIN,{rule}" if DOMAIN_PATTERN.match(rule) else None

    def _classical_to_sing_box(self, rule: str) -> Optional[str]:
        if not self._validate_classical_rule(rule): return None
        parts = [p.strip() for p in rule.split(',', 1)]
        if len(parts) < 2: return None
        
        prefix, value = parts[0], parts[1]

        if prefix == 'DST-PORT':
            items = [x.strip() for x in value.split('/') if x.strip()]
            port_list, port_range_list = [], []
            for item in self._merge_port_items(items):
                if '-' in item: port_range_list.append(item.replace('-', ':'))
                else: port_list.append(int(item) if item.isdigit() else item)
            
            res = {}
            if port_list: res['port'] = port_list
            if port_range_list: res['port_range'] = port_range_list
            return json.dumps(res) if res else None

        item = self._to_sing_box_item(rule, 'classical')
        return json.dumps({item[0]: [item[1]]}) if item else None

    def _domain_to_sing_box(self, rule: str) -> Optional[str]:
        if not self._validate_domain_rule(rule): return None
        item = self._to_sing_box_item(rule, 'domain')
        return json.dumps({item[0]: [item[1]]}) if item else None

    def _ipcidr_to_sing_box(self, rule: str) -> Optional[str]:
        if not self._validate_ipcidr_rule(rule): return None
        item = self._to_sing_box_item(rule, 'ipcidr')
        return json.dumps({item[0]: [item[1]]}) if item else None

    def _to_sing_box_item(self, rule: str, behavior: str) -> Optional[tuple]:
        if behavior == 'domain':
            return ('domain_suffix', rule[2:]) if rule.startswith('+.') else ('domain', rule)
        if behavior == 'ipcidr':
            return ('ip_cidr', rule)
            
        parts = [p.strip() for p in rule.split(',', 1)]
        if len(parts) == 2 and (field := CLASSICAL_TO_SB.get(parts[0])):
            return (field, parts[1].lower() if field == 'network' else parts[1])
        return None

    def _parse_sing_box_rule(self, rule_str: str) -> Optional[Dict[str, Any]]:
        try: return json.loads(rule_str)
        except json.JSONDecodeError: return None

    def _iter_sing_box_rules(self, rule: Dict[str, Any]) -> List[Dict[str, Any]]:
        rules = [rule]
        if rule.get('type') == 'logical':
            for nested in self._as_list(rule.get('rules')):
                if isinstance(nested, dict):
                    rules.extend(self._iter_sing_box_rules(nested))
        return rules

    def _sing_box_to_domain(self, rule_str: str) -> List[str]:
        if not (parsed := self._parse_sing_box_rule(rule_str)): return []
        result = []
        for item in self._iter_sing_box_rules(parsed):
            result.extend(str(d) for d in self._as_list(item.get('domain')))
            result.extend(f"+.{s[1:] if s.startswith('.') else s}" for s in self._as_list(item.get('domain_suffix')))
        return result

    def _sing_box_to_ipcidr(self, rule_str: str) -> List[str]:
        if not (parsed := self._parse_sing_box_rule(rule_str)): return []
        return [str(ip) for item in self._iter_sing_box_rules(parsed) for ip in self._as_list(item.get('ip_cidr'))]

    def _sing_box_to_classical(self, rule_str: str) -> List[str]:
        if not (parsed := self._parse_sing_box_rule(rule_str)): return []
        result = []
        for item in self._iter_sing_box_rules(parsed):
            result.extend(f"DOMAIN,{d}" for d in self._as_list(item.get('domain')))
            result.extend(f"DOMAIN-SUFFIX,{s[1:] if s.startswith('.') else s}" for s in self._as_list(item.get('domain_suffix')))
            result.extend(f"DOMAIN-KEYWORD,{k}" for k in self._as_list(item.get('domain_keyword')))
            result.extend(f"DOMAIN-REGEX,{r}" for r in self._as_list(item.get('domain_regex')))
            result.extend(f"IP-CIDR6,{ip}" if ':' in str(ip) else f"IP-CIDR,{ip}" for ip in self._as_list(item.get('ip_cidr')))
            result.extend(f"NETWORK,{str(n).lower()}" for n in self._as_list(item.get('network')))

            port_items = [str(p) for p in self._as_list(item.get('port'))] + \
                         [str(pr).replace(':', '-') for pr in self._as_list(item.get('port_range'))]
            if port_items:
                result.append(f"DST-PORT,{"/".join(self._merge_port_items(port_items))}")
        return result

    def _validate_classical_rule(self, rule: str) -> Optional[str]:
        try:
            parts = [p.strip() for p in rule.split(',', 1)]
            if len(parts) < 2: return None
            prefix, value = parts[0], parts[1]
            
            if prefix in ('DOMAIN', 'DOMAIN-SUFFIX'): return rule if DOMAIN_PATTERN.match(value) else None
            if prefix in ('DOMAIN-KEYWORD', 'DOMAIN-REGEX'): return rule
            if prefix == 'IP-CIDR': return rule if self._get_ipcidr_version(value) == 4 else None
            if prefix == 'IP-CIDR6': return rule if self._get_ipcidr_version(value) == 6 else None
            if prefix == 'DST-PORT':
                return rule if all(PORT_PATTERN.match(p.strip()) for p in value.split('/') if p.strip()) else None
            if prefix == 'NETWORK': return rule if value.lower() in ('tcp', 'udp') else None
            return rule
        except Exception:
            return None

    # -------------------- 规则合并与输出 --------------------
    def merge_rules(self) -> None:
        for config in self.config:
            if 'upstream' not in config or not config.get('path'): continue

            target_format = config.get('format', 'yaml')
            target_behavior = self._normalize_behavior(config.get('behavior', 'sing-box' if target_format in ('json', 'srs') else 'classical'))

            self._stats = {'total': 0, 'converted': 0, 'dropped': 0, 'duplicates': 0}
            all_rules = []
            
            # 使用线程池并发获取并转换所有数据源
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = [executor.submit(self._fetch_rules_from_source, src, target_behavior) 
                           for src in config['upstream'].values()]
                for future in as_completed(futures):
                    all_rules.extend(future.result())

            logger.info(f"所有规则源下载完毕: 原始规则={self._stats['total']}, 转换={self._stats['converted']}, 丢弃={self._stats['dropped']}")
            logger.info("开始进行规则去重与合并...")

            if target_behavior == 'sing-box':
                dict_rules = []
                for r in all_rules:
                    if isinstance(r, dict): dict_rules.append(r)
                    elif isinstance(r, str) and (parsed := self._parse_sing_box_rule(r)): dict_rules.append(parsed)
                    else: self._update_stats('dropped')
                final_rules = self._compile_final_sing_box_list(dict_rules)
            else:
                final_rules = self._deduplicate_and_merge_classical([str(r) for r in all_rules if r is not None])

            logger.info(f"聚合完成！最终规则数={len(final_rules)}, 清理重复/冗余={self._stats['duplicates']}")
            
            self._write_rules(
                config['path'], final_rules, target_format, 
                target_behavior, config.get('version', SING_BOX_RULESET_VERSION)
            )

    def _deduplicate_and_merge_classical(self, rules: List[str]) -> List[str]:
        rule_buckets = {k: [] for k in ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX', 'IP-CIDR', 'DST-PORT', 'NETWORK', 'OTHER']}

        for rule in rules:
            prefix = rule.split(',')[0]
            if prefix in rule_buckets: rule_buckets[prefix].append(rule)
            elif prefix == 'IP-CIDR6': rule_buckets['IP-CIDR'].append(rule)
            else: rule_buckets['OTHER'].append(rule)

        exact_list = [r.split(',', 1)[1].strip() for r in rule_buckets['DOMAIN'] if ',' in r]
        suffix_list = [r.split(',', 1)[1].strip() for r in rule_buckets['DOMAIN-SUFFIX'] if ',' in r]

        final_exact, final_suffix = self._unified_domain_deduplication(exact_list, suffix_list)
        self._update_stats('duplicates', (len(exact_list) + len(suffix_list)) - (len(final_exact) + len(final_suffix)))

        def dedup_list(items):
            seen = set()
            res = []
            for item in items:
                sig = self._normalize_rule_signature(item)
                if sig not in seen:
                    seen.add(sig)
                    res.append(item)
                else: self._update_stats('duplicates')
            return res

        result = [f"DOMAIN,{d}" for d in final_exact] + [f"DOMAIN-SUFFIX,{d}" for d in final_suffix]
        result.extend(dedup_list(rule_buckets['DOMAIN-KEYWORD']))
        result.extend(dedup_list(rule_buckets['DOMAIN-REGEX']))
        result.extend(self._merge_ip_rules(rule_buckets['IP-CIDR']))
        
        if merged_port := self._merge_dst_port_rules(rule_buckets['DST-PORT']):
            result.append(merged_port)
            
        result.extend(dedup_list(rule_buckets['NETWORK']))
        result.extend(dedup_list(rule_buckets['OTHER']))
        return result

    def _merge_dst_port_rules(self, rules: List[str]) -> Optional[str]:
        all_items = []
        for rule in rules:
            if len(parts := rule.split(',', 1)) == 2:
                all_items.extend(x.strip() for x in parts[1].split('/') if x.strip())
        return f"DST-PORT,{"/".join(self._merge_port_items(all_items))}" if all_items else None

    def _compile_final_sing_box_list(self, rules: List[Dict]) -> List[Dict]:
        bucket = {k: [] for k in SING_BOX_LIST_FIELDS}
        passthrough = []

        for rule in rules:
            if self._can_compact_sing_box_rule(rule):
                for k in SING_BOX_LIST_FIELDS:
                    if k in rule:
                        raw = self._as_list(rule[k])
                        if k == 'port': bucket[k].extend(int(v) if str(v).isdigit() else v for v in raw)
                        elif k == 'network': bucket[k].extend(str(v).lower() for v in raw)
                        else: bucket[k].extend(raw)
            else: passthrough.append(rule)

        if bucket['domain'] or bucket['domain_suffix']:
            ex_len, suf_len = len(bucket['domain']), len(bucket['domain_suffix'])
            bucket['domain'], bucket['domain_suffix'] = self._unified_domain_deduplication(
                [str(d) for d in bucket['domain']], [str(s) for s in bucket['domain_suffix']]
            )
            self._update_stats('duplicates', (ex_len + suf_len) - (len(bucket['domain']) + len(bucket['domain_suffix'])))

        if bucket['ip_cidr']:
            unique_ips = list(dict.fromkeys(str(ip).strip() for ip in bucket['ip_cidr']))
            self._update_stats('duplicates', len(bucket['ip_cidr']) - len(unique_ips))
            bucket['ip_cidr'] = unique_ips

        if bucket['port'] or bucket['port_range']:
            merged = self._merge_port_items([str(p) for p in bucket['port']] + [str(pr).replace(':', '-') for pr in bucket['port_range']])
            bucket['port'], bucket['port_range'] = [], []
            for item in merged:
                if '-' in item: bucket['port_range'].append(item.replace('-', ':'))
                else: bucket['port'].append(int(item))

        compacted = []
        for k in SING_BOX_LIST_FIELDS:
            if vals := bucket.get(k):
                unique = list(set(vals))
                if k == 'port' and any(not str(v).isdigit() for v in unique): unique.sort(key=str)
                elif k == 'port': unique.sort()
                else: unique.sort(key=str)
                compacted.append({k: unique})

        seen_sigs, final = set(), []
        for r in compacted + passthrough:
            if (sig := self._normalize_rule_signature(r)) not in seen_sigs:
                seen_sigs.add(sig)
                final.append(r)
            else: self._update_stats('duplicates')
            
        return final

    def _can_compact_sing_box_rule(self, rule: Dict[str, Any]) -> bool:
        if rule.get('type') == 'logical': return False
        return all(k in SING_BOX_LIST_FIELDS and all(isinstance(v, (str, int)) for v in self._as_list(v)) for k, v in rule.items())

    def _write_rules(self, output_path: str, rules: List[Any], rule_format: str, behavior: str, version: int) -> None:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        if rule_format == 'mrs':
            with self._temp_file('.tmp') as tmp:
                self._write_rules(tmp, rules, 'text', behavior, version)
                if self._convert_to_binary(self.mihomo_path, ['convert-ruleset', behavior, 'text', tmp, output_path], 'MRS'):
                    logger.info(f"已生成 mrs 规则文件: {output_path}")
            return

        if rule_format == 'srs':
            with self._temp_file('.json') as tmp_json:
                self._write_sing_box_source_direct(tmp_json, rules, version)
                if self._convert_to_binary(self.sing_box_path, ['rule-set', 'compile', '--output', output_path, tmp_json], 'SRS'):
                    logger.info(f"已生成 srs 规则文件: {output_path}")
            return

        if rule_format == 'json':
            self._write_sing_box_source_direct(output_path, rules, version)
        else:
            with open(output_path, 'w', encoding='utf-8') as f:
                if not output_path.endswith('.tmp'):
                    f.write(f"# Update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Total: {len(rules)}\n")
                if rule_format == 'yaml':
                    yaml.dump({'payload': rules}, f, allow_unicode=True, sort_keys=False)
                else:
                    f.write('\n'.join(str(r) for r in rules) + '\n')
                    
        logger.info(f"已生成 {rule_format} 规则文件: {output_path}, 共 {len(rules)} 条")

    def _write_sing_box_source_direct(self, output_path: str, rules: List[Dict], version: int) -> None:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump({'version': version, 'rules': rules}, f, ensure_ascii=False, indent=2)

    # -------------------- 二进制格式支持 --------------------
    def _read_mrs_file(self, input_path: str, behavior: str) -> List[str]:
        if not self.mihomo_path: return []
        with self._temp_file('.txt') as tmp:
            cmd = [self.mihomo_path, 'convert-ruleset', behavior, 'mrs', input_path, tmp]
            if subprocess.run(cmd, capture_output=True, timeout=60).returncode == 0:
                with open(tmp, 'r', encoding='utf-8') as f: return f.read().splitlines()
        return []

    def _decompile_srs_to_json_str(self, input_path: str) -> str:
        if not self.sing_box_path: return "{}"
        with self._temp_file('.json') as tmp:
            cmd = [self.sing_box_path, 'rule-set', 'decompile', '--output', tmp, input_path]
            if subprocess.run(cmd, capture_output=True, timeout=60).returncode == 0:
                with open(tmp, 'r', encoding='utf-8') as f: return f.read()
        return "{}"

    def _convert_to_binary(self, bin_path: str, args: List[str], name: str) -> bool:
        if not bin_path:
            logger.error(f"未配置工具路径，无法编译 {name}")
            return False
        res = subprocess.run([bin_path] + args, capture_output=True, text=True, timeout=60)
        if res.returncode != 0:
            logger.error(f"编译 {name} 失败: {res.stderr}")
            return False
        return True


def main():
    # max_workers = 10，代表允许同时拉取 10 个数据源。可根据网络环境调整。
    merger = RulesMerger('config.yaml', max_workers=10)
    merger.merge_rules()


if __name__ == '__main__':
    main()
