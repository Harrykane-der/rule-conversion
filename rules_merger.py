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
from functools import lru_cache
from typing import List, Dict, Optional, Any, Tuple, Union
from contextlib import contextmanager
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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

        self.session = requests.Session()
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        self.session.mount('http://', HTTPAdapter(max_retries=retries))
        self.session.mount('https://', HTTPAdapter(max_retries=retries))

        # ==================== 修改：输出目录改为 rules ====================
        self.output_dir = "rules"
        os.makedirs(self.output_dir, exist_ok=True)

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
    def _clean_json_text(text: str) -> str:
        """移除 UTF-8 BOM 头、单行 // 注释和多行 /* */ 注释"""
        if not text:
            return ""
        text = text.lstrip('\ufeff')
        pattern = re.compile(
            r'//.*?$|/\*.*?\*/|"(?:\\.|[^\\"])*"',
            re.DOTALL | re.MULTILINE
        )
        def replace(match):
            s = match.group(0)
            return '' if s.startswith('/') else s
        return pattern.sub(replace, text)

    @staticmethod
    @lru_cache(maxsize=65536)
    def _parse_ip_network(rule: str) -> Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        if not rule or not isinstance(rule, str):
            return None
        s = rule.strip()
        if not s:
            return None
        if ',' in s:
            parts = [p.strip() for p in s.split(',')]
            if parts[0].upper() in ('IP-CIDR', 'IP-CIDR6'):
                s = parts[1] if len(parts) > 1 else ''
            else:
                s = parts[0]
        if not s:
            return None
        try:
            return ipaddress.ip_network(s, strict=False)
        except ValueError:
            return None

    @classmethod
    def _get_ipcidr_version(cls, rule: str) -> Optional[int]:
        net = cls._parse_ip_network(rule)
        return net.version if net else None

    def _validate_ipcidr_rule(self, rule: str) -> Optional[str]:
        net = self._parse_ip_network(rule)
        return net.with_prefixlen if net else None

    def _validate_domain_rule(self, rule: str) -> Optional[str]:
        domain = rule[2:] if rule.startswith('+.') else rule
        return rule if DOMAIN_PATTERN.match(domain) else None

    def _validate_classical_rule(self, rule: str) -> Optional[str]:
        try:
            parts = [p.strip() for p in rule.split(',')]
            if not parts or not parts[0]:
                return None
            prefix = parts[0].upper()

            if prefix in ('DOMAIN', 'DOMAIN-SUFFIX'):
                return rule if len(parts) >= 2 and DOMAIN_PATTERN.match(parts[1]) else None
            if prefix in ('DOMAIN-KEYWORD', 'DOMAIN-REGEX'):
                return rule if len(parts) >= 2 else None
            if prefix == 'IP-CIDR':
                return rule if len(parts) >= 2 and self._get_ipcidr_version(parts[1]) == 4 else None
            if prefix == 'IP-CIDR6':
                return rule if len(parts) >= 2 and self._get_ipcidr_version(parts[1]) == 6 else None
            if prefix == 'DST-PORT':
                return rule if len(parts) >= 2 and all(PORT_PATTERN.match(p.strip()) for p in parts[1].split('/') if p.strip()) else None
            if prefix == 'NETWORK':
                return rule if len(parts) >= 2 and parts[1].lower() in ('tcp', 'udp') else None

            if self._parse_ip_network(parts[0]) is not None:
                return rule

            return None
        except Exception:
            return None

    def _normalize_rule_signature(self, rule: Any) -> str:
        if isinstance(rule, dict):
            canon = {}
            for k, v in rule.items():
                vals = self._as_list(v)
                if k in ('domain', 'domain_suffix'):
                    canon[k] = sorted({str(x).lower().strip('.') for x in vals})
                elif k in ('domain_keyword', 'domain_regex'):
                    canon[k] = sorted(set(str(x) for x in vals))
                elif k == 'ip_cidr':
                    norms = []
                    for ip in vals:
                        if net := self._parse_ip_network(str(ip)):
                            norms.append(net.with_prefixlen)
                        else:
                            norms.append(str(ip).strip())
                    canon[k] = sorted(set(norms))
                elif k == 'network':
                    canon[k] = sorted({str(x).lower() for x in vals})
                elif k in ('port', 'port_range'):
                    canon[k] = sorted(vals, key=str)
                else:
                    canon[k] = v
            return json.dumps(canon, ensure_ascii=False, sort_keys=True)

        if isinstance(rule, str):
            s = rule.strip().lower()
            if s.startswith('ip-cidr6,'):
                s = 'ip-cidr,' + s[9:]
            if s.startswith('domain-suffix,.'):
                s = 'domain-suffix,' + s[15:]

            if ',' in s:
                parts = [p.strip() for p in s.split(',')]
                prefix = parts[0]
                value = parts[1] if len(parts) > 1 else ''
                value_clean = value.strip().strip('.')
                if prefix in ('domain', 'domain-suffix', 'domain-keyword', 'domain-regex'):
                    s = f"{prefix},{value_clean}"
                elif prefix in ('ip-cidr', 'ip-cidr6'):
                    if net := self._parse_ip_network(value):
                        s = f"ip-cidr,{net.with_prefixlen}"
                elif prefix == 'network':
                    s = f"network,{value_clean.lower()}"
            else:
                if net := self._parse_ip_network(s):
                    s = f"ip-cidr,{net.with_prefixlen}"
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

    @staticmethod
    def _wildcard_to_domain_regex(domain: str) -> Optional[str]:
        if not domain:
            return None
        d = domain.strip()
        if d.startswith('+.'):
            d = d[2:]
        elif d.startswith('.'):
            d = d[1:]
        d = d.strip('.')
        if not d or d == '*':
            return None

        parts = d.split('*')
        body = '.*'.join(re.escape(part) for part in parts)
        return f"(^|\\.){body}$"

    def _unified_domain_deduplication(
        self, exact_domains: List[str], suffix_domains: List[str]
    ) -> Tuple[List[str], List[str]]:
        domain_types: Dict[str, int] = {}
        for d in exact_domains:
            if d_str := str(d).strip().lower().strip('.'):
                if '*' not in d_str:
                    domain_types[d_str] = 0
        for d in suffix_domains:
            if d_str := str(d).strip().lower().strip('.'):
                if '*' not in d_str:
                    domain_types[d_str] = 1
        if not domain_types:
            return [], []
        reversed_list = sorted((tuple(d.split('.'))[::-1], d) for d in domain_types)
        result_domains: List[str] = []
        last_parent: Optional[Tuple[str, ...]] = None
        last_len = 0
        for labels, original in reversed_list:
            if last_parent and len(labels) > last_len and labels[:last_len] == last_parent:
                parent_str = '.'.join(last_parent[::-1])
                domain_types[parent_str] = 1
                continue
            result_domains.append(original)
            last_parent = labels
            last_len = len(labels)
        final_exact, final_suffix = [], []
        for d in result_domains:
            if domain_types[d] == 1:
                final_suffix.append(d)
            else:
                final_exact.append(d)
        return final_exact, final_suffix

    def _merge_ip_rules(self, rules: List[str]) -> List[str]:
        v4: List[ipaddress.IPv4Network] = []
        v6: List[ipaddress.IPv6Network] = []
        other: List[str] = []
        seen_raw = set()
        for rule in rules:
            cleaned = rule.strip()
            if not cleaned:
                continue
            sig = self._normalize_rule_signature(cleaned)
            if sig in seen_raw:
                continue
            seen_raw.add(sig)

            if net := self._parse_ip_network(cleaned):
                (v4 if net.version == 4 else v6).append(net)
            else:
                other.append(cleaned)

        def prune(networks: list) -> list:
            if not networks:
                return []
            networks.sort(key=lambda n: (n.prefixlen, int(n.network_address)))
            kept = []
            for net in networks:
                if not any(net.subnet_of(k) for k in kept):
                    kept.append(net)
            return kept

        result = [f"IP-CIDR,{net.with_prefixlen}" for net in prune(v4)]
        result.extend(f"IP-CIDR6,{net.with_prefixlen}" for net in prune(v6))
        result.extend(other)
        return result

    # -------------------- 规则获取与解析 --------------------
    def _fetch_source(self, source: Dict) -> Tuple[List[Any], str, str]:
        rule_format = source.get('format', 'yaml')
        default_behavior = 'sing-box' if rule_format in ('json', 'srs') else 'classical'
        behavior = self._normalize_behavior(source.get('behavior', default_behavior))
        label = source.get('url') or source.get('path') or 'unknown'
        stype = source.get('type')

        content_bytes = b''
        try:
            if stype == 'http':
                url = source.get('url', '')
                logger.info(f"下载源: {url}")
                resp = self.session.get(url, timeout=15)
                resp.raise_for_status()
                content_bytes = resp.content
            elif stype == 'file':
                path = source.get('path', '')
                logger.info(f"读取本地源: {path}")
                with open(path, 'rb') as f:
                    content_bytes = f.read()

            raw_rules = self._parse_source_content(content_bytes, rule_format, behavior)
            logger.info(f"源读取完成: {label} → {len(raw_rules)} 条规则")
            return raw_rules, behavior, label
        except Exception as e:
            logger.error(f"获取源失败 {label}: {e}")
            return [], behavior, label

    def _parse_source_content(self, content_bytes: bytes, rule_format: str, behavior: str) -> List[Any]:
        if not content_bytes:
            return []

        if rule_format == 'srs':
            with self._temp_file('.srs') as tmp_srs:
                with open(tmp_srs, 'wb') as f:
                    f.write(content_bytes)
                return self._parse_sing_box_source_to_list(self._decompile_srs_to_json_str(tmp_srs))
        if rule_format == 'mrs':
            with self._temp_file('.mrs') as tmp_mrs:
                with open(tmp_mrs, 'wb') as f:
                    f.write(content_bytes)
                return self._read_mrs_file(tmp_mrs, behavior)

        text = content_bytes.decode('utf-8', errors='ignore')
        if rule_format == 'json':
            return self._parse_sing_box_source_to_list(text)
        if rule_format == 'yaml':
            return self._extract_yaml_rules(yaml.safe_load(text))

        if 'payload:' in text[:200]:
            return self._extract_yaml_rules(yaml.safe_load(text))
        return text.splitlines()

    def _parse_sing_box_source_to_list(self, content: str) -> List[Any]:
        if not content or not content.strip():
            return []
        
        cleaned_text = self._clean_json_text(content)
        try:
            data = json.loads(cleaned_text)
            if isinstance(data, dict):
                if 'rules' in data and isinstance(data['rules'], list):
                    return data['rules']
                if 'payload' in data and isinstance(data['payload'], list):
                    return data['payload']
                return [data]
            elif isinstance(data, list):
                return data
            return []
        except json.JSONDecodeError as e:
            logger.error(f"解析 JSON 规则源失败: {e}")
            return []

    @staticmethod
    def _extract_yaml_rules(data: Any) -> List[str]:
        if isinstance(data, dict):
            payload = data.get('payload')
            return payload if isinstance(payload, list) else []
        return data if isinstance(data, list) else []

    # -------------------- 格式转换引擎 --------------------
    def _transform(self, rule: Any, source_behavior: str, target_behavior: str) -> List[Any]:
        if isinstance(rule, dict):
            if target_behavior == 'sing-box':
                return [rule]
            transformer = self._transformers.get(('sing-box', target_behavior))
            if transformer:
                result = transformer(rule)
                return result if isinstance(result, list) else [result] if result else []
            return []

        if source_behavior == target_behavior:
            return [rule]

        if transformer := self._transformers.get((source_behavior, target_behavior)):
            result = transformer(rule)
            if result:
                return result if isinstance(result, list) else [result]
        return []

    def _classical_to_ipcidr(self, rule: str) -> Optional[str]:
        return self._validate_ipcidr_rule(rule)

    def _classical_to_domain(self, rule: str) -> Optional[str]:
        parts = rule.split(',', 1)
        if len(parts) == 2:
            prefix, domain = parts[0].strip(), parts[1].strip()
            if DOMAIN_PATTERN.match(domain):
                if prefix == 'DOMAIN':
                    return '+.' + domain.lstrip('.') if domain.startswith('.') else domain
                if prefix == 'DOMAIN-SUFFIX':
                    return '+.' + domain.lstrip('.')
        return None

    def _ipcidr_to_classical(self, rule: str) -> Optional[str]:
        if net := self._parse_ip_network(rule):
            prefix = "IP-CIDR6" if net.version == 6 else "IP-CIDR"
            return f"{prefix},{net.with_prefixlen}"
        return None

    def _domain_to_classical(self, rule: str) -> Optional[str]:
        if rule.startswith(('+.', '.')):
            domain = rule.lstrip('+.')
            return f"DOMAIN-SUFFIX,{domain}" if DOMAIN_PATTERN.match(domain) else None
        return f"DOMAIN,{rule}" if DOMAIN_PATTERN.match(rule) else None

    def _classical_to_sing_box(self, rule: str) -> Optional[str]:
        item = None
        if not self._validate_classical_rule(rule):
            return None
        parts = [p.strip() for p in rule.split(',')]
        if not parts or not parts[0]:
            return None
        prefix = parts[0].upper()

        if prefix == 'DST-PORT' and len(parts) >= 2:
            value = parts[1]
            items = [x.strip() for x in value.split('/') if x.strip()]
            port_list, port_range_list = [], []
            for p_item in self._merge_port_items(items):
                if '-' in p_item:
                    port_range_list.append(p_item.replace('-', ':'))
                else:
                    port_list.append(int(p_item) if p_item.isdigit() else p_item)
            res = {}
            if port_list:
                res['port'] = port_list
            if port_range_list:
                res['port_range'] = port_range_list
            return json.dumps(res) if res else None

        item = self._to_sing_box_item(rule, 'classical')
        if item and isinstance(item, tuple) and len(item) == 2 and item[0] and item[1]:
            return json.dumps({item[0]: [item[1]]})
        return None

    def _domain_to_sing_box(self, rule: str) -> Optional[str]:
        item = None
        if not self._validate_domain_rule(rule):
            return None
        item = self._to_sing_box_item(rule, 'domain')
        if item and isinstance(item, tuple) and len(item) == 2 and item[0] and item[1]:
            return json.dumps({item[0]: [item[1]]})
        return None

    def _ipcidr_to_sing_box(self, rule: str) -> Optional[str]:
        item = None
        if not self._validate_ipcidr_rule(rule):
            return None
        item = self._to_sing_box_item(rule, 'ipcidr')
        if item and isinstance(item, tuple) and len(item) == 2 and item[0] and item[1]:
            return json.dumps({item[0]: [item[1]]})
        return None

    def _to_sing_box_item(self, rule: str, behavior: str) -> Optional[tuple]:
        item = None
        if not rule or not isinstance(rule, str):
            return None

        rule_str = rule.strip()
        if not rule_str:
            return None

        try:
            if behavior == 'domain':
                if '*' in rule_str:
                    if regex := self._wildcard_to_domain_regex(rule_str):
                        item = ('domain_regex', regex)
                elif rule_str.startswith(('+.', '.')):
                    item = ('domain_suffix', rule_str.lstrip('+.'))
                else:
                    item = ('domain', rule_str)

            elif behavior == 'ipcidr':
                if net := self._parse_ip_network(rule_str):
                    item = ('ip_cidr', net.with_prefixlen)

            else:  # classical
                parts = [p.strip() for p in rule_str.split(',')]
                if parts and parts[0]:
                    prefix = parts[0].upper()
                    if field := CLASSICAL_TO_SB.get(prefix):
                        if len(parts) >= 2:
                            value = parts[1]
                            if field == 'ip_cidr':
                                if net := self._parse_ip_network(value):
                                    item = ('ip_cidr', net.with_prefixlen)
                            elif field in ('domain_keyword', 'domain_regex'):
                                item = (field, value)
                            elif field in ('domain', 'domain_suffix'):
                                if '*' in value:
                                    domain_for_regex = value if field == 'domain' else f"+.{value}"
                                    if regex := self._wildcard_to_domain_regex(domain_for_regex):
                                        item = ('domain_regex', regex)
                                elif value.startswith('.'):
                                    item = ('domain_suffix', value.lstrip('.'))
                                else:
                                    item = (field, value)
                            elif field == 'network':
                                item = (field, value.lower())
                    elif net := self._parse_ip_network(parts[0]):
                        item = ('ip_cidr', net.with_prefixlen)

        except Exception as e:
            logger.debug(f"解析规则条目异常 [{rule}]: {e}")
            item = None

        return item

    def _parse_sing_box_rule(self, rule_input: Any) -> Optional[Dict[str, Any]]:
        if isinstance(rule_input, dict):
            return rule_input
        if isinstance(rule_input, str):
            cleaned = self._clean_json_text(rule_input)
            try:
                res = json.loads(cleaned)
                return res if isinstance(res, dict) else None
            except json.JSONDecodeError:
                return None
        return None

    def _iter_sing_box_rules(self, rule: Any) -> List[Dict[str, Any]]:
        parsed = self._parse_sing_box_rule(rule)
        if not parsed:
            return []

        rules = [parsed]
        if parsed.get('type') == 'logical':
            for nested in self._as_list(parsed.get('rules')):
                rules.extend(self._iter_sing_box_rules(nested))
        return rules

    def _sing_box_to_domain(self, rule: Union[Dict, str]) -> List[str]:
        result = []
        for item in self._iter_sing_box_rules(rule):
            result.extend(str(d) for d in self._as_list(item.get('domain')))
            result.extend(f"+.{str(s).lstrip('.')}" for s in self._as_list(item.get('domain_suffix')))
        return result

    def _sing_box_to_ipcidr(self, rule: Union[Dict, str]) -> List[str]:
        res = []
        for item in self._iter_sing_box_rules(rule):
            for ip in self._as_list(item.get('ip_cidr')):
                if net := self._parse_ip_network(str(ip)):
                    res.append(net.with_prefixlen)
        return res

    def _sing_box_to_classical(self, rule: Union[Dict, str]) -> List[str]:
        result = []
        for item in self._iter_sing_box_rules(rule):
            result.extend(f"DOMAIN,{d}" for d in self._as_list(item.get('domain')))
            result.extend(f"DOMAIN-SUFFIX,{str(s).lstrip('.')}" for s in self._as_list(item.get('domain_suffix')))
            result.extend(f"DOMAIN-KEYWORD,{k}" for k in self._as_list(item.get('domain_keyword')))
            result.extend(f"DOMAIN-REGEX,{r}" for r in self._as_list(item.get('domain_regex')))
            for ip in self._as_list(item.get('ip_cidr')):
                if net := self._parse_ip_network(str(ip)):
                    prefix = "IP-CIDR6" if net.version == 6 else "IP-CIDR"
                    result.append(f"{prefix},{net.with_prefixlen}")
            result.extend(f"NETWORK,{str(n).lower()}" for n in self._as_list(item.get('network')))

            port_items = [str(p) for p in self._as_list(item.get('port'))] + \
                         [str(pr).replace(':', '-') for pr in self._as_list(item.get('port_range'))]
            if port_items:
                result.append(f"DST-PORT,{'/'.join(self._merge_port_items(port_items))}")
        return result

    # -------------------- 调度流程 --------------------
    def merge_rules(self) -> None:
        configs = [
            cfg for cfg in self.config
            if isinstance(cfg, dict) and 'upstream' in cfg and cfg.get('path')
        ]
        if not configs:
            logger.warning("没有有效的规则集配置")
            return

        unique_sources: Dict[Tuple, Dict] = {}
        for cfg in configs:
            for src in cfg['upstream'].values():
                key = (
                    src.get('url') or src.get('path'),
                    src.get('format', 'yaml'),
                    self._normalize_behavior(src.get('behavior'))
                )
                if key[0] and key not in unique_sources:
                    unique_sources[key] = src

        logger.info(f"共 {len(configs)} 个规则集, {len(unique_sources)} 个唯一源，开始并行获取数据源...")

        source_cache: Dict[Tuple, Tuple[List[Any], str, str]] = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_key = {
                executor.submit(self._fetch_source, src): key
                for key, src in unique_sources.items()
            }
            for future in as_completed(future_to_key):
                key = future_to_key[future]
                try:
                    source_cache[key] = future.result()
                except Exception as e:
                    logger.error(f"获取源失败 {key}: {e}")
                    source_cache[key] = ([], 'classical', str(key[0]))

        logger.info("所有数据源获取完成，开始处理规则集...")
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [
                executor.submit(self._process_one_ruleset, cfg, source_cache)
                for cfg in configs
            ]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"规则集处理抛出未捕获的异常: {e}")

        logger.info("全部规则集处理完毕。")

    def _process_one_ruleset(self, cfg: Dict, source_cache: Dict) -> None:
        path = cfg['path']
        target_format = cfg.get('format', 'yaml')
        target_behavior = self._normalize_behavior(
            cfg.get('behavior', 'sing-box' if target_format in ('json', 'srs') else 'classical')
        )
        version = cfg.get('version', SING_BOX_RULESET_VERSION)
        sources = cfg['upstream'].values()

        try:
            all_converted = []
            total_raw, dropped_count = 0, 0

            for src in sources:
                key = (
                    src.get('url') or src.get('path'),
                    src.get('format', 'yaml'),
                    self._normalize_behavior(src.get('behavior'))
                )
                raw_rules, src_behavior, label = source_cache.get(key, ([], 'classical', ''))
                total_raw += len(raw_rules)

                for rule in raw_rules:
                    if not rule:
                        continue
                    if isinstance(rule, str):
                        rule = self._clean_rule(rule)
                        if not rule or rule in ('*', '+.*', '.*', '+.', '.'):
                            dropped_count += 1
                            continue
                        if rule.startswith('*.'):
                            rule = '+.' + rule[2:]
                        elif rule.startswith('.'):
                            rule = '+.' + rule[1:]

                    transformed = self._transform(rule, src_behavior, target_behavior)
                    if transformed:
                        all_converted.extend(transformed)
                    else:
                        dropped_count += 1

            logger.info(f"[{path}] 转换完成: 原始 {total_raw} 条 -> 有效 {len(all_converted)} 条, 丢弃 {dropped_count} 条")

            if target_behavior == 'sing-box':
                dict_rules = []
                for r in all_converted:
                    if isinstance(r, dict):
                        dict_rules.append(r)
                    elif isinstance(r, str) and (parsed := self._parse_sing_box_rule(r)):
                        dict_rules.append(parsed)
                final_rules = self._compile_final_sing_box_list(dict_rules)
            else:
                final_rules = self._deduplicate_and_merge_classical(
                    [str(r) for r in all_converted if r is not None],
                    target_behavior=target_behavior
                )

            logger.info(f"[{path}] 聚合去重完成，最终规则数={len(final_rules)}，正在验证并写入...")

            # ==================== 修改：写入 rules 目录 ====================
            full_output_path = os.path.join(self.output_dir, os.path.basename(path))
            self._write_rules(full_output_path, final_rules, target_format, target_behavior, version)

        except Exception as e:
            logger.error(f"[{path}] ❌ 规则集生成失败: {e}")

    def _deduplicate_and_merge_classical(self, rules: List[str], target_behavior: str = 'classical') -> List[str]:
        buckets = {
            'DOMAIN': [], 'DOMAIN-SUFFIX': [], 'DOMAIN-KEYWORD': [],
            'DOMAIN-REGEX': [], 'IP-CIDR': [], 'DST-PORT': [],
            'NETWORK': [], 'OTHER': []
        }
        for rule in rules:
            if not rule:
                continue
            prefix = rule.split(',', 1)[0].strip().upper()
            if prefix in buckets:
                buckets[prefix].append(rule)
            elif prefix == 'IP-CIDR6':
                buckets['IP-CIDR'].append(rule)
            elif self._parse_ip_network(rule) is not None:
                buckets['IP-CIDR'].append(rule)
            else:
                buckets['OTHER'].append(rule)

        exact = [r.split(',', 1)[1].strip() for r in buckets['DOMAIN'] if ',' in r]
        suffix = [r.split(',', 1)[1].strip() for r in buckets['DOMAIN-SUFFIX'] if ',' in r]
        final_exact, final_suffix = self._unified_domain_deduplication(exact, suffix)

        def simple_dedup(items: List[str]) -> List[str]:
            seen = set()
            res = []
            for item in items:
                sig = self._normalize_rule_signature(item)
                if sig not in seen:
                    seen.add(sig)
                    res.append(item)
            return res

        merged_ip = self._merge_ip_rules(buckets['IP-CIDR'])
        if target_behavior == 'ipcidr':
            clean_ips = []
            for r in merged_ip:
                if net := self._parse_ip_network(r):
                    clean_ips.append(net.with_prefixlen)
                else:
                    clean_ips.append(r)
            return clean_ips

        result = (
            [f"DOMAIN,{d}" for d in final_exact]
            + [f"DOMAIN-SUFFIX,{d}" for d in final_suffix]
            + simple_dedup(buckets['DOMAIN-KEYWORD'])
            + simple_dedup(buckets['DOMAIN-REGEX'])
            + merged_ip
        )

        if merged_port := self._merge_dst_port_rules(buckets['DST-PORT']):
            result.append(merged_port)

        result.extend(simple_dedup(buckets['NETWORK']))
        result.extend(simple_dedup(buckets['OTHER']))
        return result

    def _merge_dst_port_rules(self, rules: List[str]) -> Optional[str]:
        all_items = []
        for rule in rules:
            if len(parts := rule.split(',', 1)) == 2:
                all_items.extend(x.strip() for x in parts[1].split('/') if x.strip())
        return f"DST-PORT,{'/'.join(self._merge_port_items(all_items))}" if all_items else None

    def _compile_final_sing_box_list(self, rules: List[Dict]) -> List[Dict]:
        bucket = {k: [] for k in SING_BOX_LIST_FIELDS}
        passthrough = []

        for rule in rules:
            if self._can_compact_sing_box_rule(rule):
                for k in SING_BOX_LIST_FIELDS:
                    if k in rule:
                        raw = self._as_list(rule[k])
                        if k == 'port':
                            bucket[k].extend(int(v) if str(v).isdigit() else v for v in raw)
                        elif k == 'network':
                            bucket[k].extend(str(v).lower() for v in raw)
                        elif k in ('domain', 'domain_suffix'):
                            bucket[k].extend(str(v).lower().strip('.') for v in raw)
                        elif k in ('domain_keyword', 'domain_regex'):
                            bucket[k].extend(str(v) for v in raw)
                        else:
                            bucket[k].extend(raw)
            else:
                passthrough.append(rule)

        if bucket['domain'] or bucket['domain_suffix']:
            bucket['domain'], bucket['domain_suffix'] = self._unified_domain_deduplication(
                [str(d) for d in bucket['domain']],
                [str(s) for s in bucket['domain_suffix']]
            )

        for key in ('domain', 'domain_suffix'):
            remaining = []
            for item in bucket[key]:
                s = str(item)
                if '*' in s:
                    original = s if key == 'domain' else f"+.{s}"
                    if regex := self._wildcard_to_domain_regex(original):
                        bucket['domain_regex'].append(regex)
                        continue
                remaining.append(item)
            bucket[key] = remaining

        if bucket['domain_regex']:
            seen = set()
            unique_regex = []
            for r in bucket['domain_regex']:
                nr = str(r).strip()
                if nr not in seen:
                    seen.add(nr)
                    unique_regex.append(r)
            bucket['domain_regex'] = unique_regex

        if bucket['ip_cidr']:
            v4, v6 = [], []
            for ip in bucket['ip_cidr']:
                if net := self._parse_ip_network(str(ip)):
                    (v4 if net.version == 4 else v6).append(net)

            def prune(nets):
                if not nets:
                    return []
                nets.sort(key=lambda n: (n.prefixlen, int(n.network_address)))
                kept = []
                for n in nets:
                    if not any(n.subnet_of(k) for k in kept):
                        kept.append(n)
                return [str(n.with_prefixlen) for n in kept]

            bucket['ip_cidr'] = prune(v4) + prune(v6)

        if bucket['port'] or bucket['port_range']:
            merged = self._merge_port_items(
                [str(p) for p in bucket['port']]
                + [str(pr).replace(':', '-') for pr in bucket['port_range']]
            )
            bucket['port'], bucket['port_range'] = [], []
            for item in merged:
                if '-' in item:
                    bucket['port_range'].append(item.replace('-', ':'))
                else:
                    bucket['port'].append(int(item))

        compacted = []
        for k in SING_BOX_LIST_FIELDS:
            if vals := bucket.get(k):
                unique = list(dict.fromkeys(vals))
                unique = sorted(unique) if k == 'port' else sorted(unique, key=str)
                compacted.append({k: unique})

        seen_sigs, final = set(), []
        for r in compacted + passthrough:
            sig = self._normalize_rule_signature(r)
            if sig not in seen_sigs:
                seen_sigs.add(sig)
                final.append(r)
        return final

    def _can_compact_sing_box_rule(self, rule: Dict[str, Any]) -> bool:
        if rule.get('type') == 'logical':
            return False
        return all(k in SING_BOX_LIST_FIELDS and all(isinstance(v, (str, int)) for v in self._as_list(v)) for k, v in rule.items())

    # -------------------- 特性 1: 规则集有效性校验 --------------------
    def _validate_generated_rules(self, tmp_file: str, rule_format: str, behavior: str) -> bool:
        """在写入磁盘前，对新编译/生成的临时规则文件进行完备校验"""
        if not os.path.exists(tmp_file) or os.path.getsize(tmp_file) == 0:
            logger.error(f"校验失败: 临时文件不存在或大小为0 bytes [{tmp_file}]")
            return False
        try:
            if rule_format == 'mrs':
                read_back = self._read_mrs_file(tmp_file, behavior)
                return len(read_back) > 0
            elif rule_format == 'srs':
                json_str = self._decompile_srs_to_json_str(tmp_file)
                parsed = json.loads(self._clean_json_text(json_str))
                return isinstance(parsed, dict) and ('rules' in parsed or 'payload' in parsed)
            elif rule_format == 'json':
                with open(tmp_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                return isinstance(data, dict) and 'rules' in data
            elif rule_format == 'yaml':
                with open(tmp_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                return isinstance(data, dict) and 'payload' in data
            else:  # text / classical / domain / ipcidr
                with open(tmp_file, 'r', encoding='utf-8') as f:
                    valid_lines = [l for l in f if l.strip() and not l.startswith('#')]
                return len(valid_lines) > 0
        except Exception as e:
            logger.error(f"生成的规则集校验抛出异常 [{tmp_file}]: {e}")
            return False

    def _prepare_rules_for_mrs(self, rules: List[Any], behavior: str) -> List[str]:
        cleaned = []
        for r in rules:
            if not r:
                continue
            s = str(r).strip()
            if not s or s.startswith('#'):
                continue

            if behavior == 'ipcidr':
                if net := self._parse_ip_network(s):
                    cleaned.append(net.with_prefixlen)
            elif behavior == 'domain':
                if ',' in s:
                    parts = [p.strip() for p in s.split(',', 1)]
                    prefix = parts[0].upper()
                    if prefix in ('DOMAIN', 'DOMAIN-SUFFIX'):
                        dom = parts[1].lstrip('.')
                        cleaned.append(f"+.{dom}" if prefix == 'DOMAIN-SUFFIX' else dom)
                else:
                    cleaned.append(s)
            else:  # classical
                cleaned.append(s)

        return list(dict.fromkeys(cleaned))

    # -------------------- 特性 2: 全格式原子替换 --------------------
    def _write_rules(self, output_path: str, rules: List[Any], rule_format: str, behavior: str, version: int) -> None:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # 临时文件写入相同目录，以便原子替换
        with self._temp_file(f'.{rule_format}') as tmp_out:
            success = False
            if rule_format == 'mrs':
                mrs_rules = self._prepare_rules_for_mrs(rules, behavior)
                if not mrs_rules:
                    logger.error(f"[{output_path}] 没有可用于 MRS 编译的有效规则，取消写盘")
                    return
                with self._temp_file('.txt') as tmp_txt:
                    with open(tmp_txt, 'w', encoding='utf-8') as f:
                        f.write('\n'.join(mrs_rules) + '\n')
                    success = self._convert_to_binary(
                        self.mihomo_path,
                        ['convert-ruleset', behavior, 'text', tmp_txt, tmp_out],
                        'MRS'
                    )
            elif rule_format == 'srs':
                with self._temp_file('.json') as tmp_json:
                    with open(tmp_json, 'w', encoding='utf-8') as f:
                        json.dump({'version': version, 'rules': rules}, f, ensure_ascii=False, indent=2)
                    success = self._convert_to_binary(
                        self.sing_box_path,
                        ['rule-set', 'compile', '--output', tmp_out, tmp_json],
                        'SRS'
                    )
            elif rule_format == 'json':
                with open(tmp_out, 'w', encoding='utf-8') as f:
                    json.dump({'version': version, 'rules': rules}, f, ensure_ascii=False, indent=2)
                success = True
            elif rule_format == 'yaml':
                with open(tmp_out, 'w', encoding='utf-8') as f:
                    yaml.dump({'payload': rules}, f, allow_unicode=True, sort_keys=False)
                success = True
            else:  # text / classical / domain / ipcidr
                with open(tmp_out, 'w', encoding='utf-8') as f:
                    f.write(f"# Update: {datetime.now():%Y-%m-%d %H:%M:%S} | Total: {len(rules)}\n")
                    f.write('\n'.join(str(r) for r in rules) + '\n')
                success = True

            # 校验生成规则的有效性
            if not success or not self._validate_generated_rules(tmp_out, rule_format, behavior):
                logger.error(f"[{output_path}] ❌ 规则集有效性校验未通过，中断替换，保留原有旧文件！")
                return

            # 系统级原子替换
            os.replace(tmp_out, output_path)

        logger.info(f"[{output_path}] ✅ 规则集已成功通过校验并完成原子覆盖，最终规则数: {len(rules)}")

    # -------------------- 二进制工具支持 --------------------
    def _read_mrs_file(self, input_path: str, behavior: str) -> List[str]:
        if not self.mihomo_path:
            return []
        with self._temp_file('.txt') as tmp:
            cmd = [self.mihomo_path, 'convert-ruleset', behavior, 'mrs', input_path, tmp]
            if subprocess.run(cmd, capture_output=True, timeout=60).returncode == 0:
                with open(tmp, 'r', encoding='utf-8') as f:
                    return f.read().splitlines()
        return []

    def _decompile_srs_to_json_str(self, input_path: str) -> str:
        if not self.sing_box_path:
            return "{}"
        with self._temp_file('.json') as tmp:
            cmd = [self.sing_box_path, 'rule-set', 'decompile', '--output', tmp, input_path]
            if subprocess.run(cmd, capture_output=True, timeout=60).returncode == 0:
                with open(tmp, 'r', encoding='utf-8') as f:
                    return f.read()
        return "{}"

    def _convert_to_binary(self, bin_path: str, args: List[str], name: str) -> bool:
        if not bin_path:
            logger.error(f"未配置工具路径，无法编译 {name}")
            return False
        try:
            res = subprocess.run([bin_path] + args, capture_output=True, text=True, timeout=60)
            if res.returncode != 0:
                err_detail = (res.stderr or res.stdout or '未明确原因').strip()
                logger.error(f"编译 {name} 失败 (退出码 {res.returncode}): {err_detail}")
                return False
            return True
        except Exception as e:
            logger.error(f"调用编译器 {bin_path} 异常: {e}")
            return False

def main():
    merger = RulesMerger('config.yaml', max_workers=10)
    merger.merge_rules()

if __name__ == '__main__':
    main()
