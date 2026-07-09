import yaml
import json
import subprocess
import tempfile
import requests
import os
import logging
import time
from typing import List, Dict, Optional, Any, Union, Tuple
from contextlib import contextmanager
import re
import ipaddress
from datetime import datetime
from functools import lru_cache

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
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
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
        self._stats = {'total': 0, 'converted': 0, 'dropped': 0, 'duplicates': 0}

    # -------------------- 通用工具方法 --------------------
    @staticmethod
    def _normalize_behavior(behavior: Optional[str]) -> str:
        if not behavior:
            return 'classical'
        b = behavior.strip().lower()
        return 'sing-box' if b in ('singbox', 'sing-box') else b

    @staticmethod
    def _load_config(path: str) -> dict:
        with open(path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

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
        if rule.startswith('#'):
            return ''
        parts = re.split(r'\s+#', rule)
        return parts[0].strip() if len(parts) > 1 else rule

    @staticmethod
    @lru_cache(maxsize=1024)
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
                s = 'ip-cidr,' + s[9:]
            if s.startswith('domain-suffix,.'):
                s = 'domain-suffix,' + s[15:]
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
                    start, end = item_str.split('-', 1)
                    ranges.append((int(start.strip()), int(end.strip())))
                else:
                    val = int(item_str)
                    ranges.append((val, val))
            except ValueError:
                continue
                
        if not ranges:
            return []
            
        ranges.sort(key=lambda x: x[0])
        
        merged = [list(ranges[0])]
        for start, end in ranges[1:]:
            last_start, last_end = merged[-1]
            if start <= last_end + 1:
                merged[-1][1] = max(last_end, end)
            else:
                merged.append([start, end])
                
        return [str(s) if s == e else f"{s}-{e}" for s, e in merged]

    def _unified_domain_deduplication(self, exact_domains: List[str], suffix_domains: List[str]) -> Tuple[List[str], List[str]]:
        """
        超高速跨类型域名智能去重：
        将精确域名 (exact) 和后缀域名 (suffix) 统一合并。
        如果出现父域名（如 baidu.com）和子域名（如 ddj.baidu.com），无条件剔除子域名，仅保留父域名。
        【重点优化】：当发生子域名被父域名“吞并”时，自动将该父域名升级为“后缀匹配 (Suffix)”。
        """
        domain_types = {}
        
        # 0 表示 exact，1 表示 suffix
        for d in exact_domains:
            if d:
                d_str = str(d).strip()
                if d_str:
                    domain_types[d_str] = 0
                    
        for d in suffix_domains:
            if d:
                d_str = str(d).strip()
                if d_str:
                    # 如果同一域名既是精确又是后缀，后写入的 1 会直接覆盖 0，实现优先级自然升级
                    domain_types[d_str] = 1
                    
        if not domain_types:
            return [], []

        # 核心算法：将域名按层级反转并排序
        # 例如：zjxud.baidu.com -> ('com', 'baidu', 'zjxud')
        # 排序后，父域名必然紧挨在它所有的子域名之前
        reversed_tuples = sorted(tuple(d.split('.'))[::-1] for d in domain_types.keys())
        
        result_domains = []
        last_parent = None
        last_len = 0
        
        for current in reversed_tuples:
            # 判断当前域名是否为上一个父域名的子域名
            if last_parent and len(current) > last_len and current[:last_len] == last_parent:
                # 触发子域名剔除逻辑！
                # 既然吞并了子域名，为了保证子域名的流量依然能匹配到，将父域名强制升级为后缀 (suffix)
                parent_str = '.'.join(last_parent[::-1])
                domain_types[parent_str] = 1
                continue
                
            # 发现新的独立根/父域名，记录下来作为新的对比基准
            result_domains.append(current)
            last_parent = current
            last_len = len(current)
            
        final_exact = []
        final_suffix = []
        for t in result_domains:
            # 把反转的元组恢复为正常域名
            domain_str = '.'.join(t[::-1])
            # 根据其在字典中的最终状态 (可能在合并时被升级为 1) 还原到对应的列表中
            if domain_types[domain_str] == 1:
                final_suffix.append(domain_str)
            else:
                final_exact.append(domain_str)
                
        return final_exact, final_suffix

    def _merge_ip_rules(self, rules: List[str]) -> List[str]:
        if not rules:
            return []
            
        seen = set()
        result = []
        
        for rule in rules:
            cleaned_rule = rule.strip()
            parts = cleaned_rule.split(',', 1)
            if len(parts) < 2:
                continue
                
            if cleaned_rule not in seen:
                seen.add(cleaned_rule)
                result.append(cleaned_rule)
            else:
                self._stats['duplicates'] += 1
                
        return result

    # -------------------- 规则获取与解析 --------------------
    def _fetch_rules_from_source(self, source: Dict, target_behavior: str) -> List[Any]:
        rule_format = source.get('format', 'yaml')
        default_behavior = 'sing-box' if rule_format in ('json', 'srs') else 'classical'
        source_behavior = self._normalize_behavior(source.get('behavior', default_behavior))
        target_behavior = self._normalize_behavior(target_behavior)

        source_type = source.get('type')
        if source_type == 'http':
            url = source.get('url', '')
            logger.info(f"准备下载规则 [格式: {rule_format}]: {url}")
            raw_rules = self._fetch_http_rules(url, rule_format, source_behavior)
            if raw_rules:
                logger.info(f"规则下载成功: {url}")
        elif source_type == 'file':
            path = source.get('path', '')
            logger.info(f"正在读取本地规则文件 [格式: {rule_format}]: {path}")
            raw_rules = self._read_local_rules(path, rule_format, source_behavior)
        else:
            return []

        logger.info(f"正在清洗并转换数据，该源共获取到原始规则 {len(raw_rules)} 条...")
        converted = []
        for rule in raw_rules:
            if rule is None:
                continue
            if isinstance(rule, str):
                cleaned = self._clean_rule(rule)
                if not cleaned:
                    continue
                if cleaned.startswith('*.'):
                    cleaned = '+.' + cleaned[2:]
                rule = cleaned
            transformed = self._transform(rule, source_behavior, target_behavior)
            if not transformed:
                logger.warning(f"规则转换失败，已丢弃: {rule} (源行为: {source_behavior}, 目标: {target_behavior})")
                self._stats['dropped'] += 1
                continue
            converted.extend(transformed)
            self._stats['converted'] += 1
        return converted

    def _fetch_http_rules(self, url: str, rule_format: str, behavior: str) -> List[Any]:
        retry_delay = 5 
        max_attempts = 8
        attempt = 1
        
        while attempt <= max_attempts:
            try:
                resp = requests.get(url, timeout=30)
                resp.raise_for_status()
                content = resp.text
                
                if rule_format == 'json':
                    return self._parse_sing_box_source_to_list(content)
                if rule_format == 'srs':
                    with self._temp_file('.srs') as tmp_srs:
                        with open(tmp_srs, 'wb') as f:
                            f.write(resp.content)
                        decompiled = self._decompile_srs_to_json_str(tmp_srs)
                        return self._parse_sing_box_source_to_list(decompiled)
                        
                content_type = resp.headers.get('content-type', '')
                is_yaml = (rule_format == 'yaml') or (
                    rule_format not in ('mrs', 'text', 'json', 'srs') and
                    ('yaml' in content_type or url.endswith(('.yml', '.yaml')))
                )
                if is_yaml:
                    data = yaml.safe_load(content)
                    return self._extract_yaml_rules(data, url)
                    
                if rule_format == 'mrs':
                    with self._temp_file('.mrs') as tmp_mrs:
                        with open(tmp_mrs, 'wb') as f:
                            f.write(resp.content)
                        return self._read_mrs_file(tmp_mrs, behavior)
                        
                return content.splitlines()

            except requests.exceptions.RequestException as e:
                if attempt >= max_attempts:
                    logger.error(f"网络异常，获取规则失败 {url} [已达到最大重试次数 {max_attempts} 次]，将跳过此源并继续。(原因: {e})")
                    return []
                logger.warning(f"网络异常，获取规则失败 {url} [正在进行第 {attempt} 次重试 / 共 {max_attempts} 次]，等待 {retry_delay} 秒... (原因: {e})")
                time.sleep(retry_delay)
                attempt += 1
            except Exception as e:
                if attempt >= max_attempts:
                    logger.error(f"解析在线规则异常 {url} [已达到最大重试次数 {max_attempts} 次]，将跳过此源并继续。(原因: {e})")
                    return []
                logger.warning(f"解析在线规则异常 {url} [正在进行第 {attempt} 次重试 / 共 {max_attempts} 次]，等待 {retry_delay} 秒... (原因: {e})")
                time.sleep(retry_delay)
                attempt += 1
                
        return []

    def _read_local_rules(self, path: str, rule_format: str, behavior: str) -> List[Any]:
        try:
            if rule_format == 'mrs':
                return self._read_mrs_file(path, behavior)
            if rule_format == 'srs':
                decompiled = self._decompile_srs_to_json_str(path)
                return self._parse_sing_box_source_to_list(decompiled)
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                if rule_format == 'json':
                    return self._parse_sing_box_source_to_list(content)
                if rule_format == 'yaml':
                    data = yaml.safe_load(content)
                    return self._extract_yaml_rules(data, path)
                return content.splitlines()
        except Exception as e:
            logger.error(f"读取本地规则失败 {path}: {e}")
            return []

    def _parse_sing_box_source_to_list(self, content: str) -> List[Dict[str, Any]]:
        try:
            data = json.loads(content.lstrip('\ufeff'))
            if isinstance(data, dict) and 'rules' in data and isinstance(data['rules'], list):
                return data['rules']
            if isinstance(data, list):
                return data
            return []
        except json.JSONDecodeError as e:
            logger.error(f"解析 sing-box JSON 失败: {e}")
            raise e 

    @staticmethod
    def _extract_yaml_rules(data: Any, source: str) -> List[str]:
        if isinstance(data, dict):
            payload = data.get('payload')
            return payload if isinstance(payload, list) else []
        if isinstance(data, list):
            return data
        return []

    # -------------------- 规则转换核心 --------------------
    def _transform(self, rule: Any, source_behavior: str, target_behavior: str) -> List[Any]:
        source_behavior = self._normalize_behavior(source_behavior)
        target_behavior = self._normalize_behavior(target_behavior)
        self._stats['total'] += 1

        if isinstance(rule, dict):
            if target_behavior == 'sing-box':
                return [rule]
            transformer = self._transformers.get(('sing-box', target_behavior))
            if transformer:
                result = transformer(json.dumps(rule))
                return result if isinstance(result, list) else [result] if result else []
            return []

        if not rule:
            return []
        if source_behavior == target_behavior:
            return [rule]

        transformer = self._transformers.get((source_behavior, target_behavior))
        if not transformer:
            return []
        result = transformer(rule)
        if result is None:
            return []
        return result if isinstance(result, list) else [result] if result else []

    # -------------------- 格式间转换器 --------------------
    def _classical_to_ipcidr(self, rule: str) -> Optional[str]:
        parts = rule.split(',')
        if len(parts) < 2:
            return None
        prefix = parts[0].strip()
        if prefix not in ('IP-CIDR', 'IP-CIDR6'):
            return None
        return self._validate_ipcidr_rule(parts[1].strip())

    def _classical_to_domain(self, rule: str) -> Optional[str]:
        parts = rule.split(',')
        if len(parts) < 2:
            return None
        prefix, domain = parts[0].strip(), parts[1].strip()
        if not DOMAIN_PATTERN.match(domain):
            return None
        if prefix == 'DOMAIN':
            return domain
        if prefix == 'DOMAIN-SUFFIX':
            return '+.' + domain
        return None

    def _ipcidr_to_classical(self, rule: str) -> Optional[str]:
        v = self._get_ipcidr_version(rule)
        if v == 4:
            return f"IP-CIDR,{rule}"
        if v == 6:
            return f"IP-CIDR6,{rule}"
        return None

    def _domain_to_classical(self, rule: str) -> Optional[str]:
        if rule.startswith('+.'):
            domain = rule[2:]
            return f"DOMAIN-SUFFIX,{domain}" if DOMAIN_PATTERN.match(domain) else None
        return f"DOMAIN,{rule}" if DOMAIN_PATTERN.match(rule) else None

    def _classical_to_sing_box(self, rule: str) -> Optional[str]:
        if not self._validate_classical_rule(rule):
            return None
        parts = [p.strip() for p in rule.split(',')]
        if len(parts) < 2:
            return None
        prefix = parts[0]

        if prefix == 'DST-PORT':
            port_expr = parts[1]
            if '/' in port_expr:
                items = [x.strip() for x in port_expr.split('/') if x.strip()]
            else:
                items = [port_expr]
            
            merged_items = self._merge_port_items(items)

            port_list = []
            port_range_list = []
            for item in merged_items:
                if '-' in item:
                    port_range_list.append(item.replace('-', ':'))
                else:
                    port_list.append(item)
            result = {}
            if port_list:
                result['port'] = port_list
            if port_range_list:
                result['port_range'] = port_range_list
            return json.dumps(result) if result else None

        else:
            item = self._to_sing_box_item(rule, 'classical')
            if not item:
                return None
            field, value = item
            if not isinstance(value, list):
                value = [value]
            return json.dumps({field: value})

    def _domain_to_sing_box(self, rule: str) -> Optional[str]:
        if not self._validate_domain_rule(rule):
            return None
        item = self._to_sing_box_item(rule, 'domain')
        return json.dumps({item[0]: [item[1]]}) if item else None

    def _ipcidr_to_sing_box(self, rule: str) -> Optional[str]:
        if not self._validate_ipcidr_rule(rule):
            return None
        item = self._to_sing_box_item(rule, 'ipcidr')
        return json.dumps({item[0]: [item[1]]}) if item else None

    def _to_sing_box_item(self, rule: str, behavior: str) -> Optional[tuple]:
        if behavior == 'domain':
            if rule.startswith('+.'):
                return ('domain_suffix', rule[2:])
            return ('domain', rule)
        if behavior == 'ipcidr':
            return ('ip_cidr', rule)
        if behavior != 'classical':
            return None
        parts = [p.strip() for p in rule.split(',')]
        if len(parts) < 2:
            return None
        field = CLASSICAL_TO_SB.get(parts[0])
        if not field:
            return None
        value = parts[1]
        if field == 'network':
            value = value.lower()
        return (field, value)

    def _parse_sing_box_rule(self, rule_str: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = json.loads(rule_str)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None

    def _iter_sing_box_rules(self, rule: Dict[str, Any]) -> List[Dict[str, Any]]:
        rules = [rule]
        if rule.get('type') == 'logical':
            for nested in self._as_list(rule.get('rules')):
                if isinstance(nested, dict):
                    rules.extend(self._iter_sing_box_rules(nested))
        return rules

    def _sing_box_to_domain(self, rule_str: str) -> List[str]:
        parsed = self._parse_sing_box_rule(rule_str)
        if not parsed:
            return []
        result = []
        for item in self._iter_sing_box_rules(parsed):
            for d in self._as_list(item.get('domain')):
                result.append(str(d))
            for s in self._as_list(item.get('domain_suffix')):
                s = s[1:] if s.startswith('.') else s
                result.append(f"+.{s}")
        return result

    def _sing_box_to_ipcidr(self, rule_str: str) -> List[str]:
        parsed = self._parse_sing_box_rule(rule_str)
        if not parsed:
            return []
        result = []
        for item in self._iter_sing_box_rules(parsed):
            for ip in self._as_list(item.get('ip_cidr')):
                result.append(str(ip))
        return result

    def _sing_box_to_classical(self, rule_str: str) -> List[str]:
        parsed = self._parse_sing_box_rule(rule_str)
        if not parsed:
            return []
        result = []
        for item in self._iter_sing_box_rules(parsed):
            for d in self._as_list(item.get('domain')):
                result.append(f"DOMAIN,{d}")
            for s in self._as_list(item.get('domain_suffix')):
                s = s[1:] if s.startswith('.') else s
                result.append(f"DOMAIN-SUFFIX,{s}")
            for k in self._as_list(item.get('domain_keyword')):
                result.append(f"DOMAIN-KEYWORD,{k}")
            for r in self._as_list(item.get('domain_regex')):
                result.append(f"DOMAIN-REGEX,{r}")
            for ip in self._as_list(item.get('ip_cidr')):
                prefix = "IP-CIDR6" if ':' in str(ip) else "IP-CIDR"
                result.append(f"{prefix},{ip}")
            for n in self._as_list(item.get('network')):
                result.append(f"NETWORK,{str(n).lower()}")

            port_items = []
            for p in self._as_list(item.get('port')):
                port_items.append(str(p))
            for pr in self._as_list(item.get('port_range')):
                port_items.append(str(pr).replace(':', '-'))
            if port_items:
                merged_items = self._merge_port_items(port_items)
                joined = "/".join(merged_items)
                result.append(f"DST-PORT,{joined}")
        return result

    def _validate_classical_rule(self, rule: str) -> Optional[str]:
        try:
            parts = [p.strip() for p in rule.split(',')]
            if len(parts) < 2:
                return None
            prefix, value = parts[0], parts[1]
            if prefix in ('DOMAIN', 'DOMAIN-SUFFIX'):
                return rule if DOMAIN_PATTERN.match(value) else None
            if prefix == 'DOMAIN-KEYWORD':
                return rule
            if prefix == 'DOMAIN-REGEX':
                return rule
            if prefix == 'IP-CIDR':
                return rule if self._get_ipcidr_version(value) == 4 else None
            if prefix == 'IP-CIDR6':
                return rule if self._get_ipcidr_version(value) == 6 else None
            if prefix == 'DST-PORT':
                if '/' in value:
                    for part in value.split('/'):
                        part = part.strip()
                        if part and not PORT_PATTERN.match(part):
                            return None
                    return rule
                else:
                    return rule if PORT_PATTERN.match(value) else None
            if prefix == 'NETWORK':
                return rule if value.lower() in ('tcp', 'udp') else None
            return rule
        except Exception:
            return None

    # -------------------- 规则合并与输出 --------------------
    def merge_rules(self) -> None:
        for config in self.config:
            if 'upstream' not in config or not config.get('path'):
                continue

            target_format = config.get('format', 'yaml')
            default_behavior = 'sing-box' if target_format in ('json', 'srs') else 'classical'
            target_behavior = self._normalize_behavior(config.get('behavior', default_behavior))

            self._stats = {'total': 0, 'converted': 0, 'dropped': 0, 'duplicates': 0}

            all_rules = []
            for source_config in config['upstream'].values():
                rules = self._fetch_rules_from_source(source_config, target_behavior)
                all_rules.extend(rules)

            logger.info(f"所有规则源下载完毕，原始输入规则数: {self._stats['total']}, 成功转换: {self._stats['converted']}, 丢弃: {self._stats['dropped']}")
            logger.info("开始进行规则去重与合并...")

            if target_behavior == 'sing-box':
                dict_rules = []
                for r in all_rules:
                    if isinstance(r, dict):
                        dict_rules.append(r)
                    elif isinstance(r, str):
                        parsed = self._parse_sing_box_rule(r)
                        if parsed:
                            dict_rules.append(parsed)
                        else:
                            logger.warning(f"无法解析为sing-box规则的字符串，已丢弃: {r}")
                            self._stats['dropped'] += 1
                    else:
                        logger.warning(f"未知类型规则，已丢弃: {r}")
                        self._stats['dropped'] += 1

                final_rules = self._compile_final_sing_box_list(dict_rules)
            else:
                str_rules = [str(r) for r in all_rules if r is not None]
                final_rules = self._deduplicate_and_merge_classical(str_rules)

            logger.info(f"去重和聚合完成！最终规则数: {len(final_rules)}, 共减少重复/冗余项: {self._stats['duplicates']}")

            output_file = config['path']
            self._write_rules(
                output_file,
                final_rules,
                target_format,
                target_behavior,
                config.get('version', SING_BOX_RULESET_VERSION)
            )

    def _deduplicate_and_merge_classical(self, rules: List[str]) -> List[str]:
        domain_rules = []
        domain_suffix_rules = []
        domain_keyword_rules = []
        domain_regex_rules = []
        ip_cidr_rules = []
        dst_port_rules = []
        network_rules = []
        other_rules = []

        for rule in rules:
            if not isinstance(rule, str):
                other_rules.append(rule)
                continue
            if rule.startswith('DOMAIN,'):
                domain_rules.append(rule)
            elif rule.startswith('DOMAIN-SUFFIX,'):
                domain_suffix_rules.append(rule)
            elif rule.startswith('DOMAIN-KEYWORD,'):
                domain_keyword_rules.append(rule)
            elif rule.startswith('DOMAIN-REGEX,'):
                domain_regex_rules.append(rule)
            elif rule.startswith('IP-CIDR') or rule.startswith('IP-CIDR6,'):
                ip_cidr_rules.append(rule)
            elif rule.startswith('DST-PORT,'):
                dst_port_rules.append(rule)
            elif rule.startswith('NETWORK,'):
                network_rules.append(rule)
            else:
                other_rules.append(rule)

        # 提取纯域名进行统一跨域智能去重
        exact_list = []
        for r in domain_rules:
            parts = r.split(',', 1)
            if len(parts) == 2:
                exact_list.append(parts[1].strip())
                
        suffix_list = []
        for r in domain_suffix_rules:
            parts = r.split(',', 1)
            if len(parts) == 2:
                suffix_list.append(parts[1].strip())

        final_exact, final_suffix = self._unified_domain_deduplication(exact_list, suffix_list)
        
        # 计算剔除的重复/子域名数量并计入统计
        diff = (len(exact_list) + len(suffix_list)) - (len(final_exact) + len(final_suffix))
        if diff > 0:
            self._stats['duplicates'] += diff

        deduped_domain = [f"DOMAIN,{d}" for d in final_exact]
        deduped_domain_suffix = [f"DOMAIN-SUFFIX,{d}" for d in final_suffix]

        # IP 去重 (完全相同去重)
        merged_ip_cidr = self._merge_ip_rules(ip_cidr_rules)

        # 端口合并去重
        merged_dst_port = self._merge_dst_port_rules(dst_port_rules)

        # 其他规则简单去重
        def dedup_list(items):
            seen = set()
            result = []
            for item in items:
                sig = self._normalize_rule_signature(item)
                if sig not in seen:
                    seen.add(sig)
                    result.append(item)
                else:
                    self._stats['duplicates'] += 1
            return result

        result = []
        result.extend(deduped_domain)
        result.extend(deduped_domain_suffix)
        result.extend(dedup_list(domain_keyword_rules))
        result.extend(dedup_list(domain_regex_rules))
        result.extend(merged_ip_cidr)
        if merged_dst_port:
            result.append(merged_dst_port)
        result.extend(dedup_list(network_rules))
        result.extend(dedup_list(other_rules))

        return result

    def _merge_dst_port_rules(self, rules: List[str]) -> Optional[str]:
        if not rules:
            return None
        all_items = []
        for rule in rules:
            parts = rule.split(',', 1)
            if len(parts) == 2:
                expr = parts[1]
                if '/' in expr:
                    items = [x.strip() for x in expr.split('/') if x.strip()]
                else:
                    items = [expr.strip()]
                all_items.extend(items)
        if not all_items:
            return None
        
        merged_items = self._merge_port_items(all_items)
        return "DST-PORT," + "/".join(merged_items)

    def _compile_final_sing_box_list(self, rules: List[Dict]) -> List[Dict]:
        bucket = {key: [] for key in SING_BOX_LIST_FIELDS}
        passthrough_rules = []

        for rule in rules:
            if self._can_compact_sing_box_rule(rule):
                self._add_sing_box_rule_items(bucket, rule)
            else:
                passthrough_rules.append(rule)

        # 域名统一跨域智能去重 (精确域名与后缀域名混合剔除子域名)
        exact_list = bucket.get('domain', [])
        suffix_list = bucket.get('domain_suffix', [])
        
        if exact_list or suffix_list:
            final_exact, final_suffix = self._unified_domain_deduplication(
                [str(d) for d in exact_list], 
                [str(s) for s in suffix_list]
            )
            
            diff = (len(exact_list) + len(suffix_list)) - (len(final_exact) + len(final_suffix))
            if diff > 0:
                self._stats['duplicates'] += diff
                
            bucket['domain'] = final_exact
            bucket['domain_suffix'] = final_suffix

        # IP 纯字符串去重
        if bucket['ip_cidr']:
            original_len = len(bucket['ip_cidr'])
            seen_ips = set()
            unique_ips = []
            
            for ip in bucket['ip_cidr']:
                ip_str = str(ip).strip()
                if ip_str not in seen_ips:
                    seen_ips.add(ip_str)
                    unique_ips.append(ip_str)
            
            self._stats['duplicates'] += (original_len - len(unique_ips))
            bucket['ip_cidr'] = unique_ips

        # 端口合并优化
        if bucket['port'] or bucket['port_range']:
            all_port_items = []
            all_port_items.extend(str(p) for p in bucket['port'])
            all_port_items.extend(str(pr).replace(':', '-') for pr in bucket['port_range'])
            
            merged_items = self._merge_port_items(all_port_items)
            
            new_port = []
            new_port_range = []
            for item in merged_items:
                if '-' in item:
                    new_port_range.append(item.replace('-', ':'))
                else:
                    new_port.append(int(item))
            bucket['port'] = new_port
            bucket['port_range'] = new_port_range

        compacted = self._compact_sing_box_rules(bucket)
        all_rules = compacted + passthrough_rules
        seen = set()
        unique = []
        for r in all_rules:
            sig = self._normalize_rule_signature(r)
            if sig not in seen:
                seen.add(sig)
                unique.append(r)
            else:
                self._stats['duplicates'] += 1
        return unique

    def _can_compact_sing_box_rule(self, rule: Dict[str, Any]) -> bool:
        if rule.get('type') == 'logical':
            return False
        for key, value in rule.items():
            if key not in SING_BOX_LIST_FIELDS:
                return False
            values = self._as_list(value)
            if values and not all(isinstance(v, (str, int)) for v in values):
                return False
        return True

    def _add_sing_box_rule_items(self, bucket: Dict[str, List[Any]], rule: Dict[str, Any]) -> None:
        for key in SING_BOX_LIST_FIELDS:
            if key in rule:
                raw = self._as_list(rule[key])
                if key == 'port':
                    cleaned = [int(v) if str(v).isdigit() else v for v in raw]
                elif key == 'network':
                    cleaned = [str(v).lower() for v in raw]
                else:
                    cleaned = raw
                bucket[key].extend(cleaned)

    def _compact_sing_box_rules(self, bucket: Dict[str, List[Any]]) -> List[Dict[str, List[Any]]]:
        compacted = []
        for key in SING_BOX_LIST_FIELDS:
            values = bucket.get(key, [])
            if not values:
                continue
            unique = list(set(values))
            if key == 'port':
                has_range = any(isinstance(v, str) and not v.isdigit() for v in unique)
                if has_range:
                    sorted_vals = sorted(str(v) for v in unique)
                else:
                    sorted_vals = sorted(int(v) for v in unique)
            elif key == 'port_range':
                sorted_vals = sorted(str(v) for v in unique)
            else:
                sorted_vals = sorted(unique, key=lambda x: str(x))
            compacted.append({key: sorted_vals})
        return compacted

    def _write_rules(self, output_path: str, rules: List[Any], rule_format: str,
                     behavior: str, version: int) -> None:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        if rule_format == 'mrs':
            with self._temp_file('.tmp') as tmp:
                self._write_rules(tmp, rules, 'text', behavior, version)
                if self._convert_to_mrs(tmp, output_path, behavior):
                    logger.info(f"已生成 mrs 规则文件: {output_path}, 共 {len(rules)} 条")
            return

        if rule_format == 'srs':
            with self._temp_file('.json') as tmp_json:
                self._write_sing_box_source_direct(tmp_json, rules, version)
                if self._convert_to_srs(tmp_json, output_path):
                    logger.info(f"已生成 srs 二进制规则文件: {output_path}")
            return

        if rule_format == 'json':
            self._write_sing_box_source_direct(output_path, rules, version)
            logger.info(f"已生成 json 规则文件: {output_path}")
            return

        with open(output_path, 'w', encoding='utf-8') as f:
            if not output_path.endswith('.tmp'):
                f.write(f"# 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# 规则数量: {len(rules)}\n")
            if rule_format == 'yaml':
                yaml_str = yaml.dump({'payload': rules}, allow_unicode=True,
                                     indent=2, default_flow_style=False, sort_keys=False)
                f.write(yaml_str)
            else:
                for r in rules:
                    f.write(f"{r}\n")
        logger.info(f"已生成 {rule_format} 规则文件: {output_path}, 共 {len(rules)} 条")

    def _write_sing_box_source_direct(self, output_path: str, rules: List[Dict], version: int) -> None:
        data = {'version': version, 'rules': rules}
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write('\n')

    # -------------------- 二进制格式支持 --------------------
    def _read_mrs_file(self, input_path: str, behavior: str) -> List[str]:
        if not self.mihomo_path:
            logger.warning("mihomo 未配置，无法读取 MRS")
            return []
        with self._temp_file('.txt') as tmp:
            cmd = [self.mihomo_path, 'convert-ruleset', behavior, 'mrs', input_path, tmp]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                logger.error(f"mihomo 解包 MRS 失败: {result.stderr}")
                return []
            with open(tmp, 'r', encoding='utf-8') as f:
                return f.read().splitlines()

    def _decompile_srs_to_json_str(self, input_path: str) -> str:
        if not self.sing_box_path:
            logger.warning("sing-box 未配置，无法反编译 SRS")
            return "{}"
        with self._temp_file('.json') as tmp:
            cmd = [self.sing_box_path, 'rule-set', 'decompile', '--output', tmp, input_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                logger.error(f"sing-box 反编译 SRS 失败: {result.stderr}")
                return "{}"
            with open(tmp, 'r', encoding='utf-8') as f:
                return f.read()

    def _convert_to_mrs(self, input_path: str, output_path: str, behavior: str) -> bool:
        if not self.mihomo_path:
            logger.error("未找到 mihomo，无法编译 MRS")
            return False
        cmd = [self.mihomo_path, 'convert-ruleset', behavior, 'text', input_path, output_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            logger.error(f"mihomo 编译 MRS 失败: {result.stderr}")
            return False
        return True

    def _convert_to_srs(self, input_path: str, output_path: str) -> bool:
        if not self.sing_box_path:
            logger.error("未找到 sing-box，无法编译 SRS")
            return False
        cmd = [self.sing_box_path, 'rule-set', 'compile', '--output', output_path, input_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            logger.error(f"sing-box 编译 SRS 失败: {result.stderr}")
            return False
        return True


def main():
    merger = RulesMerger('config.yaml')
    merger.merge_rules()


if __name__ == '__main__':
    main()
