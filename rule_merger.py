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
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
import time

# ==================== 配置 ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 增强正则：支持任意位置、任意数量的 * 通配符（包括 .stun.*.*.*.*.*）
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

    def _make_temp_path(self, suffix: str) -> str:
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        return path

    @lru_cache(maxsize=64)
    def _fetch_http_rules(self, url: str, rule_format: str, behavior: str = 'classical') -> List[str]:
        for attempt in range(RETRY_TIMES + 1):
            try:
                resp = self.session.get(url, timeout=REQUEST_TIMEOUT)
                resp.raise_for_status()
                return self._parse_response(resp, rule_format, behavior, url)
            except Exception as e:
                if attempt == RETRY_TIMES:
                    self.logger.error(f"获取规则失败 {url} (尝试{attempt+1}次): {e}")
                    return []
                time.sleep(1 * (attempt + 1))
        return []

    def _parse_response(self, response, rule_format: str, behavior: str, url: str) -> List[str]:
        if rule_format == 'json':
            return self._read_sing_box_source(response.text)

        if rule_format == 'srs':
            tmp_path = self._make_temp_path('.srs')
            try:
                with open(tmp_path, 'wb') as f:
                    f.write(response.content)
                return self._read_srs_file(tmp_path)
            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)

        content_type = response.headers.get('content-type', '').lower()
        is_yaml = (rule_format == 'yaml') or (
            rule_format not in ('mrs', 'text', 'json', 'srs') and
            ('yaml' in content_type or url.lower().endswith(('.yml', '.yaml')))
        )
        if is_yaml:
            data = yaml.safe_load(response.text)
            return self._extract_yaml_rules(data, url)

        if rule_format == 'mrs':
            tmp_path = self._make_temp_path('.mrs')
            try:
                with open(tmp_path, 'wb') as f:
                    f.write(response.content)
                return self._read_mrs_file(tmp_path, behavior)
            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)

        return [line.strip() for line in response.text.splitlines() if line.strip()]

    def _process_source_concurrent(self, upstream: Dict, target_behavior: str) -> List[str]:
        all_rules = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_source = {
                executor.submit(self._process_source, src, target_behavior): name
                for name, src in upstream.items()
            }
            for future in as_completed(future_to_source):
                name = future_to_source[future]
                try:
                    rules = future.result()
                    all_rules.extend(rules)
                    self.logger.info(f"✓ 完成源 {name}: {len(rules)} 条")
                except Exception as e:
                    self.logger.error(f"处理源 {name} 失败: {e}")
        return all_rules

    def _process_source(self, source: Dict, target_behavior: str) -> List[str]:
        rule_format = source.get('format', 'yaml')
        default_behavior = 'sing-box' if rule_format in ('json', 'srs') else 'classical'
        source_behavior = source.get('behavior', default_behavior)

        source_type = source.get('type')
        if source_type == 'http':
            url = source.get('url')
            if not url:
                return []
            rules = self._fetch_http_rules(url, rule_format, source_behavior)
        elif source_type == 'file':
            path = source.get('path')
            if not path or not os.path.exists(path):
                self.logger.warning(f"本地文件不存在: {path}")
                return []
            rules = self._read_local_rules(path, rule_format, source_behavior)
        else:
            return []

        converted = []
        for rule in rules:
            if not rule:
                continue
            cleaned = rule if source_behavior == 'sing-box' else self._clean_rule(str(rule))
            transformed = self._transform(cleaned, source_behavior, target_behavior)
            if transformed:
                converted.extend(transformed)
        return converted

    def _transform(self, rule: str, source_behavior: str, target_behavior: str) -> List[str]:
        if not rule:
            return []
        if source_behavior == target_behavior:
            validators = {
                'classical': self._validate_classical_rule,
                'ipcidr': self._validate_ipcidr_rule,
                'domain': self._validate_domain_rule,
                'sing-box': self._validate_sing_box_rule
            }
            validator = validators.get(source_behavior)
            if validator:
                validated = validator(rule)
                return [validated] if validated else []
            return [rule]

        transformer = self._transformers.get((source_behavior, target_behavior))
        if not transformer:
            return []
        result = transformer(rule)
        return result if isinstance(result, list) else [result] if result else []

    def _clean_rule(self, rule: str) -> str:
        rule = rule.strip()
        if rule.startswith('#') or not rule:
            return ''
        parts = re.split(r'\s+#', rule, maxsplit=1)
        return parts[0].strip()

    def _read_local_rules(self, path: str, rule_format: str, behavior: str = 'classical') -> List[str]:
        try:
            if rule_format == 'mrs':
                return self._read_mrs_file(path, behavior)
            if rule_format == 'srs':
                return self._read_srs_file(path)

            with open(path, 'r', encoding='utf-8') as f:
                if rule_format == 'json':
                    return self._read_sing_box_source(f.read())
                if rule_format == 'yaml':
                    data = yaml.safe_load(f)
                    return self._extract_yaml_rules(data, path)
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.logger.error(f"读取本地规则失败 {path}: {e}")
            return []

    def _extract_yaml_rules(self, data: Any, source: str) -> List[str]:
        if data is None:
            return []
        if isinstance(data, dict):
            payload = data.get('payload')
            if isinstance(payload, list):
                return payload
            return []
        if isinstance(data, list):
            return data
        return []

    # ==================== 通配符核心函数 ====================

    def _classical_to_domain(self, rule: str) -> Optional[str]:
        parts = rule.split(',')
        if len(parts) < 2:
            return None
        suffix = parts[0].strip()
        domain = parts[1].strip()

        if suffix == 'DOMAIN':
            return domain if self._validate_domain_rule(domain) else None
        elif suffix == 'DOMAIN-SUFFIX':
            if domain.startswith('*.'):
                return '+.' + domain[2:]
            return '+.' + domain
        return None

    def _domain_to_classical(self, rule: str) -> Optional[str]:
        if rule.startswith('+.'):
            suffix = rule[2:]
            return f"DOMAIN-SUFFIX,{suffix}"
        if '*' in rule or self._validate_domain_rule(rule):
            if rule.startswith('*.'):
                return f"DOMAIN-SUFFIX,{rule[2:]}"
            return f"DOMAIN,{rule}"
        return None

    def _to_sing_box_item(self, rule: str, behavior: str) -> Optional[tuple]:
        if behavior == 'domain':
            if rule.startswith('+.'):
                return 'domain_suffix', rule[2:]
            if rule.startswith('*.'):
                return 'domain_suffix', rule[2:]
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

    def _validate_domain_rule(self, rule: str) -> Optional[str]:
        if not rule:
            return None
        domain = rule[2:] if rule.startswith('+.') else rule
        if DOMAIN_PATTERN.match(domain) or '*' in domain:
            return rule
        return None

    def _validate_classical_rule(self, rule: str) -> Optional[str]:
        try:
            parts = rule.split(',')
            if len(parts) < 2:
                return None
            rule_type = parts[0]
            value = parts[1].strip()
            rule = ','.join(part.strip() for part in parts)
            if rule_type in {'DOMAIN', 'DOMAIN-SUFFIX'}:
                if self._validate_domain_rule(value) or '*' in value:
                    return rule
                return None
            elif rule_type == 'IP-CIDR':
                return rule if self._get_ipcidr_version(value) == 4 else None
            elif rule_type == 'IP-CIDR6':
                return rule if self._get_ipcidr_version(value) == 6 else None
            return rule
        except:
            return None

    def _classical_to_ipcidr(self, rule: str) -> Optional[str]:
        parts = rule.split(',')
        if len(parts) < 2:
            return None
        suffix = parts[0].strip()
        ipcidr = parts[1].strip()
        if suffix not in ('IP-CIDR', 'IP-CIDR6'):
            return None
        return self._validate_ipcidr_rule(ipcidr)

    def _ipcidr_to_classical(self, rule: str) -> Optional[str]:
        ver = self._get_ipcidr_version(rule)
        if ver == 6:
            return "IP-CIDR6," + rule
        if ver == 4:
            return "IP-CIDR," + rule
        return None

    def _write_sing_box_source(self, output_path: str, rules: List[str], behavior: str, version: int = SING_BOX_RULESET_VERSION):
        rule_set = {
            'version': version,
            'rules': self._to_sing_box_rules(rules, behavior)
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(rule_set, f, ensure_ascii=False, indent=2)

    def _to_sing_box_rules(self, rules: List[str], behavior: str) -> List[Dict[str, Any]]:
        merged = {
            'domain': [],
        },
            'domain_suffix': [],
        },
            'domain_keyword': [],
        },
            'domain_regex': [],
        },
            'ip_cidr': []
        }

        if behavior == 'sing-box':
            for rule_str in rules:
                try:
                    rule_dict = json.loads(rule_str) if isinstance(rule_str, str) else rule_str
                    for key in merged.keys():
                        if key in rule_dict:
                            val = rule_dict[key]
                            if isinstance(val, list):
                                merged[key].extend(val)
                            elif val:
                                merged[key].append(val)
                except:
                    continue
        else:
            for rule in rules:
                converted = self._to_sing_box_item(rule, behavior)
                if converted:
                    key, value = converted
                    if isinstance(value, list):
                        merged[key].extend(value)
                    else:
                        merged[key].append(value)

        compact_rule = {k: sorted(set(v)) for k, v in merged.items() if v}
        return [compact_rule] if compact_rule else []

    def _read_sing_box_source(self, content: str) -> List[str]:
        try:
            data = json.loads(content.lstrip('\ufeff'))
        except json.JSONDecodeError:
            return []
        if not isinstance(data, dict):
            return []
        rules = data.get('rules', [])
        if not isinstance(rules, list):
            return []
        normalized_rules = []
        for rule in rules:
            normalized = self._normalize_sing_box_rule(rule)
            if normalized:
                normalized_rules.append(normalized)
        return normalized_rules

    def _normalize_sing_box_rule(self, rule: Any) -> Optional[str]:
        if not isinstance(rule, dict):
            return None
        return json.dumps(rule, ensure_ascii=False, sort_keys=True, separators=(',', ':'))

    def _parse_sing_box_rule(self, rule: str) -> Optional[Dict]:
        try:
            parsed = json.loads(rule)
            return parsed if isinstance(parsed, dict) else None
        except:
            return None

    def _validate_sing_box_rule(self, rule: str) -> Optional[str]:
        parsed = self._parse_sing_box_rule(rule)
        if parsed is None:
            return None
        return self._normalize_sing_box_rule(parsed)

    def _classical_to_sing_box(self, rule: str) -> Optional[str]:
        if not self._validate_classical_rule(rule):
            return None
        item = self._to_sing_box_item(rule, 'classical')
        if not item:
            return None
        key, value = item
        return self._normalize_sing_box_rule({key: [value]})

    def _domain_to_sing_box(self, rule: str) -> Optional[str]:
        if not self._validate_domain_rule(rule):
            return None
        item = self._to_sing_box_item(rule, 'domain')
        if not item:
            return None
        key, value = item
        return self._normalize_sing_box_rule({key: [value]})

    def _ipcidr_to_sing_box(self, rule: str) -> Optional[str]:
        if not self._validate_ipcidr_rule(rule):
            return None
        item = self._to_sing_box_item(rule, 'ipcidr')
        if not item:
            return None
        key, value = item
        return self._normalize_sing_box_rule({key: [value]})

    def _sing_box_to_domain(self, rule: str) -> List[str]:
        parsed = self._parse_sing_box_rule(rule)
        if parsed is None:
            return []
        rules = []
        for item in self._iter_sing_box_rules(parsed):
            for domain in self._as_list(item.get('domain')):
                if isinstance(domain, str) and self._validate_domain_rule(domain):
                    rules.append(domain)
            for suffix in self._as_list(item.get('domain_suffix')):
                if isinstance(suffix, str):
                    suffix = suffix[1:] if suffix.startswith('.') else suffix
                    domain_rule = f"+.{suffix}"
                    if self._validate_domain_rule(domain_rule):
                        rules.append(domain_rule)
        return rules

    def _sing_box_to_ipcidr(self, rule: str) -> List[str]:
        parsed = self._parse_sing_box_rule(rule)
        if parsed is None:
            return []
        rules = []
        for item in self._iter_sing_box_rules(parsed):
            for ipcidr in self._as_list(item.get('ip_cidr')):
                if isinstance(ipcidr, str) and self._validate_ipcidr_rule(ipcidr):
                    rules.append(ipcidr)
        return rules

    def _sing_box_to_classical(self, rule: str) -> List[str]:
        parsed = self._parse_sing_box_rule(rule)
        if parsed is None:
            return []
        rules = []
        for item in self._iter_sing_box_rules(parsed):
            for domain in self._as_list(item.get('domain')):
                if isinstance(domain, str):
                    classical_rule = f"DOMAIN,{domain}"
                    if self._validate_classical_rule(classical_rule):
                        rules.append(classical_rule)
            for suffix in self._as_list(item.get('domain_suffix')):
                if isinstance(suffix, str):
                    suffix = suffix[1:] if suffix.startswith('.') else suffix
                    classical_rule = f"DOMAIN-SUFFIX,{suffix}"
                    if self._validate_classical_rule(classical_rule):
                        rules.append(classical_rule)
            for keyword in self._as_list(item.get('domain_keyword')):
                if isinstance(keyword, str):
                    rules.append(f"DOMAIN-KEYWORD,{keyword}")
            for regex_rule in self._as_list(item.get('domain_regex')):
                if isinstance(regex_rule, str):
                    rules.append(f"DOMAIN-REGEX,{regex_rule}")
            for ipcidr in self._as_list(item.get('ip_cidr')):
                if not isinstance(ipcidr, str):
                    continue
                classical_rule = f"IP-CIDR6,{ipcidr}" if ':' in ipcidr else f"IP-CIDR,{ipcidr}"
                if self._validate_classical_rule(classical_rule):
                    rules.append(classical_rule)
        return rules

    def _iter_sing_box_rules(self, rule: Dict) -> List[Dict]:
        rules = [rule]
        if rule.get('type') == 'logical':
            for nested in self._as_list(rule.get('rules')):
                if isinstance(nested, dict):
                    rules.extend(self._iter_sing_box_rules(nested))
        return rules

    def _as_list(self, value: Any) -> List[Any]:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    def _validate_ipcidr_rule(self, rule: str) -> Optional[str]:
        if self._get_ipcidr_version(rule):
            return rule
        return None

    def _get_ipcidr_version(self, rule: str) -> Optional[int]:
        try:
            return ipaddress.ip_network(rule, strict=False).version
        except ValueError:
            return None

    def _read_mrs_file(self, input_path: str, behavior: str) -> List[str]:
        if not self.mihomo_path:
            return []
        output_path = self._make_temp_path('.txt')
        try:
            cmd = [self.mihomo_path, 'convert-ruleset', behavior, 'mrs', input_path, output_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return []
            with open(output_path, 'r', encoding='utf-8') as f:
                return f.read().splitlines()
        except:
            return []
        finally:
            if os.path.exists(output_path):
                try:
                    os.unlink(output_path)
                except:
                    pass

    def _read_srs_file(self, input_path: str) -> List[str]:
        if not self.sing_box_path:
            return []
        output_path = self._make_temp_path('.json')
        try:
            cmd = [self.sing_box_path, 'rule-set', 'decompile', '--output', output_path, input_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                return []
            with open(output_path, 'r', encoding='utf-8') as f:
                return self._read_sing_box_source(f.read())
        except:
            return []
        finally:
            if os.path.exists(output_path):
                try:
                    os.unlink(output_path)
                except:
                    pass

    def _convert_to_mrs(self, input_path: str, output_path: str, behavior: str) -> bool:
        if not self.mihomo_path:
            return False
        try:
            cmd = [self.mihomo_path, 'convert-ruleset', behavior, 'text', input_path, output_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def _convert_to_srs(self, input_path: str, output_path: str) -> bool:
        if not self.sing_box_path:
            return False
        try:
            cmd = [self.sing_box_path, 'rule-set', 'compile', '--output', output_path, input_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def merge_rules(self) -> None:
        start_time = time.time()
        for cfg in self.config:
            if 'upstream' not in cfg or not cfg.get('path'):
                continue

            target_format = cfg.get('format', 'yaml')
            default_behavior = 'sing-box' if target_format in ('json', 'srs') else 'domain'
            target_behavior = cfg.get('behavior', default_behavior)

            if target_format == 'mrs' and target_behavior not in ('domain', 'ipcidr'):
                self.logger.warning(f"{cfg.get('path')} mrs仅支持 domain/ipcidr")
                continue

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

            if rule_format in ('mrs', 'srs', 'json'):
                if rule_format == 'mrs':
                    tmp_path = self._make_temp_path('.tmp')
                    self._write_rules(tmp_path, rules, 'text', behavior, version)
                    try:
                        if self._convert_to_mrs(tmp_path, output_path, behavior):
                            self._log_generated_rule_file('mrs', output_path, len(rules))
                    finally:
                        if os.path.exists(tmp_path):
                            os.unlink(tmp_path)
                    return

                if rule_format == 'srs':
                    tmp_path = self._make_temp_path('.json')
                    self._write_sing_box_source(tmp_path, rules, behavior, version)
                    try:
                        if self._convert_to_srs(tmp_path, output_path):
                            self._log_generated_rule_file('srs', output_path, len(rules))
                    finally:
                        if os.path.exists(tmp_path):
                            os.unlink(tmp_path)
                    return

                if rule_format == 'json':
                    self._write_sing_box_source(output_path, rules, behavior, version)
                    self._log_generated_rule_file('json', output_path, len(rules))
                    return

            with open(output_path, 'w', encoding='utf-8') as f:
                if not output_path.endswith('.tmp'):
                    f.write(f"# 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# 规则数量: {len(rules)}\n")
                    f.write("payload:\n")
                
                if rule_format == 'yaml':
                    for rule in rules:
                        f.write(f"  - '{rule}'\n")
                else:
                    f.write('\n'.join(rules))
            
            if not output_path.endswith('.tmp'):
                self._log_generated_rule_file(rule_format, output_path, len(rules))
        except Exception as e:
            self.logger.error(f"写入失败 {output_path}: {e}")

    def _log_generated_rule_file(self, rule_format: str, output_path: str, rule_count: int):
        self.logger.info(f"✅ 已生成 {rule_format} 文件: {output_path} ({rule_count} 条)")


def main():
    merger = RulesMerger('config.yaml')
    merger.merge_rules()


if __name__ == '__main__':
    main()
