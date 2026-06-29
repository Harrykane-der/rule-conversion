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
PORT_PATTERN = re.compile(r'^\d+(?:-\d+)?$')

MIHOMO_PATH = 'mihomo'
SING_BOX_PATH = 'sing-box'
SING_BOX_RULESET_VERSION = 5

SING_BOX_LIST_FIELDS = (
    'domain',
    'domain_suffix',
    'domain_keyword',
    'domain_regex',
    'ip_cidr',
    'port',
    'network'
)

class RulesMerger:
    def __init__(self, config_path: str):
        self.logger = logging.getLogger(__name__)
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

    def _normalize_behavior(self, behavior: Optional[str]) -> str:
        if not behavior: return 'classical'
        b = behavior.strip().lower()
        return 'sing-box' if b in ('singbox', 'sing-box') else b

    def _load_config(self, path: str) -> dict:
        try:
            with open(path, 'r', encoding='utf-8') as f: return yaml.safe_load(f)
        except Exception as e:
            self.logger.error(f"加载配置文件失败: {e}")
            raise

    def _make_temp_path(self, suffix: str) -> str:
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        return path
    
    def _fetch_http_rules(self, url: str, rule_format: str, behavior: str) -> List[Any]:
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            if rule_format == 'json': return self._parse_sing_box_source_to_list(response.text)
            if rule_format == 'srs':
                tmp_path = self._make_temp_path('.srs')
                with open(tmp_path, 'wb') as tmp_in: tmp_in.write(response.content)
                try: return self._parse_sing_box_source_to_list(self._decompile_srs_to_json_str(tmp_path))
                finally:
                    if os.path.exists(tmp_path): os.unlink(tmp_path)
            content_type = response.headers.get('content-type', '')
            is_yaml = (rule_format == 'yaml') or (rule_format not in ('mrs', 'text', 'json', 'srs') and ('yaml' in content_type or url.endswith(('.yml', '.yaml'))))
            if is_yaml: return self._extract_yaml_rules(yaml.safe_load(response.text), url)
            if rule_format == 'mrs':
                tmp_path = self._make_temp_path('.mrs')
                with open(tmp_path, 'wb') as tmp_in: tmp_in.write(response.content)
                try: return self._read_mrs_file(tmp_path, behavior)
                finally:
                    if os.path.exists(tmp_path): os.unlink(tmp_path)
            return response.text.splitlines()
        except Exception as e:
            self.logger.error(f"获取在线规则失败 {url}: {str(e)}")
            return []
    
    def _read_local_rules(self, path: str, rule_format: str, behavior: str) -> List[Any]:
        try:
            if rule_format == 'mrs': return self._read_mrs_file(path, behavior)
            if rule_format == 'srs': return self._parse_sing_box_source_to_list(self._decompile_srs_to_json_str(path))
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                if rule_format == 'json': return self._parse_sing_box_source_to_list(content)
                if rule_format == 'yaml': return self._extract_yaml_rules(yaml.safe_load(content), path)
                return content.splitlines()
        except Exception as e:
            self.logger.error(f"读取本地规则失败 {path}: {str(e)}")
            return []

    def _parse_sing_box_source_to_list(self, content: str) -> List[Dict[str, Any]]:
        try:
            data = json.loads(content.lstrip('\ufeff'))
            if isinstance(data, dict) and 'rules' in data and isinstance(data['rules'], list): return data['rules']
            return data if isinstance(data, list) else []
        except: return []

    def _extract_yaml_rules(self, data: Any, source: str) -> List[str]:
        if data is None: return []
        if isinstance(data, dict):
            payload = data.get('payload')
            return payload if isinstance(payload, list) else []
        return data if isinstance(data, list) else []
    
    def _clean_rule(self, rule: str) -> str:
        rule = rule.strip()
        if rule.startswith('#'): return ''
        parts = re.split(r'\s+#', rule)
        return parts[0].strip() if len(parts) > 1 else rule

    def _transform(self, rule: Any, source_behavior: str, target_behavior: str) -> List[Any]:
        source_behavior, target_behavior = self._normalize_behavior(source_behavior), self._normalize_behavior(target_behavior)
        if isinstance(rule, dict):
            return [rule] if target_behavior == 'sing-box' else (self._transformers.get(('sing-box', target_behavior))(json.dumps(rule)) or [])
        if not rule or source_behavior == target_behavior: return [rule] if rule else []
        transformer = self._transformers.get((source_behavior, target_behavior))
        return transformer(rule) if transformer else []

    def _process_source(self, source: Dict, target_behavior: str) -> List[Any]:
        rule_format = source.get('format', 'yaml')
        source_behavior = self._normalize_behavior(source.get('behavior', 'sing-box' if rule_format in ('json', 'srs') else 'classical'))
        source_type = source.get('type')
        rules = self._fetch_http_rules(source.get('url', ''), rule_format, source_behavior) if source_type == 'http' else self._read_local_rules(source.get('path', ''), rule_format, source_behavior)
        converted_rules = []
        for rule in rules:
            if rule is None: continue
            cleaned_rule = rule if isinstance(rule, dict) or source_behavior == 'sing-box' else self._clean_rule(str(rule))
            transformed = self._transform(cleaned_rule, source_behavior, target_behavior)
            if transformed: converted_rules.extend(transformed if isinstance(transformed, list) else [transformed])
        return converted_rules
    
    def merge_rules(self) -> None:
        for config in self.config:
            if 'upstream' not in config or not config.get('path'): continue
            target_format = config.get('format', 'yaml')
            target_behavior = self._normalize_behavior(config.get('behavior', 'sing-box' if target_format in ('json', 'srs') else 'classical'))
            raw_collected = []
            for source_config in config['upstream'].values(): raw_collected.extend(self._process_source(source_config, target_behavior))
            dict_rules = [r for r in raw_collected if isinstance(r, dict)]
            str_rules = sorted(set([r for r in raw_collected if isinstance(r, str)]))
            final_rules = self._compile_final_sing_box_list(str_rules, dict_rules) if target_behavior == 'sing-box' else str_rules
            self._write_rules(config['path'], final_rules, target_format, target_behavior, config.get('version', SING_BOX_RULESET_VERSION))

    def _compile_final_sing_box_list(self, converted_str_rules: List[str], original_dict_rules: List[Dict]) -> List[Dict]:
        bucket = {key: [] for key in SING_BOX_LIST_FIELDS}
        passthrough_rules = []
        for rule_str in converted_str_rules:
            parsed = self._parse_sing_box_rule(rule_str)
            if not parsed: continue
            if self._can_compact_sing_box_rule(parsed): self._add_sing_box_rule_items(bucket, parsed)
            else: passthrough_rules.append(parsed)
        all_rules_pool = self._compact_sing_box_rules(bucket) + passthrough_rules + original_dict_rules
        seen, unique = set(), []
        for r in all_rules_pool:
            sig = json.dumps(r, ensure_ascii=False, sort_keys=True)
            if sig not in seen:
                seen.add(sig)
                unique.append(r)
        return unique

    def _can_compact_sing_box_rule(self, rule: Dict[str, Any]) -> bool:
        if rule.get('type') == 'logical': return False
        for key, value in rule.items():
            if key not in SING_BOX_LIST_FIELDS: return False
            if not all(isinstance(item, (str, int)) for item in self._as_list(value)): return False
        return True

    def _add_sing_box_rule_items(self, bucket: Dict[str, List[Any]], rule: Dict[str, Any]) -> None:
        for key in SING_BOX_LIST_FIELDS:
            if key in rule:
                raw_values = self._as_list(rule.get(key))
                if key == 'port': bucket[key].extend([int(v) if str(v).isdigit() else v for v in raw_values])
                elif key == 'network': bucket[key].extend([str(v).lower() for v in raw_values])
                else: bucket[key].extend(raw_values)

    def _compact_sing_box_rules(self, bucket: Dict[str, List[Any]]) -> List[Dict[str, List[Any]]]:
        compacted = []
        for key in SING_BOX_LIST_FIELDS:
            values = list(set(bucket.get(key, [])))
            if values:
                vals = sorted(values, key=lambda x: str(x))
                compacted.append({key: vals})
        return compacted

    def _write_rules(self, output_path: str, rules: List[Any], rule_format: str, behavior: str, version: int) -> None:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        if rule_format == 'mrs':
            tmp = self._make_temp_path('.tmp')
            self._write_rules(tmp, rules, 'text', behavior, version)
            try: self._convert_to_mrs(tmp, output_path, behavior)
            finally:
                if os.path.exists(tmp): os.unlink(tmp)
        elif rule_format == 'srs':
            tmp = self._make_temp_path('.json')
            self._write_sing_box_source_direct(tmp, rules, version)
            try: self._convert_to_srs(tmp, output_path)
            finally:
                if os.path.exists(tmp): os.unlink(tmp)
        elif rule_format == 'json': self._write_sing_box_source_direct(output_path, rules, version)
        else:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(f"# 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n# 规则数量: {len(rules)}\n")
                if rule_format == 'yaml': f.write(yaml.dump({'payload': rules}, allow_unicode=True, indent=2, sort_keys=False).replace('\n-', '\n  -'))
                else: f.writelines(f"{r}\n" for r in rules)

    def _write_sing_box_source_direct(self, output_path: str, rules: List[Dict], version: int) -> None:
        with open(output_path, 'w', encoding='utf-8') as f: json.dump({'version': version, 'rules': rules}, f, ensure_ascii=False, indent=2)

    def _to_sing_box_item(self, rule: str, behavior: str) -> Optional[tuple[str, Any]]:
        # --- 核心修改处 ---
        if behavior == 'domain':
            if rule.startswith(('+.', '*.')): return 'domain_suffix', rule[2:]
            return 'domain', rule
        # ----------------
        if behavior == 'ipcidr': return 'ip_cidr', rule
        if behavior != 'classical': return None
        parts = [p.strip() for p in rule.split(',')]
        if len(parts) < 2: return None
        mapping = {'DOMAIN': 'domain', 'DOMAIN-SUFFIX': 'domain_suffix', 'DOMAIN-KEYWORD': 'domain_keyword', 'DOMAIN-REGEX': 'domain_regex', 'IP-CIDR': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 'PORT': 'port', 'DST-PORT': 'port', 'NETWORK': 'network'}
        target_key = mapping.get(parts[0])
        # 兼容 DOMAIN 类型下带 *. 的情况
        if parts[0] == 'DOMAIN' and parts[1].startswith(('+.', '*.')): return 'domain_suffix', parts[1][2:]
        return (target_key, int(parts[1]) if target_key == 'port' and parts[1].isdigit() else (parts[1].lower() if target_key == 'network' else parts[1])) if target_key else None

    def _classical_to_sing_box(self, rule: str) -> Optional[str]:
        item = self._to_sing_box_item(rule, 'classical')
        return json.dumps({item[0]: [item[1]]}) if item else None

    def _domain_to_sing_box(self, rule: str) -> Optional[str]:
        item = self._to_sing_box_item(rule, 'domain')
        return json.dumps({item[0]: [item[1]]}) if item else None

    def _ipcidr_to_sing_box(self, rule: str) -> Optional[str]:
        return json.dumps({'ip_cidr': [rule]})

    def _parse_sing_box_rule(self, rule: str) -> Optional[Dict]:
        try: return json.loads(rule) if isinstance(rule, str) else None
        except: return None

    def _classical_to_domain(self, rule: str) -> Optional[str]:
        parts = rule.split(',')
        if len(parts) < 2: return None
        suffix, domain = parts[0].strip(), parts[1].strip()
        if suffix == 'DOMAIN' and domain.startswith(('+.', '*.')): suffix, domain = 'DOMAIN-SUFFIX', domain[2:]
        return domain if suffix == 'DOMAIN' else (f"+.{domain}" if suffix == 'DOMAIN-SUFFIX' else None)

    def _validate_domain_rule(self, rule: str) -> Optional[str]:
        clean = rule[2:] if rule.startswith(('+.', '*.')) else rule
        return rule if DOMAIN_PATTERN.match(clean) else None

    def _classical_to_ipcidr(self, rule: str) -> Optional[str]:
        parts = rule.split(',')
        return parts[1].strip() if len(parts) >= 2 and parts[0].strip() in ('IP-CIDR', 'IP-CIDR6') else None

    def _ipcidr_to_classical(self, rule: str) -> Optional[str]:
        v = ipaddress.ip_network(rule, strict=False).version
        return f"IP-CIDR6,{rule}" if v == 6 else f"IP-CIDR,{rule}"

    def _domain_to_classical(self, rule: str) -> Optional[str]:
        if rule.startswith(('+.', '*.')): return f"DOMAIN-SUFFIX,{rule[2:]}"
        return f"DOMAIN,{rule}"

    def _sing_box_to_domain(self, rule_str: str) -> List[str]:
        parsed = self._parse_sing_box_rule(rule_str)
        if not parsed: return []
        res = []
        for item in self._iter_sing_box_rules(parsed):
            res.extend(self._as_list(item.get('domain')))
            res.extend([f"+.{s.lstrip('.')}" for s in self._as_list(item.get('domain_suffix'))])
        return res

    def _sing_box_to_ipcidr(self, rule_str: str) -> List[str]:
        parsed = self._parse_sing_box_rule(rule_str)
        if not parsed: return []
        return [str(ip) for item in self._iter_sing_box_rules(parsed) for ip in self._as_list(item.get('ip_cidr'))]

    def _sing_box_to_classical(self, rule_str: str) -> List[str]:
        parsed = self._parse_sing_box_rule(rule_str)
        if not parsed: return []
        res = []
        for item in self._iter_sing_box_rules(parsed):
            res.extend([f"DOMAIN,{d}" for d in self._as_list(item.get('domain'))])
            res.extend([f"DOMAIN-SUFFIX,{s.lstrip('.')}" for s in self._as_list(item.get('domain_suffix'))])
            res.extend([f"IP-CIDR6,{ip}" if ':' in str(ip) else f"IP-CIDR,{ip}" for ip in self._as_list(item.get('ip_cidr'))])
        return res

    def _iter_sing_box_rules(self, rule: Dict) -> List[Dict]:
        rules = [rule]
        if rule.get('type') == 'logical':
            for nested in self._as_list(rule.get('rules')):
                if isinstance(nested, dict): rules.extend(self._iter_sing_box_rules(nested))
        return rules

    def _as_list(self, value: Any) -> List[Any]: return value if isinstance(value, list) else ([value] if value is not None else [])

    def _read_mrs_file(self, path: str, b: str) -> List[str]:
        out = self._make_temp_path('.txt')
        try:
            if subprocess.run([self.mihomo_path, 'convert-ruleset', b, 'text', path, out]).returncode == 0:
                with open(out, 'r', encoding='utf-8') as f: return f.read().splitlines()
        finally:
            if os.path.exists(out): os.unlink(out)
        return []

    def _decompile_srs_to_json_str(self, path: str) -> str:
        out = self._make_temp_path('.json')
        try:
            if subprocess.run([self.sing_box_path, 'rule-set', 'decompile', '--output', out, path]).returncode == 0:
                with open(out, 'r', encoding='utf-8') as f: return f.read()
        finally:
            if os.path.exists(out): os.unlink(out)
        return "{}"

    def _convert_to_mrs(self, src: str, dst: str, b: str) -> bool:
        return subprocess.run([self.mihomo_path, 'convert-ruleset', b, 'mrs', src, dst]).returncode == 0

    def _convert_to_srs(self, src: str, dst: str) -> bool:
        return subprocess.run([self.sing_box_path, 'rule-set', 'compile', '--output', dst, src]).returncode == 0

def main():
    RulesMerger('config.yaml').merge_rules()

if __name__ == '__main__':
    main()
