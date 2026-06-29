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
        """统一 behavior 的命名规范，消除用户在 yaml 里面写 singbox 或 sing-box 的差异"""
        if not behavior:
            return 'classical'
        b = behavior.strip().lower()
        if b in ('singbox', 'sing-box'):
            return 'sing-box'
        return b

    def _load_config(self, path: str) -> dict:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
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

            if rule_format == 'json':
                return self._parse_sing_box_source_to_list(response.text)

            if rule_format == 'srs':
                tmp_path = self._make_temp_path('.srs')
                with open(tmp_path, 'wb') as tmp_in:
                    tmp_in.write(response.content)
                try:
                    decompiled_json = self._decompile_srs_to_json_str(tmp_path)
                    return self._parse_sing_box_source_to_list(decompiled_json)
                finally:
                    if os.path.exists(tmp_path): os.unlink(tmp_path)
            
            content_type = response.headers.get('content-type', '')
            is_yaml = (rule_format == 'yaml') or (
                rule_format not in ('mrs', 'text', 'json', 'srs') and
                ('yaml' in content_type or url.endswith(('.yml', '.yaml')))
            )
            if is_yaml:
                data = yaml.safe_load(response.text)
                return self._extract_yaml_rules(data, url)
            
            if rule_format == 'mrs':
                tmp_path = self._make_temp_path('.mrs')
                with open(tmp_path, 'wb') as tmp_in:
                    tmp_in.write(response.content)
                try:
                    return self._read_mrs_file(tmp_path, behavior)
                finally:
                    if os.path.exists(tmp_path): os.unlink(tmp_path)

            return response.text.splitlines()
        except Exception as e:
            self.logger.error(f"获取在线规则失败 {url}: {str(e)}")
            return []
    
    def _read_local_rules(self, path: str, rule_format: str, behavior: str) -> List[Any]:
        try:
            if rule_format == 'mrs':
                return self._read_mrs_file(path, behavior)
            if rule_format == 'srs':
                decompiled_json = self._decompile_srs_to_json_str(path)
                return self._parse_sing_box_source_to_list(decompiled_json)

            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                if rule_format == 'json':
                    return self._parse_sing_box_source_to_list(content)
                if rule_format == 'yaml':
                    data = yaml.safe_load(content)
                    return self._extract_yaml_rules(data, path)
                return content.splitlines()
        except Exception as e:
            self.logger.error(f"读取本地规则失败 {path}: {str(e)}")
            return []

    def _parse_sing_box_source_to_list(self, content: str) -> List[Dict[str, Any]]:
        try:
            data = json.loads(content.lstrip('\ufeff'))
            if isinstance(data, dict) and 'rules' in data and isinstance(data['rules'], list):
                return data['rules']
            if isinstance(data, list):
                return data
            return []
        except Exception as e:
            self.logger.error(f"解析 sing-box json 失败: {e}")
            return []

    def _extract_yaml_rules(self, data: Any, source: str) -> List[str]:
        if data is None: return []
        if isinstance(data, dict):
            payload = data.get('payload')
            return payload if isinstance(payload, list) else []
        if isinstance(data, list): return data
        return []
    
    def _clean_rule(self, rule: str) -> str:
        rule = rule.strip()
        if rule.startswith('#'): return ''
        parts = re.split(r'\s+#', rule)
        return parts[0].strip() if len(parts) > 1 else rule

    def _transform(self, rule: Any, source_behavior: str, target_behavior: str) -> List[Any]:
        source_behavior = self._normalize_behavior(source_behavior)
        target_behavior = self._normalize_behavior(target_behavior)

        if isinstance(rule, dict):
            if target_behavior == 'sing-box':
                return [rule]  # 目标是 sing-box，原装放行
            
            transformer = self._transformers.get(('sing-box', target_behavior))
            if transformer:
                return transformer(json.dumps(rule))
            return []

        if not rule: return []
        if source_behavior == target_behavior:
            return [rule]

        transformer = self._transformers.get((source_behavior, target_behavior))
        if not transformer: return []
        transformed = transformer(rule)
        if not transformed: return []
        return transformed if isinstance(transformed, list) else [transformed]

    def _process_source(self, source: Dict, target_behavior: str) -> List[Any]:
        rule_format = source.get('format', 'yaml')
        default_behavior = 'sing-box' if rule_format in ('json', 'srs') else 'classical'
        source_behavior = self._normalize_behavior(source.get('behavior', default_behavior))
        target_behavior = self._normalize_behavior(target_behavior)

        source_type = source.get('type')
        if source_type == 'http':
            rules = self._fetch_http_rules(source.get('url', ''), rule_format, source_behavior)
        elif source_type == 'file':
            rules = self._read_local_rules(source.get('path', ''), rule_format, source_behavior)
        else:
            return []

        converted_rules = []
        for rule in rules:
            if rule is None:
                continue

            # 对字符串规则进行统一预处理：清理并转换 *. 为 +.
            if isinstance(rule, str):
                cleaned = self._clean_rule(rule)
                if cleaned.startswith('*.'):
                    cleaned = '+.' + cleaned[2:]
                rule = cleaned
            # 如果是 dict 规则（原生 sing-box），保持原样

            transformed = self._transform(rule, source_behavior, target_behavior)
            if transformed:
                converted_rules.extend(transformed)
        return converted_rules
    
    def merge_rules(self) -> None:
        for config in self.config:
            if 'upstream' not in config or not config.get('path'): continue
            
            target_format = config.get('format', 'yaml')
            default_behavior = 'sing-box' if target_format in ('json', 'srs') else 'classical'
            target_behavior = self._normalize_behavior(config.get('behavior', default_behavior))
            
            raw_collected = []
            for source_config in config['upstream'].values():
                rules = self._process_source(source_config, target_behavior)
                raw_collected.extend(rules)

            # 严格各归各家区分：原生完整的 Dict 规则与单兵转换而来的字符串规则
            dict_rules = [r for r in raw_collected if isinstance(r, dict)]
            str_rules = [r for r in raw_collected if isinstance(r, str)]

            str_rules = sorted(set(str_rules))

            final_rules = []
            if target_behavior == 'sing-box':
                final_rules = self._compile_final_sing_box_list(str_rules, dict_rules)
            else:
                final_rules = str_rules

            output_file = config['path']
            self._write_rules(
                output_file,
                final_rules,
                target_format,
                target_behavior,
                config.get('version', SING_BOX_RULESET_VERSION)
            )

    def _compile_final_sing_box_list(self, converted_str_rules: List[str], original_dict_rules: List[Dict]) -> List[Dict]:
        bucket = {key: [] for key in SING_BOX_LIST_FIELDS}
        passthrough_rules = []

        # 1. 提取并合并【由文本格式转换出来的】零散碎片 JSON
        for rule_str in converted_str_rules:
            parsed = self._parse_sing_box_rule(rule_str)
            if not parsed: continue
            if self._can_compact_sing_box_rule(parsed):
                self._add_sing_box_rule_items(bucket, parsed)
            else:
                passthrough_rules.append(parsed)

        # 2. 压缩合并大桶里的文本转换碎片
        compacted_results = self._compact_sing_box_rules(bucket)
        
        # 3. 精准透传：原装的完整的 original_dict_rules 直接不拆散、不加工、直接原样拼入
        all_rules_pool = compacted_results + passthrough_rules + original_dict_rules

        # 高级精准特征去重
        seen_signatures = set()
        unique_final_rules = []
        for r in all_rules_pool:
            sig = json.dumps(r, ensure_ascii=False, sort_keys=True)
            if sig not in seen_signatures:
                seen_signatures.add(sig)
                unique_final_rules.append(r)

        return unique_final_rules

    def _can_compact_sing_box_rule(self, rule: Dict[str, Any]) -> bool:
        if rule.get('type') == 'logical': return False
        for key, value in rule.items():
            if key not in SING_BOX_LIST_FIELDS: return False
            values = self._as_list(value)
            if not values: continue
            if not all(isinstance(item, (str, int)) for item in values): return False
        return True

    def _add_sing_box_rule_items(self, bucket: Dict[str, List[Any]], rule: Dict[str, Any]) -> None:
        for key in SING_BOX_LIST_FIELDS:
            if key in rule:
                raw_values = self._as_list(rule.get(key))
                if key == 'port':
                    cleaned_values = [int(v) if str(v).isdigit() else str(v) for v in raw_values]
                elif key == 'network':
                    cleaned_values = [str(v).lower() for v in raw_values]
                else:
                    cleaned_values = raw_values
                bucket[key].extend(cleaned_values)

    def _compact_sing_box_rules(self, bucket: Dict[str, List[Any]]) -> List[Dict[str, List[Any]]]:
        compacted_rules = []
        for key in SING_BOX_LIST_FIELDS:
            values = bucket.get(key, [])
            if values:
                unique_values = list(set(values))
                if key == 'port':
                    has_str_range = any(isinstance(v, str) and not v.isdigit() for v in unique_values)
                    if has_str_range:
                        unique_values = [str(v) for v in unique_values]
                        unique_sorted_values = sorted(unique_values)
                    else:
                        unique_values = [int(v) if str(v).isdigit() else v for v in unique_values]
                        unique_sorted_values = sorted(unique_values)
                else:
                    unique_sorted_values = sorted(unique_values, key=lambda x: str(x))
                compacted_rules.append({key: unique_sorted_values})
        return compacted_rules

    def _write_rules(self, output_path: str, rules: List[Any], rule_format: str, behavior: str, version: int) -> None:
        try:
            output_dir = os.path.dirname(output_path)
            if output_dir: os.makedirs(output_dir, exist_ok=True)

            if rule_format == 'mrs':
                tmp_path = self._make_temp_path('.tmp')
                self._write_rules(tmp_path, rules, 'text', behavior, version)
                try:
                    if self._convert_to_mrs(tmp_path, output_path, behavior):
                        self.logger.info(f"已生成 mrs 规则文件: {output_path}, 共 {len(rules)} 条")
                finally:
                    if os.path.exists(tmp_path): os.unlink(tmp_path)
                return

            if rule_format == 'srs':
                tmp_path = self._make_temp_path('.json')
                self._write_sing_box_source_direct(tmp_path, rules, version)
                try:
                    if self._convert_to_srs(tmp_path, output_path):
                        self.logger.info(f"已生成 srs 二进制规则文件: {output_path}")
                finally:
                    if os.path.exists(tmp_path): os.unlink(tmp_path)
                return

            if rule_format == 'json':
                self._write_sing_box_source_direct(output_path, rules, version)
                self.logger.info(f"已生成 json 规则文件: {output_path}")
                return
            
            with open(output_path, 'w', encoding='utf-8') as f:
                if not output_path.endswith('.tmp'):
                    f.write(f"# 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# 规则数量: {len(rules)}\n")
                if rule_format == 'yaml':
                    yaml_str = yaml.dump({'payload': rules}, allow_unicode=True, indent=2, default_flow_style=False, sort_keys=False)
                    f.write(yaml_str.replace('\n-', '\n  -'))
                else:
                    for rule in rules: f.write(f"{rule}\n")
        except Exception as e:
            self.logger.error(f"写入文件失败: {str(e)}")
            raise

    def _write_sing_box_source_direct(self, output_path: str, rules: List[Dict], version: int) -> None:
        rule_set = {'version': version, 'rules': rules}
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(rule_set, f, ensure_ascii=False, indent=2)
            f.write('\n')

    def _classical_to_ipcidr(self, rule: str) -> Optional[str]:
        parts = rule.split(',')
        if len(parts) < 2: return None
        return self._validate_ipcidr_rule(parts[1].strip()) if parts[0].strip() in ('IP-CIDR', 'IP-CIDR6') else None
    
    def _classical_to_domain(self, rule: str) -> Optional[str]:
        parts = rule.split(',')
        if len(parts) < 2: return None
        suffix, domain = parts[0].strip(), parts[1].strip()
        if not DOMAIN_PATTERN.match(domain): return None
        return domain if suffix == 'DOMAIN' else '+.' + domain if suffix == 'DOMAIN-SUFFIX' else None
    
    def _ipcidr_to_classical(self, rule: str) -> Optional[str]:
        v = self._get_ipcidr_version(rule)
        return f"IP-CIDR6,{rule}" if v == 6 else f"IP-CIDR,{rule}" if v == 4 else None
    
    def _domain_to_classical(self, rule: str) -> Optional[str]:
        if rule.startswith('+.'):
            return f"DOMAIN-SUFFIX,{rule[2:]}" if DOMAIN_PATTERN.match(rule[2:]) else None
        return f"DOMAIN,{rule}" if DOMAIN_PATTERN.match(rule) else None

    def _to_sing_box_item(self, rule: str, behavior: str) -> Optional[tuple[str, Any]]:
        if behavior == 'domain':
            return ('domain_suffix', rule[2:]) if rule.startswith('+.') else ('domain', rule)
        if behavior == 'ipcidr':
            return 'ip_cidr', rule
        if behavior != 'classical': return None
        parts = [p.strip() for p in rule.split(',')]
        if len(parts) < 2: return None
        mapping = {
            'DOMAIN': 'domain', 'DOMAIN-SUFFIX': 'domain_suffix', 'DOMAIN-KEYWORD': 'domain_keyword',
            'DOMAIN-REGEX': 'domain_regex', 'IP-CIDR': 'ip_cidr', 'IP-CIDR6': 'ip_cidr',
            'PORT': 'port', 'DST-PORT': 'port', 'NETWORK': 'network'
        }
        target_key = mapping.get(parts[0])
        if not target_key: return None
        if target_key == 'port': return target_key, int(parts[1]) if parts[1].isdigit() else parts[1]
        if target_key == 'network': return target_key, parts[1].lower()
        return target_key, parts[1]

    def _classical_to_sing_box(self, rule: str) -> Optional[str]:
        if not self._validate_classical_rule(rule): return None
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

    def _parse_sing_box_rule(self, rule: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = json.loads(rule)
            return parsed if isinstance(parsed, dict) else None
        except: return None

    def _sing_box_to_domain(self, rule_str: str) -> List[str]:
        parsed = self._parse_sing_box_rule(rule_str)
        if not parsed: return []
        res = []
        for item in self._iter_sing_box_rules(parsed):
            for d in self._as_list(item.get('domain')): res.append(str(d))
            for s in self._as_list(item.get('domain_suffix')):
                s = s[1:] if s.startswith('.') else s
                res.append(f"+.{s}")
        return res

    def _sing_box_to_ipcidr(self, rule_str: str) -> List[str]:
        parsed = self._parse_sing_box_rule(rule_str)
        if not parsed: return []
        res = []
        for item in self._iter_sing_box_rules(parsed):
            for ip in self._as_list(item.get('ip_cidr')): res.append(str(ip))
        return res

    def _sing_box_to_classical(self, rule_str: str) -> List[str]:
        parsed = self._parse_sing_box_rule(rule_str)
        if not parsed: return []
        res = []
        for item in self._iter_sing_box_rules(parsed):
            for d in self._as_list(item.get('domain')): res.append(f"DOMAIN,{d}")
            for s in self._as_list(item.get('domain_suffix')):
                s = s[1:] if s.startswith('.') else s
                res.append(f"DOMAIN-SUFFIX,{s}")
            for k in self._as_list(item.get('domain_keyword')): res.append(f"DOMAIN-KEYWORD,{k}")
            for r in self._as_list(item.get('domain_regex')): res.append(f"DOMAIN-REGEX,{r}")
            for ip in self._as_list(item.get('ip_cidr')):
                res.append(f"IP-CIDR6,{ip}" if ':' in str(ip) else f"IP-CIDR,{ip}")
            for p in self._as_list(item.get('port')): res.append(f"PORT,{p}")
            for n in self._as_list(item.get('network')): res.append(f"NETWORK,{str(n).lower()}")
        return res

    def _iter_sing_box_rules(self, rule: Dict[str, Any]) -> List[Dict[str, Any]]:
        rules = [rule]
        if rule.get('type') == 'logical':
            for nested in self._as_list(rule.get('rules')):
                if isinstance(nested, dict): rules.extend(self._iter_sing_box_rules(nested))
        return rules

    def _as_list(self, value: Any) -> List[Any]:
        if value is None: return []
        return value if isinstance(value, list) else [value]
    
    def _validate_classical_rule(self, rule: str) -> Optional[str]:
        try:
            parts = rule.split(',')
            if len(parts) < 2: return None
            t, v = parts[0].strip(), parts[1].strip()
            comb = ','.join(p.strip() for p in parts)
            if t in {'DOMAIN', 'DOMAIN-SUFFIX'}: return comb if DOMAIN_PATTERN.match(v) else None
            if t == 'IP-CIDR': return comb if self._get_ipcidr_version(v) == 4 else None
            if t == 'IP-CIDR6': return comb if self._get_ipcidr_version(v) == 6 else None
            if t in {'PORT', 'DST-PORT'}: return comb if PORT_PATTERN.match(v) else None
            if t == 'NETWORK': return comb if v.lower() in {'tcp', 'udp'} else None
            return comb
        except: return None

    def _validate_ipcidr_rule(self, rule: str) -> Optional[str]:
        return rule if self._get_ipcidr_version(rule) else None

    def _get_ipcidr_version(self, rule: str) -> Optional[int]:
        try: return ipaddress.ip_network(rule, strict=False).version
        except: return None

    def _validate_domain_rule(self, rule: str) -> Optional[str]:
        return rule if DOMAIN_PATTERN.match(rule[2:] if rule.startswith('+.') else rule) else None

    def _read_mrs_file(self, input_path: str, behavior: str) -> List[str]:
        if not self.mihomo_path: return []
        output_path = self._make_temp_path('.txt')
        try:
            cmd = [self.mihomo_path, 'convert-ruleset', behavior, 'mrs', input_path, output_path]
            if subprocess.run(cmd, capture_output=True, text=True).returncode == 0:
                with open(output_path, 'r', encoding='utf-8') as f: return f.read().splitlines()
            return []
        except: return []
        finally:
            if os.path.exists(output_path): os.unlink(output_path)

    def _decompile_srs_to_json_str(self, input_path: str) -> str:
        if not self.sing_box_path: return "{}"
        output_path = self._make_temp_path('.json')
        try:
            cmd = [self.sing_box_path, 'rule-set', 'decompile', '--output', output_path, input_path]
            if subprocess.run(cmd, capture_output=True, text=True).returncode == 0:
                with open(output_path, 'r', encoding='utf-8') as f: return f.read()
            return "{}"
        except: return "{}"
        finally:
            if os.path.exists(output_path): os.unlink(output_path)

    def _convert_to_mrs(self, input_path: str, output_path: str, behavior: str) -> bool:
        if not self.mihomo_path: 
            self.logger.error("未找到 mihomo 执行路径，无法编译二进制 MRS")
            return False
        res = subprocess.run([self.mihomo_path, 'convert-ruleset', behavior, 'text', input_path, output_path], capture_output=True, text=True)
        if res.returncode != 0:
            self.logger.error(f"mihomo 编译二进制失败: {res.stderr}")
            return False
        return True

    def _convert_to_srs(self, input_path: str, output_path: str) -> bool:
        if not self.sing_box_path: 
            self.logger.error("未找到 sing-box 执行路径，无法编译二进制 SRS")
            return False
        res = subprocess.run([self.sing_box_path, 'rule-set', 'compile', '--output', output_path, input_path], capture_output=True, text=True)
        if res.returncode != 0:
            self.logger.error(f"sing-box 编译二进制失败: {res.stderr}")
            return False
        return True


def main():
    merger = RulesMerger('config.yaml')
    merger.merge_rules()

if __name__ == '__main__':
    main()
