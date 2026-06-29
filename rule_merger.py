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

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# 支持任意位置、任意数量 * 通配符的域名正则
DOMAIN_PATTERN = re.compile(
    r'^(?:\.?(\*|[a-zA-Z0-9*](?:[a-zA-Z0-9*-]*[a-zA-Z0-9*])?))'
    r'(?:\.(?:\*|[a-zA-Z0-9*](?:[a-zA-Z0-9*-]*[a-zA-Z0-9*])?))*$'
)

MIHOMO_PATH = 'mihomo'
SING_BOX_PATH = 'sing-box'
SING_BOX_RULESET_VERSION = 4

# sing-box 标准支持的列表字段
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

    def _load_config(self, path: str) -> dict:
        """加载配置文件"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            self.logger.error(f"配置文件不存在: {path}")
            raise
        except yaml.YAMLError as e:
            self.logger.error(f"配置文件解析失败: {e}")
            raise

    def _make_temp_path(self, suffix: str) -> str:
        """创建临时文件路径并立即关闭句柄，方便外部工具读写。"""
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        return path
    
    def _fetch_http_rules(self, url: str, rule_format: str, behavior: str = 'classical') -> List[str]:
        """获取在线规则"""
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            if rule_format == 'json':
                return self._read_sing_box_source(response.text)

            if rule_format == 'srs':
                tmp_path = self._make_temp_path('.srs')
                with open(tmp_path, 'wb') as tmp_in:
                    tmp_in.write(response.content)

                try:
                    return self._read_srs_file(tmp_path)
                finally:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
            
            content_type = response.headers.get('content-type', '')
            is_yaml = (rule_format == 'yaml') or (rule_format not in ('mrs', 'text', 'json', 'srs') and ('yaml' in content_type or url.endswith(('.yml', '.yaml'))))
            
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
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)

            return response.text.splitlines()
        except Exception as e:
            self.logger.error(f"获取规则失败 {url}: {str(e)}", exc_info=True)
            return []

    def _fetch_http_srs_rules(self, url: str) -> List[str]:
        """下载 json 格式规则，编译为 srs 验证后再解压读取"""
        if not self.sing_box_path:
            self.logger.error("未找到 sing-box")
            return []
        json_path = self._make_temp_path('.json')
        srs_path = self._make_temp_path('.srs')
        out_json = self._make_temp_path('.json')
        try:
            r = requests.get(url, timeout=20)
            r.raise_for_status()
            
            with open(json_path, 'wb') as f:
                f.write(r.content)
            
            if not self._convert_to_srs(json_path, srs_path):
                self.logger.error(f"从 {url} 下载的 JSON 编译为 SRS 失败，可能是非标准 Rule-set 格式")
                return []
            
            cmd = [self.sing_box_path, 'rule-set', 'decompile', '--output', out_json, srs_path]
            rs = subprocess.run(cmd, capture_output=True, text=True)
            if rs.returncode != 0:
                self.logger.error(f"反编译 SRS 失败: {rs.stderr}")
                return []
            
            with open(out_json, 'r', encoding='utf-8') as f:
                return self._read_sing_box_source(f.read())
        except Exception as e:
            self.logger.error(f"处理 HTTP SRS 规则链条失败: {e}", exc_info=True)
            return []
        finally:
            for p in (json_path, srs_path, out_json):
                if os.path.exists(p): 
                    os.unlink(p)

    def _read_local_rules(self, path: str, rule_format: str, behavior: str = 'classical') -> List[str]:
        """读取本地规则"""
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
                return f.read().splitlines()
        except Exception as e:
            self.logger.error(f"读取本地规则失败 {path}: {str(e)}")
            return []

    def _extract_yaml_rules(self, data: Any, source: str) -> List[str]:
        """从 YAML 内容中提取规则列表。"""
        if data is None:
            return []
        if isinstance(data, dict):
            payload = data.get('payload')
            if isinstance(payload, list):
                return payload
            self.logger.warning(f"YAML规则缺少有效payload列表: {source}")
            return []
        if isinstance(data, list):
            return data
        self.logger.warning(f"YAML规则格式不支持: {source}")
        return []
    
    def _clean_rule(self, rule: str) -> str:
        """清理规则中的注释内容"""
        rule = rule.strip()
        if rule.startswith('#'):
            return ''
        parts = re.split(r'\s+#', rule)
        if len(parts) > 1:
            rule = parts[0]
        return rule.strip()

    def _process_source_to_atom(self, source: Dict) -> Dict[str, set]:
        """
        处理单个规则源并将其分类打散为原子级 set，在最细粒度层面实现混合源完美去重。
        """
        atom_bucket = {
            'domain': set(), 'domain_suffix': set(), 'domain_keyword': set(), 'domain_regex': set(),
            'ip_cidr': set(), 'port': set(), 'network': set(), 'classical_raw': set()
        }
        
        rule_format = source.get('format', 'yaml')
        if rule_format == 'jxon': 
            rule_format = 'json'
            
        default_behavior = 'sing-box' if rule_format in ('json', 'srs') else 'classical'
        source_behavior = source.get('behavior', default_behavior)
        if source_behavior == 'singbox': 
            source_behavior = 'sing-box'

        source_type = source.get('type')
        rules = []
        if source_type == 'http':
            url = source.get('url')
            if not url:
                self.logger.warning("http规则源缺少url")
                return atom_bucket
            if rule_format == 'json' or url.lower().split('?')[0].endswith('.json'):
                rules = self._fetch_http_srs_rules(url)
            else:
                rules = self._fetch_http_rules(url, rule_format, source_behavior)
        elif source_type == 'file':
            path = source.get('path')
            if not path:
                self.logger.warning("file规则源缺少path")
                return atom_bucket
            rules = self._read_local_rules(path, rule_format, source_behavior)
        else:
            self.logger.warning(f"不支持的规则源类型: {source_type}")
            return atom_bucket

        for rule in rules:
            if rule is None: 
                continue
            
            # 1. 如果上游是 sing-box JSON 结构，解包其内容并归类
            if source_behavior == 'sing-box':
                parsed = self._parse_sing_box_rule(str(rule))
                if parsed:
                    for item in self._iter_sing_box_rules(parsed):
                        for k in atom_bucket.keys():
                            if k in item:
                                atom_bucket[k].update(self._as_list(item[k]))
                continue

            # 2. 如果上游是常规文本规则（Mihomo / 纯文本）
            cleaned = self._clean_rule(str(rule))
            if not cleaned: 
                continue

            if source_behavior == 'domain':
                if cleaned.startswith('+.'):
                    if self._validate_domain_rule(cleaned):
                        atom_bucket['domain_suffix'].add(cleaned[2:])
                else:
                    if self._validate_domain_rule(cleaned):
                        atom_bucket['domain'].add(cleaned)
                        
            elif source_behavior == 'ipcidr':
                if self._validate_ipcidr_rule(cleaned):
                    atom_bucket['ip_cidr'].add(cleaned)
                    
            elif source_behavior == 'classical':
                parts = [p.strip() for p in cleaned.split(',')]
                if len(parts) < 2: 
                    continue
                rtype = parts[0].upper()
                rval = parts[1]
                
                mapping = {
                    'DOMAIN': 'domain', 
                    'DOMAIN-SUFFIX': 'domain_suffix', 
                    'DOMAIN-KEYWORD': 'domain_keyword', 
                    'DOMAIN-REGEX': 'domain_regex',
                    'IP-CIDR': 'ip_cidr', 
                    'IP-CIDR6': 'ip_cidr', 
                    'DST-PORT': 'port', 
                    'PORT': 'port'
                }
                
                if rtype in mapping:
                    if rtype in ('DOMAIN', 'DOMAIN-SUFFIX') and not DOMAIN_PATTERN.match(rval):
                        continue
                    if rtype == 'IP-CIDR' and self._get_ipcidr_version(rval) != 4:
                        continue
                    if rtype == 'IP-CIDR6' and self._get_ipcidr_version(rval) != 6:
                        continue
                    
                    if mapping[rtype] == 'port':
                        for sp in [p.strip() for p in rval.split('/')]:
                            if sp.isdigit():
                                atom_bucket['port'].add(int(sp))
                            else:
                                atom_bucket['port'].add(sp)
                    else:
                        atom_bucket[mapping[rtype]].add(rval)
                elif rtype == 'NETWORK':
                    atom_bucket['network'].add(rval.lower())
                else:
                    atom_bucket['classical_raw'].add(cleaned)

        return atom_bucket
    
    def merge_rules(self) -> None:
        """合并所有规则并生成目标格式文件"""
        for config in self.config:
            if 'upstream' not in config or not config.get('path'):
                continue
            
            target_format = config.get('format', 'yaml')
            default_behavior = 'sing-box' if target_format in ('json', 'srs') else 'classical'
            target_behavior = config.get('behavior', default_behavior)
            
            if target_behavior == 'singbox':
                target_behavior = 'sing-box'

            if target_format == 'mrs' and target_behavior not in ('domain', 'ipcidr'):
                self.logger.info(f"{config.get('path')}: mrs格式仅支持domain/ipcidr")
                continue
            
            # 全局原子存储桶，用于交叉合并时天然去重
            total_bucket = {
                'domain': set(), 'domain_suffix': set(), 'domain_keyword': set(), 'domain_regex': set(),
                'ip_cidr': set(), 'port': set(), 'network': set(), 'classical_raw': set()
            }

            # 收集所有上游源
            for source_config in config['upstream'].values():
                source_atom = self._process_source_to_atom(source_config)
                for k in total_bucket.keys():
                    total_bucket[k].update(source_atom[k])
            
            # 根据目标行为 (Target Behavior) 重组并打包数据
            final_rules = []

            # 【核心修复】：如果目标是 sing-box，将每个原子规则项包装为独立的单条 JSON 规则对象
            # 这样可以在 `rules` 列表中展现真实的规则条目总数，并完美兼容底层编译器结构。
            if target_behavior == 'sing-box':
                for d in sorted(list(total_bucket['domain'])):
                    final_rules.append(json.dumps({'domain': [d]}, ensure_ascii=False))
                for s in sorted(list(total_bucket['domain_suffix'])):
                    final_rules.append(json.dumps({'domain_suffix': [s]}, ensure_ascii=False))
                for k in sorted(list(total_bucket['domain_keyword'])):
                    final_rules.append(json.dumps({'domain_keyword': [k]}, ensure_ascii=False))
                for r in sorted(list(total_bucket['domain_regex'])):
                    final_rules.append(json.dumps({'domain_regex': [r]}, ensure_ascii=False))
                for ip in sorted(list(total_bucket['ip_cidr'])):
                    final_rules.append(json.dumps({'ip_cidr': [ip]}, ensure_ascii=False))
                for p in sorted(list(total_bucket['port']), key=lambda x: (0, int(x)) if str(x).isdigit() else (1, str(x))):
                    final_rules.append(json.dumps({'port': [p]}, ensure_ascii=False))
                for n in sorted(list(total_bucket['network'])):
                    final_rules.append(json.dumps({'network': [n]}, ensure_ascii=False))
                    
            elif target_behavior == 'domain':
                final_rules.extend(sorted(list(total_bucket['domain'])))
                for suffix in sorted(list(total_bucket['domain_suffix'])):
                    final_rules.append(f"+.{suffix}")
                    
            elif target_behavior == 'ipcidr':
                final_rules.extend(sorted(list(total_bucket['ip_cidr'])))
                
            elif target_behavior == 'classical':
                for d in sorted(list(total_bucket['domain'])): 
                    final_rules.append(f"DOMAIN,{d}")
                for s in sorted(list(total_bucket['domain_suffix'])): 
                    final_rules.append(f"DOMAIN-SUFFIX,{s}")
                for k in sorted(list(total_bucket['domain_keyword'])): 
                    final_rules.append(f"DOMAIN-KEYWORD,{k}")
                for r in sorted(list(total_bucket['domain_regex'])): 
                    final_rules.append(f"DOMAIN-REGEX,{r}")
                for ip in sorted(list(total_bucket['ip_cidr'])):
                    prefix = "IP-CIDR6" if ":" in ip else "IP-CIDR"
                    final_rules.append(f"{prefix},{ip}")
                for p in sorted(list(total_bucket['port']), key=lambda x: str(x)): 
                    final_rules.append(f"DST-PORT,{p}")
                for n in sorted(list(total_bucket['network'])): 
                    final_rules.append(f"NETWORK,{n.upper()}")
                final_rules.extend(sorted(list(total_bucket['classical_raw'])))

            output_file = config['path']
            self._write_rules(
                output_file,
                final_rules,
                target_format,
                target_behavior,
                config.get('version', SING_BOX_RULESET_VERSION)
            )

    def _write_rules(
        self,
        output_path: str,
        rules: List[str],
        rule_format: str = 'yaml',
        behavior: str = 'classical',
        version: int = SING_BOX_RULESET_VERSION
    ) -> None:
        """写入规则到文件"""
        try:
            output_dir = os.path.dirname(output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

            if rule_format == 'mrs':
                tmp_path = self._make_temp_path('.tmp')
                self._write_rules(tmp_path, rules, 'text', behavior, version)

                try:
                    if self._convert_to_mrs(tmp_path, output_path, behavior):
                        self._log_generated_rule_file('mrs', output_path, len(rules))
                    else:
                        self.logger.error(f"生成 mrs 规则文件失败: {output_path}")
                finally:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                return

            if rule_format == 'srs':
                tmp_path = self._make_temp_path('.json')
                self._write_sing_box_source(tmp_path, rules, version)

                try:
                    if self._convert_to_srs(tmp_path, output_path):
                        self._log_generated_rule_file('srs', output_path, len(rules))
                    else:
                        self.logger.error(f"生成 srs 规则文件失败: {output_path}")
                finally:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                return

            if rule_format == 'json':
                self._write_sing_box_source(output_path, rules, version)
                self._log_generated_rule_file('json', output_path, len(rules))
                return
            
            with open(output_path, 'w', encoding='utf-8') as f:
                if not output_path.endswith('.tmp'):
                    f.write(f"# 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# 规则数量: {len(rules)}\n")
                if rule_format == 'yaml':
                    yaml_str = yaml.dump(
                        {'payload': rules}, 
                        allow_unicode=True, 
                        indent=2,
                        default_flow_style=False,
                        sort_keys=False
                    )
                    formatted_yaml = yaml_str.replace('\n-', '\n  -')
                    f.write(formatted_yaml)
                else:
                    for rule in rules:
                        f.write(f"{rule}\n")
            if not output_path.endswith('.tmp'):
                self._log_generated_rule_file(rule_format, output_path, len(rules))
        except Exception as e:
            self.logger.error(f"写入规则文件失败: {str(e)}", exc_info=True)
            raise

    def _log_generated_rule_file(self, rule_format: str, output_path: str, rule_count: int) -> None:
        self.logger.info(f"已生成 {rule_format} 规则文件: {output_path}, 共 {rule_count} 条规则")

    def _write_sing_box_source(
        self,
        output_path: str,
        rules: List[str],
        version: int = SING_BOX_RULESET_VERSION
    ) -> None:
        """写入 sing-box source rule-set JSON。"""
        parsed_rules = []
        for r in rules:
            try:
                parsed_rules.append(json.loads(r))
            except json.JSONDecodeError:
                continue

        rule_set = {
            'version': version,
            'rules': parsed_rules
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(rule_set, f, ensure_ascii=False, indent=2)
            f.write('\n')

    def _read_sing_box_source(self, content: str) -> List[str]:
        """读取 sing-box source rule-set JSON，返回规范化 headless rule 字符串列表。"""
        try:
            data = json.loads(content.lstrip('\ufeff'))
        except json.JSONDecodeError as e:
            self.logger.error(f"sing-box json 解析失败: {e}")
            return []

        if not isinstance(data, dict):
            self.logger.error("sing-box json 顶层必须是对象")
            return []

        rules = data.get('rules', [])
        if not isinstance(rules, list):
            self.logger.error("sing-box json rules 必须是列表")
            return []

        normalized_rules = []
        for rule in rules:
            normalized_rule = self._normalize_sing_box_rule(rule)
            if normalized_rule:
                normalized_rules.append(normalized_rule)
        return normalized_rules

    def _normalize_sing_box_rule(self, rule: Any) -> Optional[str]:
        if not isinstance(rule, dict):
            return None
        return json.dumps(rule, ensure_ascii=False, sort_keys=True, separators=(',', ':'))

    def _parse_sing_box_rule(self, rule: str) -> Optional[Dict[str, Any]]:
        try:
            parsed = json.loads(rule)
        except (TypeError, json.JSONDecodeError):
            return None
        return parsed if isinstance(parsed, dict) else None

    def _iter_sing_box_rules(self, rule: Dict[str, Any]) -> List[Dict[str, Any]]:
        rules = [rule]
        if rule.get('type') == 'logical':
            for nested_rule in self._as_list(rule.get('rules')):
                if isinstance(nested_rule, dict):
                    rules.extend(self._iter_sing_box_rules(nested_rule))
        return rules

    def _as_list(self, value: Any) -> List[Any]:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    def _validate_ipcidr_rule(self, rule: str) -> Optional[str]:
        """验证 IP-CIDR 规则格式"""
        if self._get_ipcidr_version(rule):
            return rule
        self.logger.debug(f"IP-CIDR 规则验证失败: {rule}")
        return None

    def _get_ipcidr_version(self, rule: str) -> Optional[int]:
        try:
            return ipaddress.ip_network(rule, strict=False).version
        except ValueError:
            return None

    def _validate_domain_rule(self, rule: str) -> Optional[str]:
        """验证域名规则格式"""
        domain = rule[2:] if rule.startswith('+.') else rule
        if DOMAIN_PATTERN.match(domain):
            return rule
        self.logger.debug(f"域名规则验证失败: {rule}")
        return None

    def _read_mrs_file(self, input_path: str, behavior: str) -> List[str]:
        """读取mrs文件"""
        if not self.mihomo_path:
            self.logger.warning("未找到 mihomo，无法读取mrs文件")
            return []
        output_path = self._make_temp_path('.txt')
        try:
            cmd = [self.mihomo_path, 'convert-ruleset', behavior, 'mrs', input_path, output_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                self.logger.error(f"读取mrs失败: {result.stderr}")
                return []
            with open(output_path, 'r', encoding='utf-8') as f:
                return f.read().splitlines()
        except Exception as e:
            self.logger.error(f"读取mrs失败: {str(e)}")
            return []
        finally:
            if os.path.exists(output_path):
                try: os.unlink(output_path)
                except OSError: pass

    def _read_srs_file(self, input_path: str) -> List[str]:
        """读取 sing-box srs 文件。"""
        if not self.sing_box_path:
            self.logger.warning("未找到 sing-box，无法读取srs文件")
            return []
        output_path = self._make_temp_path('.json')
        try:
            cmd = [self.sing_box_path, 'rule-set', 'decompile', '--output', output_path, input_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                self.logger.error(f"读取srs失败: {result.stderr}")
                return []
            with open(output_path, 'r', encoding='utf-8') as f:
                return self._read_sing_box_source(f.read())
        except Exception as e:
            self.logger.error(f"读取srs失败: {str(e)}")
            return []
        finally:
            if os.path.exists(output_path):
                try: os.unlink(output_path)
                except OSError: pass

    def _convert_to_mrs(self, input_path: str, output_path: str, behavior: str) -> bool:
        """将 text 规则文件转换为 mrs 格式"""
        if not self.mihomo_path:
            self.logger.error("未找到 mihomo，无法生成 mrs 文件")
            return False
        try:
            cmd = [self.mihomo_path, 'convert-ruleset', behavior, 'text', input_path, output_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                self.logger.error(f"生成 mrs 失败: {result.stderr}")
                return False
            return True
        except Exception as e:
            self.logger.error(f"生成 mrs 过程中发生错误: {str(e)}")
            return False

    def _convert_to_srs(self, input_path: str, output_path: str) -> bool:
        """将 sing-box source JSON 转换为 srs 格式"""
        if not self.sing_box_path:
            self.logger.error("未找到 sing-box，无法生成 srs 文件")
            return False
        try:
            cmd = [self.sing_box_path, 'rule-set', 'compile', '--output', output_path, input_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                self.logger.error(f"生成 srs 失败: {result.stderr}")
                return False
            return True
        except Exception as e:
            self.logger.error(f"生成 srs 过程中发生错误: {str(e)}")
            return False

def main():
    merger = RulesMerger('config.yaml')
    merger.merge_rules()

if __name__ == '__main__':
    main()
