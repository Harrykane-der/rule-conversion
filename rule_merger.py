import yaml
import json
import subprocess
import tempfile
import requests
import os
import logging
from typing import List, Dict, Optional, Any, Set
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
SING_BOX_RULESET_VERSION = 5

# sing-box 1.11+ 标准 Headless 规则支持的数组字段
SING_BOX_LIST_FIELDS = (
    'domain',
    'domain_suffix',
    'domain_keyword',
    'domain_regex',
    'ip_cidr',
    'port',
    'network',
    'package_name',
    'package_name_regex'
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
        """创建临时文件路径并立即关闭句柄"""
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        return path

    def _new_pool(self) -> Dict[str, Set[str]]:
        """创建一个干净的原子规则池，包含所有高级字段"""
        pool = {field: set() for field in SING_BOX_LIST_FIELDS}
        pool['other'] = set()  # 容纳无法归类的特殊文本规则串
        return pool

    def _fetch_http_rules(self, url: str, rule_format: str) -> List[str]:
        """获取在线规则原始行/文本"""
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            if rule_format == 'json':
                return [response.text]

            if rule_format == 'srs':
                tmp_path = self._make_temp_path('.srs')
                with open(tmp_path, 'wb') as tmp_in:
                    tmp_in.write(response.content)
                try:
                    return self._decompile_srs_to_json_str(tmp_path)
                finally:
                    if os.path.exists(tmp_path): os.unlink(tmp_path)

            content_type = response.headers.get('content-type', '')
            is_yaml = (rule_format == 'yaml') or (rule_format not in ('mrs', 'text') and ('yaml' in content_type or url.endswith(('.yml', '.yaml'))))

            if is_yaml:
                data = yaml.safe_load(response.text)
                return self._extract_yaml_rules(data, url)

            if rule_format == 'mrs':
                tmp_path = self._make_temp_path('.mrs')
                with open(tmp_path, 'wb') as tmp_in:
                    tmp_in.write(response.content)
                try:
                    # 尽可能全面地读取 mrs
                    behavior = 'classical'
                    if 'domain' in url.lower(): behavior = 'domain'
                    elif 'ip' in url.lower(): behavior = 'ipcidr'
                    return self._read_mrs_file(tmp_path, behavior)
                finally:
                    if os.path.exists(tmp_path): os.unlink(tmp_path)

            return response.text.splitlines()
        except Exception as e:
            self.logger.error(f"获取规则失败 {url}: {str(e)}")
            return []

    def _decompile_srs_to_json_str(self, srs_path: str) -> List[str]:
        if not self.sing_box_path:
            return []
        out_json = self._make_temp_path('.json')
        try:
            cmd = [self.sing_box_path, 'rule-set', 'decompile', '--output', out_json, srs_path]
            rs = subprocess.run(cmd, capture_output=True, text=True)
            if rs.returncode == 0:
                with open(out_json, 'r', encoding='utf-8') as f:
                    return [f.read()]
            else:
                self.logger.error(f"反编译 SRS 失败: {rs.stderr}")
        except Exception as e:
            self.logger.error(f"反编译过程出错: {e}")
        finally:
            if os.path.exists(out_json): os.unlink(out_json)
        return []

    def _read_local_rules(self, path: str, rule_format: str, behavior: str) -> List[str]:
        """读取本地规则原始行/文本"""
        try:
            if rule_format == 'mrs':
                return self._read_mrs_file(path, behavior)
            if rule_format == 'srs':
                return self._decompile_srs_to_json_str(path)

            with open(path, 'r', encoding='utf-8') as f:
                if rule_format == 'json':
                    return [f.read()]
                if rule_format == 'yaml':
                    data = yaml.safe_load(f)
                    return self._extract_yaml_rules(data, path)
                return f.read().splitlines()
        except Exception as e:
            self.logger.error(f"读取本地规则失败 {path}: {str(e)}")
            return []

    def _extract_yaml_rules(self, data: Any, source: str) -> List[str]:
        if data is None: return []
        if isinstance(data, dict):
            payload = data.get('payload')
            if isinstance(payload, list): return [str(i).strip() for i in payload if i]
        elif isinstance(data, list):
            return [str(i).strip() for i in data if i]
        return []

    def _clean_rule(self, rule: str) -> str:
        rule = rule.strip()
        if rule.startswith('#') or rule.startswith('//'):
            return ''
        parts = re.split(r'\s+#', rule)
        if len(parts) > 1:
            rule = parts[0]
        return rule.strip()

    def _parse_and_flatten_to_pool(self, raw_rules: List[str], format_type: str, behavior: str, pool: Dict[str, Set[str]]):
        """
        【突破性修复】智能探测文本源格式，无论外界配置是 classical、domain 还是 ipcidr，
        都同时进行全格式解析，避免因为规则格式不匹配引发的“无法转换、丢失规则”情况。
        """
        if format_type in ('json', 'srs') or (len(raw_rules) == 1 and raw_rules[0].strip().startswith('{')):
            # sing-box JSON 家族解包流程
            for content in raw_rules:
                try:
                    data = json.loads(content.lstrip('\ufeff'))
                    rules_list = data.get('rules', []) if isinstance(data, dict) else [data]
                    for r in rules_list:
                        self._extract_sing_box_atom(r, pool)
                except Exception as e:
                    self.logger.debug(f"解析 sing-box 元素失败: {e}")
            return

        # 文本类规则源（Mihomo 文本、YAML 或者是扁平列表）
        for rule in raw_rules:
            cleaned = self._clean_rule(str(rule))
            if not cleaned:
                continue

            # --- 步骤 1: 尝试解析带前缀的经典 Mihomo/Clash 规则 ---
            parts = [p.strip() for p in cleaned.split(',')]
            if len(parts) >= 2:
                req_type = parts[0].upper()
                val = parts[1]

                if req_type == 'DOMAIN':
                    if DOMAIN_PATTERN.match(val): pool['domain'].add(val)
                    continue
                elif req_type == 'DOMAIN-SUFFIX':
                    if DOMAIN_PATTERN.match(val): pool['domain_suffix'].add(val)
                    continue
                elif req_type == 'DOMAIN-KEYWORD':
                    pool['domain_keyword'].add(val)
                    continue
                elif req_type == 'DOMAIN-REGEX':
                    pool['domain_regex'].add(val)
                    continue
                elif req_type in ('IP-CIDR', 'IP-CIDR6'):
                    try:
                        ipaddress.ip_network(val, strict=False)
                        pool['ip_cidr'].add(val)
                    except ValueError:
                        pass
                    continue
                elif req_type in ('DST-PORT', 'PORT'):
                    pool['port'].add(val)
                    continue
                elif req_type == 'NETWORK':
                    pool['network'].add(val.lower())
                    continue
                elif req_type == 'PROCESS-NAME':
                    pool['package_name'].add(val)
                    continue
                elif req_type == 'PROCESS-NAME-REGEX':
                    pool['package_name_regex'].add(val)
                    continue

            # --- 步骤 2: 降级适配无前缀的纯列表（Domain 或 IP-CIDR） ---
            # 如果是带 +. 开头的域名后缀（如 Clash 扁平 Domain 规则）
            if cleaned.startswith('+.'):
                d = cleaned[2:]
                if DOMAIN_PATTERN.match(d):
                    pool['domain_suffix'].add(d)
                continue

            # 尝试作为纯 IP 检测
            try:
                ipaddress.ip_network(cleaned, strict=False)
                pool['ip_cidr'].add(cleaned)
                continue
            except ValueError:
                pass

            # 最终尝试作为纯域名检测
            if DOMAIN_PATTERN.match(cleaned):
                pool['domain'].add(cleaned)
            else:
                # 仍无法识别的保留到 other 桶
                pool['other'].add(cleaned)

    def _extract_sing_box_atom(self, rule_obj: Any, pool: Dict[str, Set[str]]):
        """递归提取 sing-box 规则里的原子字段"""
        if not isinstance(rule_obj, dict):
            return
        
        if rule_obj.get('type') == 'logical':
            sub_rules = rule_obj.get('rules', [])
            for sr in sub_rules:
                self._extract_sing_box_atom(sr, pool)
            return

        # 提取各个标准字段
        for field in SING_BOX_LIST_FIELDS:
            if field in rule_obj:
                vals = rule_obj[field]
                if isinstance(vals, (str, int)): vals = [str(vals)]
                if isinstance(vals, list):
                    for v in vals:
                        v_str = str(v).strip()
                        if v_str:
                            if field == 'network': v_str = v_str.lower()
                            pool[field].add(v_str)

    def merge_rules(self) -> None:
        """全量合并与重构出口"""
        for config in self.config:
            if 'upstream' not in config or not config.get('path'):
                continue
            
            target_path = config['path']
            target_format = config.get('format', 'yaml')
            default_behavior = 'sing-box' if target_format in ('json', 'srs') else 'classical'
            target_behavior = config.get('behavior', default_behavior)
            if target_behavior == 'singbox': target_behavior = 'sing-box'

            pool = self._new_pool()

            # 1. 抓取所有源
            for source_config in config['upstream'].values():
                r_format = source_config.get('format', 'yaml')
                def_b = 'sing-box' if r_format in ('json', 'srs') else 'classical'
                s_behavior = source_config.get('behavior', def_b)
                if s_behavior == 'singbox': s_behavior = 'sing-box'

                if source_config.get('type') == 'http':
                    raw_data = self._fetch_http_rules(source_config.get('url', ''), r_format)
                else:
                    raw_data = self._read_local_rules(source_config.get('path', ''), r_format, s_behavior)
                
                self._parse_and_flatten_to_pool(raw_data, r_format, s_behavior, pool)

            # 2. 重新编译组合
            final_export_list = self._compile_pool_to_target(pool, target_behavior)

            # 3. 按照目标格式写出文件
            self._write_final_file(
                target_path,
                final_export_list,
                target_format,
                target_behavior,
                config.get('version', SING_BOX_RULESET_VERSION)
            )

    def _compile_pool_to_target(self, pool: Dict[str, Set[str]], target_behavior: str) -> List[Any]:
        """将清洗干净的原子池，反向组装为目标格式所期望的规则形态"""
        result = []

        if target_behavior == 'domain':
            for d in sorted(pool['domain']): result.append(d)
            for s in sorted(pool['domain_suffix']): result.append(f"+.{s}")
            return result

        if target_behavior == 'ipcidr':
            return sorted(list(pool['ip_cidr']))

        if target_behavior == 'classical':
            for d in sorted(pool['domain']): result.append(f"DOMAIN,{d}")
            for s in sorted(pool['domain_suffix']): result.append(f"DOMAIN-SUFFIX,{s}")
            for k in sorted(pool['domain_keyword']): result.append(f"DOMAIN-KEYWORD,{k}")
            for r in sorted(pool['domain_regex']): result.append(f"DOMAIN-REGEX,{r}")
            for ip in sorted(pool['ip_cidr']):
                prefix = "IP-CIDR6" if ":" in ip else "IP-CIDR"
                result.append(f"{prefix},{ip}")
            for port in sorted(pool['port'], key=lambda x: int(x.split(':')[0]) if ':' in x and x.split(':')[0].isdigit() else (int(x) if x.isdigit() else 0)):
                result.append(f"DST-PORT,{port}")
            for net in sorted(pool['network']):
                result.append(f"NETWORK,{net.upper()}")
            for pkg in sorted(pool['package_name']):
                result.append(f"PROCESS-NAME,{pkg}")
            for pkg_rgx in sorted(pool['package_name_regex']):
                result.append(f"PROCESS-NAME-REGEX,{pkg_rgx}")
            for o in sorted(pool['other']): 
                result.append(o)
            return result

        if target_behavior == 'sing-box':
            sb_rule = {}
            for field in SING_BOX_LIST_FIELDS:
                if pool[field]:
                    if field == 'port':
                        sb_rule[field] = sorted([int(p) if p.isdigit() else p for p in pool[field]], key=lambda x: x if isinstance(x, int) else int(str(x).split(':')[0]) if ':' in str(x) else 0)
                    else:
                        sb_rule[field] = sorted(list(pool[field]))
            return [sb_rule] if sb_rule else []

        return result

    def _write_final_file(self, path: str, data_list: List[Any], r_format: str, behavior: str, version: int):
        try:
            output_dir = os.path.dirname(path)
            if output_dir: os.makedirs(output_dir, exist_ok=True)

            if r_format == 'mrs':
                tmp = self._make_temp_path('.tmp')
                self._write_plain_text_or_yaml(tmp, data_list, 'text')
                try:
                    if self._convert_to_mrs(tmp, path, behavior):
                        self.logger.info(f"已生成 mrs 二进制规则: {path}, 包含 {len(data_list)} 条规则")
                finally:
                    if os.path.exists(tmp): os.unlink(tmp)
                return

            if r_format == 'srs':
                tmp = self._make_temp_path('.json')
                self._write_sing_box_json(tmp, data_list, version, behavior)
                try:
                    if self._convert_to_srs(tmp, path):
                        self.logger.info(f"已生成 srs 二进制规则: {path}")
                finally:
                    if os.path.exists(tmp): os.unlink(tmp)
                return

            if r_format == 'json':
                self._write_sing_box_json(path, data_list, version, behavior)
                self.logger.info(f"已生成 json 规则: {path}")
                return

            self._write_plain_text_or_yaml(path, data_list, r_format)
            self.logger.info(f"已生成 {r_format} 文本规则: {path}, 包含 {len(data_list)} 条规则")

        except Exception as e:
            self.logger.error(f"写入规则文件 {path} 失败: {e}", exc_info=True)

    def _write_plain_text_or_yaml(self, path: str, data_list: List[str], r_format: str):
        with open(path, 'w', encoding='utf-8') as f:
            if not path.endswith('.tmp'):
                f.write(f"# 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# 规则数量: {len(data_list)}\n")
            if r_format == 'yaml':
                yaml_str = yaml.dump({'payload': data_list}, allow_unicode=True, indent=2, default_flow_style=False, sort_keys=False)
                f.write(yaml_str.replace('\n-', '\n  -'))
            else:
                for line in data_list:
                    f.write(f"{line}\n")

    def _write_sing_box_json(self, path: str, data_list: List[Any], version: int, behavior: str):
        with open(path, 'w', encoding='utf-8') as f:
            if behavior in ('domain', 'ipcidr'):
                json.dump(data_list, f, ensure_ascii=False, indent=2)
            else:
                rule_set = {
                    'version': version,
                    'rules': data_list
                }
                json.dump(rule_set, f, ensure_ascii=False, indent=2)
            f.write('\n')

    def _read_mrs_file(self, input_path: str, behavior: str) -> List[str]:
        if not self.mihomo_path: return []
        output_path = self._make_temp_path('.txt')
        try:
            cmd = [self.mihomo_path, 'convert-ruleset', behavior, 'mrs', input_path, output_path]
            if subprocess.run(cmd, capture_output=True).returncode == 0:
                with open(output_path, 'r', encoding='utf-8') as f:
                    return f.read().splitlines()
        except Exception as e:
            self.logger.debug(f"读取mrs失败: {e}")
        finally:
            if os.path.exists(output_path): os.unlink(output_path)
        return []

    def _convert_to_mrs(self, input_path: str, output_path: str, behavior: str) -> bool:
        if not self.mihomo_path: return False
        cmd = [self.mihomo_path, 'convert-ruleset', behavior, 'text', input_path, output_path]
        return subprocess.run(cmd, capture_output=True).returncode == 0

    def _convert_to_srs(self, input_path: str, output_path: str) -> bool:
        if not self.sing_box_path: return False
        cmd = [self.sing_box_path, 'rule-set', 'compile', '--output', output_path, input_path]
        return subprocess.run(cmd, capture_output=True).returncode == 0


def main():
    merger = RulesMerger('config.yaml')
    merger.merge_rules()


if __name__ == '__main__':
    main()
