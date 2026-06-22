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
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
import time

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$')
SING_BOX_RULESET_VERSION = 4


class RulesMerger:
    def __init__(self, config_path: str):
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config(config_path)
        self.mihomo_path = self._get_tool_path('mihomo')
        self.sing_box_path = self._get_tool_path('sing-box')
        self._transformers = { ... }  # 保持原样，略

    def _get_tool_path(self, name: str) -> str:
        """从配置或环境变量获取工具路径"""
        # config.yaml 中可以写 mihomo_path / sing_box_path
        tool_path = self.config[0].get(f'{name}_path') if self.config else None
        return tool_path or os.getenv(f'{name.upper()}_PATH', name)

    def _load_config(self, path: str) -> list:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                cfg = yaml.safe_load(f)
            if not isinstance(cfg, list):
                cfg = [cfg] if isinstance(cfg, dict) else []
            self.logger.info(f"已加载配置，共 {len(cfg)} 个输出任务")
            return cfg
        except Exception as e:
            self.logger.error(f"配置文件加载失败: {e}")
            raise

    def _make_temp_path(self, suffix: str) -> str:
        """创建临时文件"""
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            return tmp.name

    def _fetch_http_rules(self, url: str, rule_format: str, behavior: str = 'classical') -> List[str]:
        """带重试的 HTTP 获取"""
        for attempt in range(3):
            try:
                resp = requests.get(url, timeout=15)
                resp.raise_for_status()
                return self._parse_response(resp, rule_format, behavior, url)
            except Exception as e:
                if attempt == 2:
                    self.logger.error(f"获取规则失败 {url}: {e}")
                    return []
                time.sleep(1 * (attempt + 1))
        return []

    def _parse_response(self, response: requests.Response, rule_format: str, behavior: str, url: str) -> List[str]:
        # ...（保持原有逻辑，略微精简）
        if rule_format == 'json':
            return self._read_sing_box_source(response.text)
        if rule_format == 'srs':
            return self._read_binary_rules(response.content, '.srs', self._read_srs_file)
        if rule_format == 'mrs':
            return self._read_binary_rules(response.content, '.mrs', partial(self._read_mrs_file, behavior=behavior))

        # YAML / text 逻辑...
        content_type = response.headers.get('content-type', '')
        is_yaml = (rule_format == 'yaml') or (
            rule_format not in ('mrs', 'text', 'json', 'srs') and
            ('yaml' in content_type or url.endswith(('.yml', '.yaml')))
        )
        if is_yaml:
            return self._extract_yaml_rules(yaml.safe_load(response.text), url)
        return [line for line in response.text.splitlines() if line.strip()]

    def _read_binary_rules(self, content: bytes, suffix: str, reader_func) -> List[str]:
        tmp_path = self._make_temp_path(suffix)
        try:
            with open(tmp_path, 'wb') as f:
                f.write(content)
            return reader_func(tmp_path)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    # ====================== 并行处理 ======================
    def _process_all_sources(self, upstreams: Dict, target_behavior: str) -> List[str]:
        merged = []
        with ThreadPoolExecutor(max_workers=8) as executor:
            future_to_source = {
                executor.submit(self._process_source, src, target_behavior): name
                for name, src in upstreams.items()
            }
            for future in as_completed(future_to_source):
                try:
                    merged.extend(future.result())
                except Exception as e:
                    self.logger.error(f"源 {future_to_source[future]} 处理失败: {e}")
        return merged

    def merge_rules(self) -> None:
        for cfg in self.config:
            if 'upstream' not in cfg or not cfg.get('path'):
                continue

            target_format = cfg.get('format', 'yaml')
            default_behavior = 'sing-box' if target_format in ('json', 'srs') else 'classical'
            target_behavior = cfg.get('behavior', default_behavior)

            if target_format == 'mrs' and target_behavior not in ('domain', 'ipcidr'):
                self.logger.warning(f"{cfg.get('path')}: mrs 仅支持 domain/ipcidr")
                continue

            self.logger.info(f"开始合并 → {cfg['path']} ({target_format}/{target_behavior})")
            
            merged_rules = self._process_all_sources(cfg['upstream'], target_behavior)
            merged_rules = sorted(set(merged_rules))   # 去重 + 排序

            self._write_rules(
                cfg['path'],
                merged_rules,
                target_format,
                target_behavior,
                cfg.get('version', SING_BOX_RULESET_VERSION)
            )

    # 其他方法（_write_rules, _read_mrs_file, _convert_to_mrs 等）保持核心逻辑，优化临时文件清理和日志

    def _write_rules(self, output_path: str, rules: List[str], rule_format: str = 'yaml',
                     behavior: str = 'classical', version: int = SING_BOX_RULESET_VERSION):
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            if rule_format == 'mrs':
                self._write_via_temp(rules, 'text', lambda tmp: self._convert_to_mrs(tmp, str(output_path), behavior))
            elif rule_format == 'srs':
                self._write_via_temp(rules, 'json', lambda tmp: self._convert_to_srs(tmp, str(output_path)), 
                                   writer=self._write_sing_box_source)
            elif rule_format == 'json':
                self._write_sing_box_source(str(output_path), rules, behavior, version)
            else:
                self._write_text_rules(output_path, rules, rule_format)

            self._log_generated_rule_file(rule_format, str(output_path), len(rules))
        except Exception as e:
            self.logger.error(f"写入 {output_path} 失败: {e}", exc_info=True)

    def _write_via_temp(self, rules: List[str], temp_format: str, converter, writer=None):
        tmp_path = self._make_temp_path(f'.{temp_format}')
        try:
            if writer:
                writer(tmp_path, rules, 'classical' if temp_format == 'text' else None)  # 简化
            else:
                self._write_text_rules(Path(tmp_path), rules, temp_format)
            converter(tmp_path)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    # ... 其余转换、验证方法可保持原有实现，仅做少量清理（如减少重复的 strip()）

def main():
    merger = RulesMerger('config.yaml')
    start = time.time()
    merger.merge_rules()
    self.logger.info(f"全部规则合并完成，耗时 {time.time()-start:.2f} 秒")


if __name__ == '__main__':
    main()
