    def _compile_final_sing_box_list(self, converted_str_rules: List[str], original_dict_rules: List[Dict]) -> List[Dict]:
        # =====================================================================
        # 1. 提取并合并【由文本格式转换出来的】零散碎片 JSON（进大桶）
        # =====================================================================
        bucket = {key: [] for key in SING_BOX_LIST_FIELDS}
        passthrough_rules = []

        for rule_str in converted_str_rules:
            parsed = self._parse_sing_box_rule(rule_str)
            if not parsed: continue
            if self._can_compact_sing_box_rule(parsed):
                self._add_sing_box_rule_items(bucket, parsed)
            else:
                passthrough_rules.append(parsed)

        # 压缩合并文本碎片的桶，得到基础的单字段规则数组
        compacted_results = self._compact_sing_box_rules(bucket)
        
        # =====================================================================
        # 2. 【核心新增】：对原装的完整的 Dict 规则（如 ablock）进行深度合并与去重
        # =====================================================================
        merged_original_dict = {}
        advanced_dict_rules = []

        for r in original_dict_rules:
            # 如果包含 logical 或者非标准字段，不贸然合并，放入高级规则组
            if r.get('type') == 'logical' or not all(k in SING_BOX_LIST_FIELDS for k in r.keys()):
                advanced_dict_rules.append(r)
                continue
            
            # 将标准的、可合并的字段注入到 merged_original_dict 聚合大字典中
            for key in SING_BOX_LIST_FIELDS:
                if key in r:
                    if key not in merged_original_dict:
                        merged_original_dict[key] = []
                    merged_original_dict[key].extend(self._as_list(r[key]))

        # 对聚合后的标准 Dict 内部的各个列表进行去重和排序
        final_merged_dict = {}
        for key, values in merged_original_dict.items():
            if values:
                # 针对端口/网络/域名等清洗与排序
                if key == 'port':
                    unique_vals = list(set(int(v) if str(v).isdigit() else str(v) for v in values))
                    has_str_range = any(isinstance(v, str) and not v.isdigit() for v in unique_vals)
                    unique_sorted = sorted(unique_vals, key=lambda x: str(x)) if has_str_range else sorted(unique_vals)
                elif key == 'network':
                    unique_sorted = sorted(list(set(str(v).lower() for v in values)))
                else:
                    unique_sorted = sorted(list(set(str(v) for v in values)))
                
                final_merged_dict[key] = unique_sorted

        # 准备装配最终的池子
        # 结构包含：[文本碎片合并结果] + [文本碎片无法合并的高级项] + [高级不可合并Dict]
        all_rules_pool = compacted_results + passthrough_rules + advanced_dict_rules
        
        # 如果聚合后的 ablock 等 Dict 里面确实有内容，作为一个**完整一体的 Dict 块**塞入
        if final_merged_dict:
            all_rules_pool.append(final_merged_dict)

        # =====================================================================
        # 3. 终极精准特征去重（防止整块规则完全重复）
        # =====================================================================
        seen_signatures = set()
        unique_final_rules = []
        for r in all_rules_pool:
            sig = json.dumps(r, ensure_ascii=False, sort_keys=True)
            if sig not in seen_signatures:
                seen_signatures.add(sig)
                unique_final_rules.append(r)

        return unique_final_rules
