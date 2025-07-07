#!/bin/bash
set -e

COLLECTORS_DIR="my_collectors"
COLLECTOR_GO="node_exporter/collector/collector.go"
TMP_IMPORT_GO="${COLLECTOR_GO}.import.tmp"
NODE_EXPORTER_MY_COLLECTORS="node_exporter/my_collectors"
GIT_COMMIT_MSG="auto: register new collectors from my_collectors"

# 0. 自动复制 my_collectors 目录下所有 .go 文件到 node_exporter 子模块下
mkdir -p "$NODE_EXPORTER_MY_COLLECTORS"
find "$COLLECTORS_DIR" -name '*.go' -exec cp {} "$NODE_EXPORTER_MY_COLLECTORS/" \;

# 工具函数：下划线转驼峰
function to_camel_case() {
    local input="$1"
    local output=""
    IFS='_' read -ra parts <<< "$input"
    for part in "${parts[@]}"; do
        output="${output}$(tr '[:lower:]' '[:upper:]' <<< ${part:0:1})${part:1}"
    done
    echo "$output"
}

# 1. 生成 import 和注册代码（去重）
IMPORTS_SET=()
REGISTERS_SET=()
IMPORTS=""
REGISTERS=""

for file in ${COLLECTORS_DIR}/*_collector.go; do
    [ -e "$file" ] || continue
    base=$(basename "$file" .go)
    collector_name="${base%_collector}"
    camel_collector_name=$(to_camel_case "$collector_name")
    ctor="New${camel_collector_name}Collector"
    import_line="\t\"github.com/prometheus/node_exporter/my_collectors\""
    register_line="\tregisterCollector(\"${collector_name}\", defaultEnabled, func(logger *slog.Logger) (Collector, error) {\n\t\treturn my_collectors.${ctor}(), nil\n\t})"
    # 去重
    if [[ ! " ${IMPORTS_SET[*]} " =~ "${import_line}" ]]; then
        IMPORTS_SET+=("${import_line}")
        IMPORTS+="${import_line}\n"
    fi
    if [[ ! " ${REGISTERS_SET[*]} " =~ "${register_line}" ]]; then
        REGISTERS_SET+=("${register_line}")
        REGISTERS+="${register_line}\n"
    fi
    done

# 2. 替换 import 块（精确定位起止行号，只替换import块内容，其他内容全部保留）
IMPORT_START=$(awk '/^import \(/ {print NR; exit}' "$COLLECTOR_GO")
IMPORT_END=$(awk 'NR>'"$IMPORT_START"' && /^\)/ {print NR; exit}' "$COLLECTOR_GO")

if [[ -z "$IMPORT_START" || -z "$IMPORT_END" ]]; then
    echo "未找到 import 块，脚本终止。"
    exit 1
fi

{
    awk "NR < $IMPORT_START" "$COLLECTOR_GO"
    echo "import ("
    echo -e "$IMPORTS"
    awk "NR > $IMPORT_START && NR < $IMPORT_END" "$COLLECTOR_GO" | grep -v 'github.com.prometheus.node_exporter.my_collectors' | grep -v 'github.com/prometheus/node_exporter/my_collectors'
    echo ")"
    awk "NR > $IMPORT_END" "$COLLECTOR_GO"
} > "$TMP_IMPORT_GO"

# 3. 替换或追加 init 块（只替换 init 块内容，其他内容全部保留）
if grep -q '^func init() {' "$TMP_IMPORT_GO"; then
    awk -v registers="$REGISTERS" '
        BEGIN {in_init=0}
        /^func init\(\) \{/ {print "func init() {"; print registers; in_init=1; next}
        /^\tregisterCollector\(/ {next}
        /^\}/ && in_init {in_init=0; print "}"; next}
        {if (!in_init) print}
    ' "$TMP_IMPORT_GO" > "$COLLECTOR_GO"
else
    cat "$TMP_IMPORT_GO" > "$COLLECTOR_GO"
    echo -e "\nfunc init() {\n$REGISTERS}" >> "$COLLECTOR_GO"
fi

rm -f "$TMP_IMPORT_GO"