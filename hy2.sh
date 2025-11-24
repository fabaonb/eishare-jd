#!/bin/bash
# =========================================
# Hysteria2 v2.6.5 自动部署脚本
# 适用于超低内存环境（32-64MB）
# =========================================
set -euo pipefail
export LC_ALL=C

# ============================================================
# 配置变量（可根据需要修改）
# ============================================================
HYSTERIA_VERSION="v2.6.5"      # Hysteria2 版本
DEFAULT_PORT=22222              # 默认端口
AUTH_PASSWORD="ieshare2025"     # 默认密码（建议修改）
SNI="www.bing.com"              # SNI 域名
ALPN="h3"                       # ALPN 协议
CERT_FILE="cert.pem"            # 证书文件名
KEY_FILE="key.pem"              # 密钥文件名

# 资源监控配置
MONITOR_INTERVAL=10             # 监控间隔（秒）
CPU_THRESHOLD=85                # CPU 告警阈值（%）
MEM_THRESHOLD=85                # 内存告警阈值（%）
HEARTBEAT_INTERVAL=1           # 心跳日志间隔（秒）
# ============================================================



# ========== 读取端口和密码 ==========
read_port_password() {
  if [[ $# -ge 1 && -n "${1:-}" ]]; then
    SERVER_PORT="$1"
    echo "✅ 使用指定端口: $SERVER_PORT"
  else
    SERVER_PORT="${SERVER_PORT:-$DEFAULT_PORT}"
    echo "🎲 使用默认端口: $SERVER_PORT"
  fi

  if [[ $# -ge 2 && -n "${2:-}" ]]; then
    AUTH_PASSWORD="$2"
    echo "✅ 使用指定密码: $AUTH_PASSWORD"
  else
    echo "🎲 使用默认密码: $AUTH_PASSWORD"
  fi
}

# ========== 检查已有配置 ==========
load_existing_config() {
  if [[ -f "server.yaml" ]]; then
    SERVER_PORT=$(grep '^listen:' server.yaml | sed 's/.*://; s/"//g' | tr -d '\n\r ' || echo "$DEFAULT_PORT")
    AUTH_PASSWORD=$(grep 'password:' server.yaml | awk '{print $2}' | tr -d '"\n\r ' || echo "$AUTH_PASSWORD")
    echo "📂 Existing config detected. Loading..."
    return 0
  fi
  return 1
}

# ========== 检测架构 ==========
arch_name() {
    local machine
    machine=$(uname -m | tr '[:upper:]' '[:lower:]')
    if [[ "$machine" == *"arm64"* ]] || [[ "$machine" == *"aarch64"* ]]; then
        echo "arm64"
    elif [[ "$machine" == *"x86_64"* ]] || [[ "$machine" == *"amd64"* ]]; then
        echo "amd64"
    else
        echo ""
    fi
}

ARCH=$(arch_name)
if [ -z "$ARCH" ]; then
  echo "❌ 无法识别 CPU 架构: $(uname -m)"
  exit 1
fi

BIN_NAME="hysteria-linux-${ARCH}"
BIN_PATH="./${BIN_NAME}"

# ========== 下载二进制 ==========
download_binary() {
    if [ -f "$BIN_PATH" ]; then
        echo "✅ hysteria-server already exists."
        return
    fi
    URL="https://github.com/apernet/hysteria/releases/download/app/${HYSTERIA_VERSION}/${BIN_NAME}"
    echo "📥 Downloading hysteria-server..."
    curl -L --retry 3 --connect-timeout 30 -o "$BIN_PATH" "$URL"
    chmod +x "$BIN_PATH"
}

# ========== 生成证书 ==========
generate_cert() {
    if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
        echo "🔐 Certificate exists, skipping."
        return
    fi
    echo "🔐 Generating self-signed certificate for ${SNI}..."
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -days 3650 -keyout "$KEY_FILE" -out "$CERT_FILE" -subj "/CN=${SNI}" >/dev/null 2>&1
    chmod 600 "$KEY_FILE"
    chmod 644 "$CERT_FILE"
    echo "✅ Certificate generated successfully."
}

# ========== 检测系统资源 ==========
detect_system_resources() {
    local total_mem=$(free -m 2>/dev/null | awk '/^Mem:/{print $2}' || echo "512")
    local cpu_cores=$(nproc 2>/dev/null || echo "1")
    
    echo "📊 系统资源检测:"
    echo "   💾 总内存: ${total_mem}MB"
    echo "   🔧 CPU 核心: ${cpu_cores}"
    
    # 根据内存自动调整配置
    if [ "$total_mem" -lt 128 ]; then
        BANDWIDTH_UP="50mbps"
        BANDWIDTH_DOWN="50mbps"
        MAX_STREAMS=2
        STREAM_WINDOW=16384
        echo "   ⚙️ 检测到超低内存环境（<128MB），使用最小配置"
    elif [ "$total_mem" -lt 384 ]; then
        BANDWIDTH_UP="100mbps"
        BANDWIDTH_DOWN="100mbps"
        MAX_STREAMS=3
        STREAM_WINDOW=32768
        echo "   ⚙️ 检测到低内存环境（<384MB），使用优化配置"
    elif [ "$total_mem" -lt 768 ]; then
        BANDWIDTH_UP="150mbps"
        BANDWIDTH_DOWN="150mbps"
        MAX_STREAMS=4
        STREAM_WINDOW=49152
        echo "   ⚙️ 检测到中等内存环境（512MB），使用平衡配置"
    else
        BANDWIDTH_UP="200mbps"
        BANDWIDTH_DOWN="200mbps"
        MAX_STREAMS=6
        STREAM_WINDOW=65536
        echo "   ⚙️ 内存充足（≥768MB），使用标准配置"
    fi
}

# ========== 生成配置 ==========
generate_config() {
cat > server.yaml <<EOF
listen: ":${SERVER_PORT}"
tls:
  cert: "$(pwd)/${CERT_FILE}"
  key: "$(pwd)/${KEY_FILE}"
  alpn:
    - "${ALPN}"
auth:
  type: "password"
  password: "${AUTH_PASSWORD}"
bandwidth:
  up: "${BANDWIDTH_UP}"
  down: "${BANDWIDTH_DOWN}"
quic:
  max_idle_timeout: "10s"
  max_concurrent_streams: ${MAX_STREAMS}
  initial_stream_receive_window: ${STREAM_WINDOW}
  max_stream_receive_window: $((STREAM_WINDOW * 2))
  initial_conn_receive_window: $((STREAM_WINDOW * 2))
  max_conn_receive_window: $((STREAM_WINDOW * 4))
EOF
    echo "✅ Configuration written to server.yaml (Port=${SERVER_PORT}, Bandwidth=${BANDWIDTH_UP}/${BANDWIDTH_DOWN})."
}

# ========== 获取服务器 IP ==========
get_server_ip() {
    IP=$(curl -s --max-time 10 https://api.ipify.org || echo "YOUR_SERVER_IP")
    echo "$IP"
}

# ========== 生成Hysteria2链接 ==========
generate_link() {
  local ip="$1"
  # 节点输出链接
  echo "🔗 Hysteria2 链接已生成:"
  echo "hysteria2://${AUTH_PASSWORD}@${ip}:${SERVER_PORT}?sni=${SNI}&alpn=${ALPN}&insecure=1#Hy2-${ip}"
}

# ========== 安装自动启动 ==========
install_autostart() {
    local script_path="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
    local work_dir="$(pwd)"
    
    # 尝试使用 systemd
    if command -v systemctl >/dev/null 2>&1 && [[ -d /etc/systemd/system ]]; then
        echo "📦 检测到 systemd，创建服务..."
        cat > /tmp/hysteria2.service <<EOF
[Unit]
Description=Hysteria2 Proxy Server
After=network.target

[Service]
Type=simple
WorkingDirectory=${work_dir}
ExecStart=${BIN_PATH} server -c ${work_dir}/server.yaml
Restart=always
RestartSec=5
User=$(whoami)

[Install]
WantedBy=multi-user.target
EOF
        sudo mv /tmp/hysteria2.service /etc/systemd/system/ 2>/dev/null && \
        sudo systemctl daemon-reload && \
        sudo systemctl enable hysteria2.service && \
        echo "✅ Systemd 服务已安装并启用" || \
        echo "⚠️ 需要 root 权限安装 systemd 服务，跳过自动启动配置"
    else
        # 使用 crontab @reboot
        echo "📦 使用 crontab 配置自动启动..."
        (crontab -l 2>/dev/null | grep -v "hysteria2"; echo "@reboot cd ${work_dir} && ${BIN_PATH} server -c ${work_dir}/server.yaml >/dev/null 2>&1 &") | crontab - && \
        echo "✅ Crontab 自动启动已配置" || \
        echo "⚠️ Crontab 配置失败"
    fi
}

# ========== 资源监控函数 (公共) ==========

# 获取网络流量（所有接口总和）
get_net_traffic() {
  sed 's/:/ /g' /proc/net/dev | awk 'NR>2 {if ($1 !~ /lo/) {rx+=$2; tx+=$10}} END {print rx+0 "\t" tx+0}' 2>/dev/null || printf "0\t0"
}

# 获取网络使用率（KB/s）
get_net_usage() {
  read rx1 tx1 <<< $(get_net_traffic)
  sleep 1
  read rx2 tx2 <<< $(get_net_traffic)
  
  local rx_rate=$(( (rx2 - rx1) / 1024 ))
  local tx_rate=$(( (tx2 - tx1) / 1024 ))
  
  echo "${rx_rate}↓ ${tx_rate}↑"
}

# 获取 CPU 使用率
get_cpu_usage() {
  # 优先使用 /proc/stat 因为格式更统一
  if [ -f /proc/stat ]; then
    # 第一次采样
    eval $(awk '/^cpu /{print "total1=" $2+$3+$4+$5+$6+$7+$8 "; idle1=" $5}' /proc/stat)
    sleep 1
    # 第二次采样
    eval $(awk '/^cpu /{print "total2=" $2+$3+$4+$5+$6+$7+$8 "; idle2=" $5}' /proc/stat)
    
    local diff_idle=$((idle2 - idle1))
    local diff_total=$((total2 - total1))
    
    if [ "$diff_total" -gt 0 ]; then
      # 使用 awk 进行浮点运算
      echo "$diff_idle $diff_total" | awk '{printf "%.1f", 100 * (1 - $1/$2)}'
    else
      echo "0.0"
    fi
  elif command -v top >/dev/null 2>&1; then
    # 回退到 top
    top -bn1 2>/dev/null | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}' || echo "0.0"
  else
    echo "0.0"
  fi
}

# 获取内存使用率
get_mem_usage() {
  if command -v free >/dev/null 2>&1; then
    free 2>/dev/null | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}' || echo "0"
  elif [ -f /proc/meminfo ]; then
    local total=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    local avail=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
    
    if [ -n "$total" ] && [ -n "$avail" ] && [ "$total" -gt 0 ]; then
      local used=$((total - avail))
      echo "$used $total" | awk '{printf "%.0f", 100 * $1 / $2}'
    else
      echo "0"
    fi
  else
    echo "0"
  fi
}

# 动态调整配置
adjust_config() {
  local cpu=$1
  local mem=$2
  
  if [ ! -f "server.yaml" ]; then return; fi
  
  if [ "${cpu%.*}" -gt "$CPU_THRESHOLD" ] || [ "${mem%.*}" -gt "$MEM_THRESHOLD" ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ⚠️ 资源过高 CPU:${cpu}% MEM:${mem}% - 降低配置"
    sed -i 's/up: "200mbps"/up: "100mbps"/; s/down: "200mbps"/down: "100mbps"/; s/max_concurrent_streams: 4/max_concurrent_streams: 2/' server.yaml 2>/dev/null
    pkill -HUP -f "hysteria-linux" 2>/dev/null || systemctl reload hysteria2 2>/dev/null || true
  elif [ "${cpu%.*}" -lt 50 ] && [ "${mem%.*}" -lt 50 ]; then
    if grep -q 'up: "100mbps"' server.yaml 2>/dev/null; then
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✅ 资源充足 CPU:${cpu}% MEM:${mem}% - 恢复配置"
      sed -i 's/up: "100mbps"/up: "200mbps"/; s/down: "100mbps"/down: "200mbps"/; s/max_concurrent_streams: 2/max_concurrent_streams: 4/' server.yaml 2>/dev/null
      pkill -HUP -f "hysteria-linux" 2>/dev/null || systemctl reload hysteria2 2>/dev/null || true
    fi
  fi
}

# ========== 检测容器环境 ==========
is_container_env() {
  if [[ -f /.dockerenv ]] || [[ -n "${PTERODACTYL:-}" ]] || [[ -n "${container:-}" ]] || [[ -n "${KUBERNETES_SERVICE_HOST:-}" ]]; then
    return 0
  else
    return 1
  fi
}

# ========== 启动资源监控 ==========
start_resource_monitor() {
    cat > hy2_monitor.sh <<MONITOR_EOF
#!/bin/bash
# Hysteria2 资源监控脚本
MONITOR_INTERVAL=10
CPU_THRESHOLD=85
MEM_THRESHOLD=85
NET_INTERFACE=""

$(declare -f get_net_traffic)
$(declare -f get_net_usage)
$(declare -f get_cpu_usage)
$(declare -f get_mem_usage)
$(declare -f adjust_config)

# 主监控循环
while true; do
  cpu=\$(get_cpu_usage)
  mem=\$(get_mem_usage)
  net=\$(get_net_usage)
  
  # 记录详细资源信息
  echo "[\$(date '+%Y-%m-%d %H:%M:%S')] 📊 CPU: \${cpu}% | 内存: \${mem}% | 网络: \${net} KB/s"
  
  adjust_config "\$cpu" "\$mem"
  sleep "\$MONITOR_INTERVAL"
done
MONITOR_EOF
    
    chmod +x hy2_monitor.sh
    
    # 后台启动监控
    nohup ./hy2_monitor.sh >> hy2_monitor.log 2>&1 &
    echo $! > .hy2_monitor.pid
    echo "✅ 资源监控已启动 (PID: $!)"
}

# ========== 备份关键文件 ==========
backup_critical_files() {
  local backup_dir=".hy2_backup"
  mkdir -p "$backup_dir"
  
  if [[ -f "server.yaml" ]]; then
    cp "server.yaml" "$backup_dir/" 2>/dev/null && echo "📦 已备份配置文件"
  fi
  
  if [[ -f "$CERT_FILE" ]] && [[ -f "$KEY_FILE" ]]; then
    cp "$CERT_FILE" "$backup_dir/" 2>/dev/null
    cp "$KEY_FILE" "$backup_dir/" 2>/dev/null
    echo "🔐 已备份证书文件"
  fi
}

# ========== 恢复关键文件 ==========
restore_critical_files() {
  local backup_dir=".hy2_backup"
  
  if [[ ! -d "$backup_dir" ]]; then
    return 1
  fi
  
  local restored=false
  
  if [[ -f "$backup_dir/server.yaml" ]]; then
    cp "$backup_dir/server.yaml" "server.yaml" 2>/dev/null && echo "📂 已恢复配置文件" && restored=true
  fi
  
  if [[ -f "$backup_dir/$CERT_FILE" ]] && [[ -f "$backup_dir/$KEY_FILE" ]]; then
    cp "$backup_dir/$CERT_FILE" "$CERT_FILE" 2>/dev/null
    cp "$backup_dir/$KEY_FILE" "$KEY_FILE" 2>/dev/null
    echo "🔐 已恢复证书文件（节点保持有效）" && restored=true
  fi
  
  if [[ "$restored" == "true" ]]; then
    return 0
  else
    return 1
  fi
}

# ========== 清理旧文件 ==========
cleanup_files() {
  echo "🧹 清理旧文件..."
  rm -f "$BIN_PATH" "server.yaml" "$CERT_FILE" "$KEY_FILE" \
        "hy2_config.txt" "hy2_monitor.sh" "hy2_monitor.log" ".hy2_monitor.pid"
        
  # 停止可能正在运行的进程
  pkill -f "hysteria-linux" 2>/dev/null || true
  pkill -f "hy2_monitor.sh" 2>/dev/null || true
}

# ========== 主流程 ==========
main() {
    echo "=========================================================================="
    echo "Hysteria2 自动部署脚本"
    echo "用法: bash hy2.sh [端口] [密码]"
    echo "示例: bash hy2.sh 443 mypassword123"
    echo "=========================================================================="
    
    # 读取参数
    read_port_password "$@"
    
    # 检查部署模式
    if [[ "${FORCE_REDEPLOY:-}" == "true" ]]; then
        echo "🔄 强制重新部署模式"
        cleanup_files
    elif [[ "${CLEAN_REDEPLOY:-}" == "true" ]]; then
        echo "🔄 清理重新部署模式（保留节点有效性）"
        backup_critical_files
        cleanup_files
        if restore_critical_files; then
            echo "✅ 已恢复关键配置，节点保持有效"
        fi
    else
        # 默认模式：停止旧进程但保留配置文件
        pkill -f "hysteria-linux" 2>/dev/null || true
        pkill -f "hy2_monitor.sh" 2>/dev/null || true
    fi
    
    if ! load_existing_config; then
        download_binary
        generate_cert
        detect_system_resources
        generate_config
    else
        echo "📂 检测到现有配置，使用已有的端口和密码"
        download_binary
        generate_cert
    fi
    
    # 保存配置信息到文件（用于查看）
    cat > hy2_config.txt <<EOF
# Hysteria2 配置信息
端口: ${SERVER_PORT}
密码: ${AUTH_PASSWORD}
SNI: ${SNI}
ALPN: ${ALPN}

# 重启后会自动读取 server.yaml 配置文件
# 配置文件路径: $(pwd)/server.yaml
EOF

    ip="$(get_server_ip)"
    generate_link "$ip"
    
    echo ""
    echo "💾 配置已保存到 server.yaml 和 hy2_config.txt"
    echo "📌 重启后会自动使用相同的端口和密码"
    
    # 启动资源监控
    start_resource_monitor
    
    # 检测是否为交互式终端（增强检测）
    if [[ -t 0 ]] && [[ -t 1 ]] && [[ -n "${TERM:-}" ]] && [[ -n "${PS1:-}" ]]; then
        # 交互式环境，询问是否安装自动启动
        read -p "🔧 是否配置服务器重启自动运行？(y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_autostart
        fi
    else
        # 非交互式环境（curl 管道或容器），跳过询问
        echo "ℹ️ 非交互式环境，跳过自动启动配置"
        echo "💡 如需配置自动启动，请手动运行: bash hy2.sh"
    fi
    
    run_background_loop
}

# ========== 守护进程 ==========
run_background_loop() {
    echo "🚀 启动 Hysteria2 服务器..."
    echo "📊 资源监控日志: tail -f hy2_monitor.log"
    echo "✅ 服务器正在运行中..."
    echo ""
    
    # 检测是否在容器环境中
    if is_container_env; then
        echo "🐳 检测到容器环境，启用详细日志..."
        echo "💡 提示：详细连接日志已过滤，仅显示关键状态"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        
        # 启动后台状态监控
        (
            sleep 10
            while true; do
                # 第一次采样：CPU 和网络
                if [ -f /proc/stat ]; then
                  eval $(awk '/^cpu /{print "total1=" $2+$3+$4+$5+$6+$7+$8 "; idle1=" $5}' /proc/stat)
                else
                  total1=0
                  idle1=0
                fi
                
                # 获取网络流量（所有接口总和）
                read RX1 TX1 <<< $(get_net_traffic)
                
                # 等待 1 秒
                sleep 1
                
                # 第二次采样：CPU 和网络
                if [ -f /proc/stat ]; then
                  eval $(awk '/^cpu /{print "total2=" $2+$3+$4+$5+$6+$7+$8 "; idle2=" $5}' /proc/stat)
                  
                  # 计算 CPU 使用率
                  diff_idle=$((idle2 - idle1))
                  diff_total=$((total2 - total1))
                  
                  if [ "$diff_total" -gt 0 ]; then
                    CPU_USAGE=$(echo "$diff_idle $diff_total" | awk '{printf "%.1f%%", 100 * (1 - $1/$2)}')
                  else
                    CPU_USAGE="0.0%"
                  fi
                else
                  CPU_USAGE="N/A"
                fi
                
                read RX2 TX2 <<< $(get_net_traffic)
                
                # 计算网络速率
                RX_RATE=$(( (RX2 - RX1) / 1024 ))
                TX_RATE=$(( (TX2 - TX1) / 1024 ))
                
                # 获取内存使用情况（从 /proc/meminfo）
                if [ -f /proc/meminfo ]; then
                  MEM_TOTAL=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
                  MEM_AVAIL=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
                  
                  if [ -n "$MEM_TOTAL" ] && [ -n "$MEM_AVAIL" ] && [ "$MEM_TOTAL" -gt 0 ]; then
                    MEM_USED=$((MEM_TOTAL - MEM_AVAIL))
                    MEM_USAGE=$(echo "$MEM_USED" | awk '{printf "%.0fMB", $1 / 1024}')
                    MEM_PERCENT=$(echo "$MEM_USED $MEM_TOTAL" | awk '{printf "%.0f%%", 100 * $1 / $2}')
                  else
                    MEM_USAGE="N/A"
                    MEM_PERCENT=""
                  fi
                else
                  MEM_USAGE="N/A"
                  MEM_PERCENT=""
                fi
                
                echo "[$(date '+%Y-%m-%d %H:%M:%S')] 💓 服务器运行中 | 端口: ${SERVER_PORT} | CPU: ${CPU_USAGE} | 内存: ${MEM_USAGE}(${MEM_PERCENT}) | 网络: ${RX_RATE}↓ ${TX_RATE}↑ KB/s"
                sleep $((${HEARTBEAT_INTERVAL} - 1))
            done
        ) &
        
        export HYSTERIA_LOG_LEVEL=info
        
        # 启动服务器并过滤所有日志
        while true; do
          "$BIN_PATH" server -c server.yaml >/dev/null 2>&1 || true
          sleep 5
        done
    else
        # 非容器环境，静默运行
        while true; do
          "$BIN_PATH" server -c server.yaml >/dev/null 2>&1 || true
          sleep 5
        done
    fi
}

main "$@"
