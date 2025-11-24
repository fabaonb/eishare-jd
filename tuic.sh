#!/bin/bash
# =========================================
# TUIC v1.4.5 over QUIC 自动部署脚本（免 root）
# =========================================
set -euo pipefail
export LC_ALL=C
IFS=$'\n\t'
# ============================================================
# 配置变量（可根据需要修改）
# ============================================================
TUIC_VERSION="v1.4.5"           # TUIC 版本
MASQ_DOMAIN="www.bing.com"      # SNI 域名
TUIC_BIN="./tuic-server"        # 二进制文件路径
SERVER_TOML="server.toml"       # 配置文件名
CERT_PEM="tuic-cert.pem"        # 证书文件名
KEY_PEM="tuic-key.pem"          # 密钥文件名
LINK_TXT="tuic_link.txt"        # 连接链接文件名
# 资源监控配置
MONITOR_INTERVAL=10             # 监控间隔（秒）
CPU_THRESHOLD=85                # CPU 告警阈值（%）
MEM_THRESHOLD=85                # 内存告警阈值（%）
HEARTBEAT_INTERVAL=1           # 心跳日志间隔（秒）

# ============================================================
# ========== 随机生成函数 ==========
random_port() {
  echo $(( (RANDOM % 40000) + 20000 ))
}
random_string() {
  openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | xxd -p
}
# ========== 参数处理函数 ==========
read_port() {
  if [[ $# -ge 1 && -n "${1:-}" ]]; then
    TUIC_PORT="$1"
    echo "✅ 使用指定端口: $TUIC_PORT"
    return
  fi
  if [[ -n "${SERVER_PORT:-}" ]]; then
    TUIC_PORT="$SERVER_PORT"
    echo "✅ 使用环境变量端口: $TUIC_PORT"
    return
  fi
  TUIC_PORT=$(random_port)
  echo "🎲 随机端口: $TUIC_PORT"
}
read_uuid() {
  if [[ $# -ge 2 && -n "${2:-}" ]]; then
    TUIC_UUID="$2"
    echo "✅ 使用指定 UUID: $TUIC_UUID"
    return
  fi
  
  TUIC_UUID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)"
  echo "🎲 生成随机 UUID: $TUIC_UUID"
}
read_password() {
  if [[ $# -ge 3 && -n "${3:-}" ]]; then
    TUIC_PASSWORD="$3"
    echo "✅ 使用指定密码: $TUIC_PASSWORD"
    return
  fi
  
  TUIC_PASSWORD="$(random_string)"
  echo "🎲 生成随机密码: $TUIC_PASSWORD"
}
# ========== 检查已有配置 ==========
load_existing_config() {
  if [[ -f "$SERVER_TOML" ]]; then
    TUIC_PORT=$(grep '^server' "$SERVER_TOML" | sed 's/.*://; s/"//g' | tr -d '\n\r ' || echo "")
    TUIC_UUID=$(grep '^\[users\]' -A1 "$SERVER_TOML" | tail -n1 | awk '{print $1}' | tr -d '\n\r ' || echo "")
    TUIC_PASSWORD=$(grep '^\[users\]' -A1 "$SERVER_TOML" | tail -n1 | awk -F'"' '{print $2}' | tr -d '\n\r ' || echo "")
    
    if [[ -n "$TUIC_PORT" ]] && [[ -n "$TUIC_UUID" ]] && [[ -n "$TUIC_PASSWORD" ]]; then
      echo "📂 Existing config detected. Loading..."
      return 0
    fi
  fi
  return 1
}
# ========== 生成证书 ==========
generate_cert() {
  if [[ -f "$CERT_PEM" ]] && [[ -f "$KEY_PEM" ]]; then
    echo "🔐 Certificate exists, skipping."
    return
  fi
  echo "🔐 Generating self-signed certificate for ${MASQ_DOMAIN}..."
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$KEY_PEM" -out "$CERT_PEM" -subj "/CN=${MASQ_DOMAIN}" -days 365 -nodes >/dev/null 2>&1
  chmod 600 "$KEY_PEM"
  chmod 644 "$CERT_PEM"
  echo "✅ Certificate generated successfully."
}
# ========== 检测架构 ==========
arch_name() {
  local machine
  machine=$(uname -m | tr '[:upper:]' '[:lower:]')
  if [[ "$machine" == *"arm64"* ]] || [[ "$machine" == *"aarch64"* ]]; then
    echo "aarch64"
  elif [[ "$machine" == *"x86_64"* ]] || [[ "$machine" == *"amd64"* ]]; then
    echo "x86_64"
  else
    echo ""
  fi
}

ARCH=$(arch_name)
if [[ -z "$ARCH" ]]; then
  echo "❌ 无法识别 CPU 架构: $(uname -m)"
  exit 1
fi

# ========== 下载二进制 ==========
download_binary() {
  if [[ -x "$TUIC_BIN" ]]; then
    echo "✅ tuic-server already exists."
    return
  fi
  
  local url="https://github.com/Itsusinn/tuic/releases/download/${TUIC_VERSION}/tuic-server-${ARCH}-linux"
  echo "📥 Downloading tuic-server (${ARCH})..."
  curl -L --retry 3 --connect-timeout 30 -o "$TUIC_BIN" "$url"
  chmod +x "$TUIC_BIN"
  echo "✅ Download completed successfully."
}
# ========== 检测系统资源 ==========
detect_system_resources() {
  local total_mem=$(free -m 2>/dev/null | awk '/^Mem:/{print $2}' || echo "512")
  local cpu_cores=$(nproc 2>/dev/null || echo "1")
  
  echo "📊 系统资源检测:"
  echo "   💾 总内存: ${total_mem}MB"
  echo "   🔧 CPU 核心: ${cpu_cores}"
  
  # 根据内存自动调整配置
  if [[ "$total_mem" -lt 128 ]]; then
    SEND_WINDOW=8388608
    RECV_WINDOW=4194304
    INIT_WINDOW=1572864
    echo "   ⚙️ 检测到超低内存环境（<128MB），使用最小配置"
  elif [[ "$total_mem" -lt 384 ]]; then
    SEND_WINDOW=16777216
    RECV_WINDOW=8388608
    INIT_WINDOW=3145728
    echo "   ⚙️ 检测到低内存环境（<384MB），使用优化配置"
  elif [[ "$total_mem" -lt 768 ]]; then
    SEND_WINDOW=25165824
    RECV_WINDOW=12582912
    INIT_WINDOW=4718592
    echo "   ⚙️ 检测到中等内存环境（512MB），使用平衡配置"
  else
    SEND_WINDOW=33554432
    RECV_WINDOW=16777216
    INIT_WINDOW=6291456
    echo "   ⚙️ 内存充足（≥768MB），使用标准配置"
  fi
}
# ========== 生成配置 ==========
generate_config() {
  # 检测容器环境，设置合适的日志级别
  local log_level="warn"
  if is_container_env; then
    log_level="info"
    echo "🐳 容器环境检测：启用详细日志（info 级别）"
  fi
  
cat > "$SERVER_TOML" <<EOF
log_level = "${log_level}"
server = "0.0.0.0:${TUIC_PORT}"
udp_relay_ipv6 = false
zero_rtt_handshake = true
dual_stack = false
auth_timeout = "8s"
task_negotiation_timeout = "4s"
gc_interval = "8s"
gc_lifetime = "8s"
max_external_packet_size = 8192
[users]
${TUIC_UUID} = "${TUIC_PASSWORD}"
[tls]
certificate = "$CERT_PEM"
private_key = "$KEY_PEM"
alpn = ["h3"]
[restful]
addr = "127.0.0.1:${TUIC_PORT}"
secret = "$(openssl rand -hex 16)"
maximum_clients_per_user = 999999999
[quic]
initial_mtu = $((1200 + RANDOM % 200))
min_mtu = 1200
gso = true
pmtu = true
send_window = ${SEND_WINDOW}
receive_window = ${RECV_WINDOW}
max_idle_time = "25s"
[quic.congestion_control]
controller = "bbr"
initial_window = ${INIT_WINDOW}
EOF
}
# ========== 获取公网IP ==========
get_server_ip() {
  curl -s --connect-timeout 3 https://api64.ipify.org || echo "YOUR_SERVER_IP"
}
# ========== 生成TUIC链接 ==========
generate_link() {
  local ip="$1"
  # 节点输出链接
  cat > "$LINK_TXT" <<EOF
tuic://${TUIC_UUID}:${TUIC_PASSWORD}@${ip}:${TUIC_PORT}?congestion_control=bbr&alpn=h3&allowInsecure=1&sni=${MASQ_DOMAIN}&udp_relay_mode=native&disable_sni=0&reduce_rtt=1&max_udp_relay_packet_size=8192#TUIC-${ip}
EOF
  echo "🔗 TUIC 链接已生成:"
  cat "$LINK_TXT"
}
# ========== 安装自动启动 ==========
install_autostart() {
  local work_dir="$(pwd)"
  
  # 尝试使用 systemd
  if command -v systemctl >/dev/null 2>&1 && [[ -d /etc/systemd/system ]]; then
    echo "📦 检测到 systemd，创建服务..."
    cat > /tmp/tuic.service <<EOF
[Unit]
Description=TUIC Proxy Server
After=network.target
[Service]
Type=simple
WorkingDirectory=${work_dir}
ExecStart=${work_dir}/tuic-server -c ${work_dir}/server.toml
Restart=always
RestartSec=5
User=$(whoami)
[Install]
WantedBy=multi-user.target
EOF
    sudo mv /tmp/tuic.service /etc/systemd/system/ 2>/dev/null && \
    sudo systemctl daemon-reload && \
    sudo systemctl enable tuic.service && \
    echo "✅ Systemd 服务已安装并启用" || \
    echo "⚠️ 需要 root 权限安装 systemd 服务，跳过自动启动配置"
  else
    # 使用 crontab @reboot
    echo "📦 使用 crontab 配置自动启动..."
    local start_script="${work_dir}/tuic_start.sh"
    cat > "$start_script" <<EOF
#!/bin/bash
cd ${work_dir}
while true; do
  ${work_dir}/tuic-server -c ${work_dir}/server.toml >/dev/null 2>&1 || true
  sleep 5
done
EOF
    chmod +x "$start_script"
    (crontab -l 2>/dev/null | grep -v "tuic_start.sh"; echo "@reboot ${start_script} &") | crontab - && \
    echo "✅ Crontab 自动启动已配置" || \
    echo "⚠️ Crontab 配置失败"
  fi
}
# ========== 资源监控函数 (公共) ==========
# 获取网络流量（所有接口总和）
get_net_traffic() {
  # 先用 sed 规范化格式：确保冒号后有空格，然后用 awk 求和
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
  if [[ -f /proc/stat ]]; then
    # 第一次采样
    eval $(awk '/^cpu /{print "total1=" $2+$3+$4+$5+$6+$7+$8 "; idle1=" $5}' /proc/stat)
    sleep 1
    # 第二次采样
    eval $(awk '/^cpu /{print "total2=" $2+$3+$4+$5+$6+$7+$8 "; idle2=" $5}' /proc/stat)
    
    local diff_idle=$((idle2 - idle1))
    local diff_total=$((total2 - total1))
    
    if [[ "$diff_total" -gt 0 ]]; then
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
  elif [[ -f /proc/meminfo ]]; then
    local total=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    local avail=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
    
    if [[ -n "$total" ]] && [[ -n "$avail" ]] && [[ "$total" -gt 0 ]]; then
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
  
  if [[ ! -f "server.toml" ]]; then return; fi
  
  if [[ "${cpu%.*}" -gt "$CPU_THRESHOLD" ]] || [[ "${mem%.*}" -gt "$MEM_THRESHOLD" ]]; then
    if grep -q "send_window = ${ORIGIN_SEND}" server.toml 2>/dev/null; then
       if [[ "${ORIGIN_SEND}" != "${REDUCED_SEND}" ]]; then
          echo "[$(date '+%Y-%m-%d %H:%M:%S')] ⚠️ 资源过高 CPU:${cpu}% MEM:${mem}% - 降低配置"
          sed -i "s/send_window = ${ORIGIN_SEND}/send_window = ${REDUCED_SEND}/; s/receive_window = ${ORIGIN_RECV}/receive_window = ${REDUCED_RECV}/; s/initial_window = ${ORIGIN_INIT}/initial_window = ${REDUCED_INIT}/" server.toml 2>/dev/null
          pkill -HUP -f "tuic-server" 2>/dev/null || systemctl reload tuic 2>/dev/null || true
       fi
    fi
  elif [[ "${cpu%.*}" -lt 50 ]] && [[ "${mem%.*}" -lt 50 ]]; then
    if grep -q "send_window = ${REDUCED_SEND}" server.toml 2>/dev/null; then
       if [[ "${ORIGIN_SEND}" != "${REDUCED_SEND}" ]]; then
          echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✅ 资源充足 CPU:${cpu}% MEM:${mem}% - 恢复配置"
          sed -i "s/send_window = ${REDUCED_SEND}/send_window = ${ORIGIN_SEND}/; s/receive_window = ${REDUCED_RECV}/receive_window = ${ORIGIN_RECV}/; s/initial_window = ${REDUCED_INIT}/initial_window = ${ORIGIN_INIT}/" server.toml 2>/dev/null
          pkill -HUP -f "tuic-server" 2>/dev/null || systemctl reload tuic 2>/dev/null || true
       fi
    fi
  fi
}
# ========== 启动资源监控 ==========
start_resource_monitor() {
  # 计算降低后的配置
  local reduced_send="${SEND_WINDOW}"
  local reduced_recv="${RECV_WINDOW}"
  local reduced_init="${INIT_WINDOW}"
  
  if [[ "${SEND_WINDOW}" == "33554432" ]]; then
    reduced_send="16777216"
    reduced_recv="8388608"
    reduced_init="3145728"
  elif [[ "${SEND_WINDOW}" == "25165824" ]]; then
    reduced_send="16777216"
    reduced_recv="8388608"
    reduced_init="3145728"
  elif [[ "${SEND_WINDOW}" == "16777216" ]]; then
    reduced_send="8388608"
    reduced_recv="4194304"
    reduced_init="1572864"
  fi
  
  cat > tuic_monitor.sh <<MONITOR_EOF
#!/bin/bash
# TUIC 资源监控脚本
MONITOR_INTERVAL=10
CPU_THRESHOLD=85
MEM_THRESHOLD=85
NET_INTERFACE=""

# 注入配置变量
ORIGIN_SEND="${SEND_WINDOW}"
ORIGIN_RECV="${RECV_WINDOW}"
ORIGIN_INIT="${INIT_WINDOW}"

REDUCED_SEND="${reduced_send}"
REDUCED_RECV="${reduced_recv}"
REDUCED_INIT="${reduced_init}"

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
  
  chmod +x tuic_monitor.sh
  
  # 后台启动监控
  nohup ./tuic_monitor.sh >> tuic_monitor.log 2>&1 &
  echo $! > .tuic_monitor.pid
  echo "✅ 资源监控已启动 (PID: $!)"
}
# ========== 检测容器环境 ==========
is_container_env() {
  if [[ -f /.dockerenv ]] || [[ -n "${PTERODACTYL:-}" ]] || [[ -n "${container:-}" ]] || [[ -n "${KUBERNETES_SERVICE_HOST:-}" ]]; then
    return 0
  else
    return 1
  fi
}
# ========== 守护进程 ==========
run_background_loop() {
  echo "🚀 启动 TUIC 服务器..."
  echo "📊 资源监控日志: tail -f tuic_monitor.log"
  echo "✅ 服务器正在运行中..."
  echo ""
  
  # 检测是否在容器环境中
  if is_container_env; then
    echo "🐳 检测到容器环境，显示实时日志..."
    echo "💡 提示：详细连接日志已过滤，仅显示关键状态"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    # 启动后台状态监控
    (
      sleep 10
      while true; do
        # 第一次采样：CPU 和网络
        if [[ -f /proc/stat ]]; then
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
        if [[ -f /proc/stat ]]; then
          eval $(awk '/^cpu /{print "total2=" $2+$3+$4+$5+$6+$7+$8 "; idle2=" $5}' /proc/stat)
          
          # 计算 CPU 使用率
          diff_idle=$((idle2 - idle1))
          diff_total=$((total2 - total1))
          
          if [[ "$diff_total" -gt 0 ]]; then
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
        if [[ -f /proc/meminfo ]]; then
          MEM_TOTAL=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
          MEM_AVAIL=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
          
          if [[ -n "$MEM_TOTAL" ]] && [[ -n "$MEM_AVAIL" ]] && [[ "$MEM_TOTAL" -gt 0 ]]; then
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
        
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] 💓 服务器运行中 | 端口: ${TUIC_PORT} | CPU: ${CPU_USAGE} | 内存: ${MEM_USAGE}(${MEM_PERCENT}) | 网络: ${RX_RATE}↓ ${TX_RATE}↑ KB/s"
        sleep $((${HEARTBEAT_INTERVAL} - 1))
      done
    ) &
    
    while true; do
      "$TUIC_BIN" -c "$SERVER_TOML" >/dev/null 2>&1 || true
      sleep 5
    done
  else
    # 非容器环境，静默运行
    while true; do
      "$TUIC_BIN" -c "$SERVER_TOML" >/dev/null 2>&1 || true
      sleep 5
    done
  fi
}
# ========== 备份关键文件 ==========
backup_critical_files() {
  local backup_dir=".tuic_backup"
  mkdir -p "$backup_dir"
  
  if [[ -f "$SERVER_TOML" ]]; then
    cp "$SERVER_TOML" "$backup_dir/" 2>/dev/null && echo "📦 已备份配置文件"
  fi
  
  if [[ -f "$CERT_PEM" ]] && [[ -f "$KEY_PEM" ]]; then
    cp "$CERT_PEM" "$backup_dir/" 2>/dev/null
    cp "$KEY_PEM" "$backup_dir/" 2>/dev/null
    echo "🔐 已备份证书文件"
  fi
}
# ========== 恢复关键文件 ==========
restore_critical_files() {
  local backup_dir=".tuic_backup"
  
  if [[ ! -d "$backup_dir" ]]; then
    return 1
  fi
  
  local restored=false
  
  if [[ -f "$backup_dir/$SERVER_TOML" ]]; then
    cp "$backup_dir/$SERVER_TOML" "$SERVER_TOML" 2>/dev/null && echo "📂 已恢复配置文件" && restored=true
  fi
  
  if [[ -f "$backup_dir/$CERT_PEM" ]] && [[ -f "$backup_dir/$KEY_PEM" ]]; then
    cp "$backup_dir/$CERT_PEM" "$CERT_PEM" 2>/dev/null
    cp "$backup_dir/$KEY_PEM" "$KEY_PEM" 2>/dev/null
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
  rm -f "$TUIC_BIN" "$SERVER_TOML" "$CERT_PEM" "$KEY_PEM" "$LINK_TXT" \
        "tuic_config.txt" "tuic_monitor.sh" "tuic_monitor.log" ".tuic_monitor.pid" \
        "tuic_start.sh"
  
  # 停止可能正在运行的进程
  pkill -f "tuic-server" 2>/dev/null || true
  pkill -f "tuic_monitor.sh" 2>/dev/null || true
}
# ========== 主流程 ==========
main() {
  echo "=========================================================================="
  echo "TUIC 自动部署脚本"
  echo "用法: bash tuic.sh [端口] [UUID] [密码]"
  echo "示例: bash tuic.sh 8443 550e8400-e29b-41d4-a716-446655440000 mypass123"
  echo "=========================================================================="
  
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
    pkill -f "tuic-server" 2>/dev/null || true
    pkill -f "tuic_monitor.sh" 2>/dev/null || true
  fi
  
  if ! load_existing_config; then
    read_port "$@"
    read_uuid "$@"
    read_password "$@"
    generate_cert
    download_binary
    detect_system_resources
    generate_config
  else
    echo "📂 检测到现有配置，使用已有的端口、UUID 和密码"
    generate_cert
    download_binary
  fi
  # 保存配置信息到文件（用于查看）
  cat > tuic_config.txt <<EOF
# TUIC 配置信息
端口: ${TUIC_PORT}
UUID: ${TUIC_UUID}
密码: ${TUIC_PASSWORD}
SNI: ${MASQ_DOMAIN}
# 重启后会自动读取 server.toml 配置文件
# 配置文件路径: $(pwd)/server.toml
EOF
  ip="$(get_server_ip)"
  generate_link "$ip"
  
  echo ""
  echo "💾 配置已保存到 server.toml 和 tuic_config.txt"
  echo "📌 重启后会自动使用相同的端口、UUID 和密码"
  
  # 启动资源监控
  start_resource_monitor
  
  # 检测是否为交互式终端（增强检测）
  if [[ -t 0 ]]; then
    # 交互式环境，询问是否安装自动启动
    read -p "🔧 是否配置服务器重启自动运行？(y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      install_autostart
    fi
  else
    # 非交互式环境（curl 管道或容器），跳过询问
    echo "ℹ️ 非交互式环境，跳过自动启动配置"
    echo "💡 如需配置自动启动，请手动运行: bash tuic.sh"
  fi
  
  run_background_loop
}
main "$@"
