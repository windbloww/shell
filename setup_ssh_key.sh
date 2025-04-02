#!/bin/bash

# 开启严格模式，确保脚本在错误时退出
# -e: 命令失败时退出
# -u: 引用未定义变量时退出
# -o pipefail: pipeline 中任意命令失败则整个 pipeline 失败
set -euo pipefail

# --- 配置 ---
SSHD_CONFIG_FILE="/etc/ssh/sshd_config"
FAIL2BAN_JAIL_LOCAL="/etc/fail2ban/jail.local"
BACKUP_SUFFIX=".bak-$(date +%Y%m%d_%H%M%S)"

# 默认值（可通过交互修改）
DEFAULT_PORT_MIN=10000
DEFAULT_PORT_MAX=65000
DEFAULT_FAIL2BAN_BANTIME=3600
DEFAULT_FAIL2BAN_FINDTIME=300
DEFAULT_FAIL2BAN_MAXRETRY=3

# 用户选择
CHANGE_PORT="no"
CUSTOM_PORT=""
INSTALL_FAIL2BAN="no"
DISABLE_ROOT_LOGIN="no"
DISABLE_PASSWORD_AUTH="yes"

# --- 函数定义 ---

# 输出错误信息并退出
error_exit() {
  echo "错误: $1" >&2
  exit 1
}

# 输出警告信息
log_warning() {
  echo "警告: $1" >&2
}

# 输出信息
log_info() {
  echo "信息: $1"
}

# 备份文件
backup_file() {
  local file_path="$1"
  if [[ -f "$file_path" ]]; then
    log_info "正在备份 $file_path 到 ${file_path}${BACKUP_SUFFIX}"
    cp "$file_path" "${file_path}${BACKUP_SUFFIX}" || error_exit "备份文件 $file_path 失败。"
  fi
}

# 获取用户输入，带默认值
get_input_with_default() {
  local prompt="$1"
  local default="$2"
  local answer
  
  read -p "$prompt [$default]: " answer
  echo "${answer:-$default}"
}

# 获取是/否输入
get_yes_no_input() {
  local prompt="$1"
  local default="$2"
  local answer
  
  while true; do
    read -p "$prompt (y/n) [$default]: " answer
    answer="${answer:-$default}"
    case "$answer" in
      [Yy]|[Yy][Ee][Ss]) return 0 ;;
      [Nn]|[Nn][Oo]) return 1 ;;
      *) echo "请输入 'y' 或 'n'" ;;
    esac
  done
}

# 检查系统包管理器并安装软件包
install_package() {
  local package_name="$1"
  
  log_info "正在检查/安装 $package_name..."
  
  if command -v apt-get &>/dev/null; then
    # Debian/Ubuntu
    apt-get update && apt-get install -y "$package_name" || error_exit "无法安装 $package_name"
  elif command -v yum &>/dev/null; then
    # CentOS/RHEL
    yum install -y "$package_name" || error_exit "无法安装 $package_name"
  elif command -v dnf &>/dev/null; then
    # Fedora/新版 RHEL
    dnf install -y "$package_name" || error_exit "无法安装 $package_name"
  elif command -v zypper &>/dev/null; then
    # openSUSE
    zypper install -y "$package_name" || error_exit "无法安装 $package_name"
  elif command -v pacman &>/dev/null; then
    # Arch Linux
    pacman -Sy --noconfirm "$package_name" || error_exit "无法安装 $package_name"
  else
    error_exit "未能识别的包管理器，请手动安装 $package_name"
  fi
  
  log_info "$package_name 已安装"
}

# 生成随机高端口号
generate_random_port() {
  local min_port="$1"
  local max_port="$2"
  local port
  port=$(( (RANDOM % (max_port - min_port + 1)) + min_port ))
  echo "$port"
}

# 检查端口是否已被使用
is_port_in_use() {
  local port="$1"
  if command -v ss &>/dev/null; then
    ss -tuln | grep -q ":$port "
    return $?
  elif command -v netstat &>/dev/null; then
    netstat -tuln | grep -q ":$port "
    return $?
  else
    # 如果既没有 ss 也没有 netstat，假设端口可用
    return 1
  fi
}

# 获取未被使用的随机端口
get_unused_random_port() {
  local min_port="$1"
  local max_port="$2"
  local port
  local max_attempts=10
  local attempts=0
  
  while [[ $attempts -lt $max_attempts ]]; do
    port=$(generate_random_port "$min_port" "$max_port")
    if ! is_port_in_use "$port"; then
      echo "$port"
      return 0
    fi
    ((attempts++))
  done
  
  error_exit "无法获取未使用的随机端口，请手动指定端口。"
}

# 检查并设置 sshd_config 参数
# $1: 参数名 (e.g., PasswordAuthentication)
# $2: 期望的值 (e.g., no)
# $3: 配置文件路径
ensure_sshd_config() {
  local parameter="$1"
  local expected_value="$2"
  local config_file="$3"
  local pattern="^[#[:space:]]*${parameter}[[:space:]].*"
  local desired_line="${parameter} ${expected_value}"

  if grep -qE "$pattern" "$config_file"; then
    # 参数行存在 (可能被注释)
    # 使用 sed 先确保取消注释，然后设置正确的值
    sed -i -E "s|${pattern}|${desired_line}|" "$config_file"
    log_info "已更新 $config_file 中的 $parameter 设置为 $expected_value。"
  else
    # 参数行不存在，追加到文件末尾
    log_info "在 $config_file 中未找到 $parameter，正在添加 $desired_line。"
    echo "$desired_line" >> "$config_file"
  fi
}

# 简单检查公钥的基本格式
# 返回0表示基本格式正确，非0表示格式错误
check_ssh_public_key_basic() {
  local key="$1"
  
  # 检查是否以标准SSH密钥类型开头
  if ! echo "$key" | grep -q -E '^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519|sk-ecdsa-sha2-nistp256)'; then
    return 1
  fi
  
  # 检查公钥是否包含至少两部分（类型和数据）
  if [[ $(echo "$key" | wc -w) -lt 2 ]]; then
    return 1
  fi
  
  return 0
}

# 显示公钥信息（如果系统支持）
show_key_info() {
  local key="$1"
  
  if command -v ssh-keygen &>/dev/null; then
    echo "公钥信息:"
    if ! ssh-keygen -lf - <<< "$key" 2>/dev/null; then
      log_warning "无法使用ssh-keygen显示公钥信息，但这不影响安装过程。"
    fi
  fi
}

# 设置和配置fail2ban
setup_fail2ban() {
  local ssh_port="$1"
  local bantime="$2"
  local findtime="$3"
  local maxretry="$4"
  
  # 检查fail2ban是否已安装
  if ! command -v fail2ban-client &>/dev/null; then
    log_info "Fail2Ban未安装，正在安装..."
    install_package "fail2ban"
  fi
  
  # 确保fail2ban服务已启动
  if command -v systemctl &>/dev/null; then
    systemctl enable fail2ban
    systemctl start fail2ban
  elif command -v service &>/dev/null; then
    service fail2ban start
  fi
  
  # 创建或修改配置文件
  if [[ ! -f "$FAIL2BAN_JAIL_LOCAL" ]]; then
    log_info "创建Fail2Ban配置文件 $FAIL2BAN_JAIL_LOCAL..."
    cat > "$FAIL2BAN_JAIL_LOCAL" << EOF
[DEFAULT]
bantime = $bantime
findtime = $findtime
maxretry = $maxretry

[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = %(sshd_log)s
maxretry = $maxretry
bantime = $bantime
EOF
    log_info "已创建Fail2Ban配置文件。"
  else
    log_info "更新Fail2Ban配置文件 $FAIL2BAN_JAIL_LOCAL..."
    backup_file "$FAIL2BAN_JAIL_LOCAL"
    
    # 检查[DEFAULT]部分是否存在
    if ! grep -q '^\[DEFAULT\]' "$FAIL2BAN_JAIL_LOCAL"; then
      cat > "${FAIL2BAN_JAIL_LOCAL}.tmp" << EOF
[DEFAULT]
bantime = $bantime
findtime = $findtime
maxretry = $maxretry

$(cat "$FAIL2BAN_JAIL_LOCAL")
EOF
      mv "${FAIL2BAN_JAIL_LOCAL}.tmp" "$FAIL2BAN_JAIL_LOCAL"
    fi
    
    # 检查[sshd]部分是否存在
    if ! grep -q '^\[sshd\]' "$FAIL2BAN_JAIL_LOCAL"; then
      cat >> "$FAIL2BAN_JAIL_LOCAL" << EOF

[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = %(sshd_log)s
maxretry = $maxretry
bantime = $bantime
EOF
    else
      # 更新现有的[sshd]部分
      awk -v port="$ssh_port" -v bantime="$bantime" -v maxretry="$maxretry" '
      BEGIN { in_sshd_section = 0; port_found = 0; enabled_found = 0; maxretry_found = 0; bantime_found = 0; }
      /^[[:space:]]*\[sshd\]/ { in_sshd_section = 1; print; next; }
      /^[[:space:]]*\[.*\]/ { 
          if(in_sshd_section) {
              if(!enabled_found) { print "enabled = true"; enabled_found = 1; }
              if(!port_found) { print "port = " port; port_found = 1; }
              if(!maxretry_found) { print "maxretry = " maxretry; maxretry_found = 1; }
              if(!bantime_found) { print "bantime = " bantime; bantime_found = 1; }
          }
          in_sshd_section = 0;
          print;
          next;
      }
      in_sshd_section {
          if (/^[#[:space:]]*enabled[[:space:]]*=/) {
              print "enabled = true";
              enabled_found = 1;
          } else if (/^[#[:space:]]*port[[:space:]]*=/) {
              print "port = " port;
              port_found = 1;
          } else if (/^[#[:space:]]*maxretry[[:space:]]*=/) {
              print "maxretry = " maxretry;
              maxretry_found = 1;
          } else if (/^[#[:space:]]*bantime[[:space:]]*=/) {
              print "bantime = " bantime;
              bantime_found = 1;
          } else {
              print;
          }
          next;
      }
      { print }
      END { 
          if(in_sshd_section) {
              if(!enabled_found) { print "enabled = true"; }
              if(!port_found) { print "port = " port; }
              if(!maxretry_found) { print "maxretry = " maxretry; }
              if(!bantime_found) { print "bantime = " bantime; }
          }
      }
      ' "$FAIL2BAN_JAIL_LOCAL" > "${FAIL2BAN_JAIL_LOCAL}.tmp" && mv "${FAIL2BAN_JAIL_LOCAL}.tmp" "$FAIL2BAN_JAIL_LOCAL"
    fi
  fi
  
  # 重启Fail2Ban服务
  log_info "正在重启Fail2Ban服务..."
  if command -v systemctl &>/dev/null; then
    systemctl restart fail2ban || log_warning "使用systemctl重启fail2ban服务失败。"
  else
    service fail2ban restart || log_warning "使用service重启fail2ban服务失败。"
  fi
  
  log_info "Fail2Ban配置完成。"
}

# --- 主逻辑 ---

echo "==================================================="
echo "        SSH 密钥和安全配置脚本（交互版）          "
echo "==================================================="
log_info "开始 SSH 密钥配置脚本..."

# 1. 检测是否以 root 用户运行
if [ "$(id -u)" -ne 0 ]; then
  error_exit "请以 root 用户运行此脚本 (例如使用 sudo)。"
fi

# 2. 获取目标用户和家目录
TARGET_USER="${SUDO_USER:-$(logname 2>/dev/null || echo $USER)}" # 优先用 SUDO_USER, 备选 logname 或 USER
if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" ]]; then
    read -p "请输入要为其配置 SSH 密钥的用户名: " TARGET_USER
    if [[ -z "$TARGET_USER" ]]; then
        error_exit "用户名不能为空。"
    fi
    # 检查用户是否存在
    if ! id "$TARGET_USER" &>/dev/null; then
        error_exit "用户 '$TARGET_USER' 不存在。"
    fi
fi
USER_HOME=$(eval echo "~$TARGET_USER")
if [[ ! -d "$USER_HOME" ]]; then
    error_exit "用户 '$TARGET_USER' 的家目录 '$USER_HOME' 不存在或无法访问。"
fi
log_info "将为用户 '$TARGET_USER' (家目录: $USER_HOME) 配置 SSH 密钥。"

# 3. 提示用户粘贴公钥并进行简单验证
echo "请粘贴用户 '$TARGET_USER' 的 SSH 公钥 (以 ssh-rsa, ssh-ed25519, ecdsa-sha2-nistp... 开头)"
read -p "> " PUBLIC_KEY

# 验证公钥是否为空
if [[ -z "$PUBLIC_KEY" ]]; then
  error_exit "公钥不能为空。"
fi

# 简单的格式检查
if ! check_ssh_public_key_basic "$PUBLIC_KEY"; then
  log_warning "公钥格式可能不正确。请确保它以 ssh-rsa, ssh-ed25519 等开头，并包含数据部分。"
  if ! get_yes_no_input "是否继续使用此公钥?" "n"; then
    error_exit "已取消操作。"
  fi
else
  # 尝试显示公钥信息
  show_key_info "$PUBLIC_KEY"
fi

# 4. 询问用户是否需要更改SSH端口
echo ""
echo "=== SSH端口配置 ==="
if get_yes_no_input "是否需要更改默认SSH端口 (22)?" "y"; then
  CHANGE_PORT="yes"
  if get_yes_no_input "是否使用随机高端口 (${DEFAULT_PORT_MIN}-${DEFAULT_PORT_MAX})?" "y"; then
    # 使用自定义范围的随机端口
    PORT_MIN=$(get_input_with_default "请输入最小端口范围" "${DEFAULT_PORT_MIN}")
    PORT_MAX=$(get_input_with_default "请输入最大端口范围" "${DEFAULT_PORT_MAX}")
    # 确保输入是有效的数字
    if ! [[ "$PORT_MIN" =~ ^[0-9]+$ ]] || ! [[ "$PORT_MAX" =~ ^[0-9]+$ ]]; then
      error_exit "端口必须是有效的数字。"
    fi
    if [[ "$PORT_MIN" -lt 1024 ]]; then
      log_warning "使用小于1024的端口需要root权限，并可能与系统服务冲突。"
    fi
    if [[ "$PORT_MAX" -le "$PORT_MIN" ]]; then
      error_exit "最大端口必须大于最小端口。"
    fi
  else
    # 使用用户指定的端口
    CUSTOM_PORT=$(get_input_with_default "请输入要使用的SSH端口" "22222")
    if ! [[ "$CUSTOM_PORT" =~ ^[0-9]+$ ]]; then
      error_exit "端口必须是有效的数字。"
    fi
    if [[ "$CUSTOM_PORT" -lt 1024 ]]; then
      log_warning "使用小于1024的端口需要root权限，并可能与系统服务冲突。"
    fi
    if is_port_in_use "$CUSTOM_PORT"; then
      log_warning "端口 $CUSTOM_PORT 已被使用。"
      if ! get_yes_no_input "是否继续使用此端口?" "n"; then
        error_exit "已取消操作。"
      fi
    fi
  fi
fi

# 5. 询问用户是否禁用密码登录
echo ""
echo "=== SSH认证配置 ==="
if get_yes_no_input "是否禁用密码登录 (仅允许密钥认证)?" "y"; then
  DISABLE_PASSWORD_AUTH="yes"
else
  DISABLE_PASSWORD_AUTH="no"
  log_warning "保留密码认证可能会降低系统安全性。建议配置完成后测试密钥登录成功后再禁用密码认证。"
fi

# 6. 询问用户是否禁用root登录
if get_yes_no_input "是否禁用root用户直接登录 (增强安全性)?" "n"; then
  DISABLE_ROOT_LOGIN="yes"
fi

# 7. 询问用户是否安装和配置Fail2Ban
echo ""
echo "=== Fail2Ban配置 ==="
if get_yes_no_input "是否安装和配置Fail2Ban (防止暴力破解)?" "y"; then
  INSTALL_FAIL2BAN="yes"
  echo "配置Fail2Ban参数:"
  FAIL2BAN_BANTIME=$(get_input_with_default "封禁时间 (秒)" "${DEFAULT_FAIL2BAN_BANTIME}")
  FAIL2BAN_FINDTIME=$(get_input_with_default "检测时间窗口 (秒)" "${DEFAULT_FAIL2BAN_FINDTIME}")
  FAIL2BAN_MAXRETRY=$(get_input_with_default "最大尝试次数" "${DEFAULT_FAIL2BAN_MAXRETRY}")
  
  # 确保输入是有效的数字
  if ! [[ "$FAIL2BAN_BANTIME" =~ ^[0-9]+$ ]] || ! [[ "$FAIL2BAN_FINDTIME" =~ ^[0-9]+$ ]] || ! [[ "$FAIL2BAN_MAXRETRY" =~ ^[0-9]+$ ]]; then
    error_exit "Fail2Ban参数必须是有效的数字。"
  fi
  
  log_info "Fail2Ban配置: 在 ${FAIL2BAN_FINDTIME} 秒内失败 ${FAIL2BAN_MAXRETRY} 次将被封禁 ${FAIL2BAN_BANTIME} 秒。"
fi

# 8. 确认配置信息
echo ""
echo "=== 确认配置 ==="
echo "用户: $TARGET_USER"
echo "公钥已验证: $(check_ssh_public_key_basic "$PUBLIC_KEY" && echo "是" || echo "否 (但将继续使用)")"
if [[ "$CHANGE_PORT" == "yes" ]]; then
  if [[ -n "$CUSTOM_PORT" ]]; then
    echo "SSH端口: 将更改为 $CUSTOM_PORT"
  else
    echo "SSH端口: 将更改为 ${PORT_MIN}-${PORT_MAX} 范围内的随机端口"
  fi
else
  echo "SSH端口: 保持不变"
fi
echo "密码认证: $([ "$DISABLE_PASSWORD_AUTH" == "yes" ] && echo "将禁用" || echo "保持启用")"
echo "Root登录: $([ "$DISABLE_ROOT_LOGIN" == "yes" ] && echo "将禁用" || echo "保持不变")"
echo "Fail2Ban: $([ "$INSTALL_FAIL2BAN" == "yes" ] && echo "将安装和配置" || echo "不安装")"

if ! get_yes_no_input "是否确认以上配置并继续?" "y"; then
  error_exit "已取消操作。"
fi

# 9. 创建 .ssh 目录并设置权限
SSH_DIR="$USER_HOME/.ssh"
AUTH_KEYS_FILE="$SSH_DIR/authorized_keys"

mkdir -p "$SSH_DIR" || error_exit "创建目录 $SSH_DIR 失败。"
chmod 700 "$SSH_DIR" || error_exit "设置 $SSH_DIR 权限失败。"

# 10. 检查公钥是否已存在，不存在则写入 authorized_keys 文件
if [[ -f "$AUTH_KEYS_FILE" ]] && grep -qF "$PUBLIC_KEY" "$AUTH_KEYS_FILE"; then
  log_info "公钥已存在于 $AUTH_KEYS_FILE 文件中，跳过添加。"
else
  # 如果文件已存在，先备份
  if [[ -f "$AUTH_KEYS_FILE" ]]; then
    backup_file "$AUTH_KEYS_FILE"
  fi
  
  log_info "正在将公钥添加到 $AUTH_KEYS_FILE 文件..."
  echo "$PUBLIC_KEY" >> "$AUTH_KEYS_FILE" || error_exit "写入公钥到 $AUTH_KEYS_FILE 失败。"
fi
chmod 600 "$AUTH_KEYS_FILE" || error_exit "设置 $AUTH_KEYS_FILE 权限失败。"

# 11. 确保用户拥有文件和目录的所有权 (用户和组)
TARGET_GROUP=$(id -gn "$TARGET_USER") || error_exit "获取用户 '$TARGET_USER' 的组失败。"
chown -R "${TARGET_USER}:${TARGET_GROUP}" "$SSH_DIR" || error_exit "设置 $SSH_DIR 所有权失败。"

# 12. 处理 SELinux 上下文 (如果系统使用 SELinux)
if command -v restorecon &> /dev/null && command -v getenforce &> /dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
  log_info "检测到 SELinux 启用，正在恢复 $SSH_DIR 的安全上下文..."
  restorecon -Rv "$SSH_DIR" || log_info "警告：restorecon 命令执行时遇到问题，但这可能不影响功能。" # 不要因为 restorecon 失败而退出
fi

# 13. 备份并修改 SSH 配置文件
log_info "检查 SSH 配置文件 $SSHD_CONFIG_FILE ..."
if [[ ! -f "$SSHD_CONFIG_FILE" ]]; then
    error_exit "SSH 配置文件 $SSHD_CONFIG_FILE 未找到。"
fi

backup_file "$SSHD_CONFIG_FILE"

# 获取当前 SSH 端口
SSH_PORT=$(awk '/^[[:space:]]*Port[[:space:]]+/{p=$2} END{if(p) print p; else print 22}' "$SSHD_CONFIG_FILE")
log_info "当前 SSH 监听端口是: $SSH_PORT"

# 生成新的SSH端口（如果需要）
if [[ "$CHANGE_PORT" == "yes" ]]; then
  if [[ -n "$CUSTOM_PORT" ]]; then
    NEW_SSH_PORT="$CUSTOM_PORT"
  else
    NEW_SSH_PORT=$(get_unused_random_port "$PORT_MIN" "$PORT_MAX")
  fi
  log_info "将 SSH 端口从 $SSH_PORT 更改为: $NEW_SSH_PORT"
  
  # 修改SSH端口
  ensure_sshd_config "Port" "$NEW_SSH_PORT" "$SSHD_CONFIG_FILE"
else
  NEW_SSH_PORT="$SSH_PORT"
fi

log_info "配置 SSH 服务..."
ensure_sshd_config "PubkeyAuthentication" "yes" "$SSHD_CONFIG_FILE"

# 根据用户选择配置密码认证
if [[ "$DISABLE_PASSWORD_AUTH" == "yes" ]]; then
  log_info "禁用密码认证..."
  ensure_sshd_config "PasswordAuthentication" "no" "$SSHD_CONFIG_FILE"
  ensure_sshd_config "ChallengeResponseAuthentication" "no" "$SSHD_CONFIG_FILE"
else
  log_info "保留密码认证..."
  ensure_sshd_config "PasswordAuthentication" "yes" "$SSHD_CONFIG_FILE"
fi

# 禁用root登录（如果用户选择）
if [[ "$DISABLE_ROOT_LOGIN" == "yes" ]]; then
  log_info "禁用root用户直接登录..."
  ensure_sshd_config "PermitRootLogin" "no" "$SSHD_CONFIG_FILE"
fi

# 其他安全设置
ensure_sshd_config "X11Forwarding" "no" "$SSHD_CONFIG_FILE"  # 禁用X11转发，增强安全性

# 14. 安装和配置Fail2Ban（如果用户选择）
if [[ "$INSTALL_FAIL2BAN" == "yes" ]]; then
  log_info "安装和配置Fail2Ban..."
  setup_fail2ban "$NEW_SSH_PORT" "$FAIL2BAN_BANTIME" "$FAIL2BAN_FINDTIME" "$FAIL2BAN_MAXRETRY"
fi

# 15. 验证 SSH 配置
log_info "正在验证 SSH 配置..."
if sshd -t -f "$SSHD_CONFIG_FILE"; then
  log_info "SSH 配置验证成功。"
else
  error_exit "SSH 配置文件 ($SSHD_CONFIG_FILE) 语法错误！请在重启 SSH 服务前手动修复。备份文件位于 ${SSHD_CONFIG_FILE}${BACKUP_SUFFIX}"
fi

# 16. 如果更改了端口，打开防火墙端口（如果有防火墙）
if [[ "$CHANGE_PORT" == "yes" ]]; then
  log_info "检查并配置防火墙以允许新SSH端口..."
  if command -v firewall-cmd &>/dev/null; then
    # Firewalld (CentOS/RHEL/Fedora)
    firewall-cmd --add-port="$NEW_SSH_PORT/tcp" --permanent
    firewall-cmd --reload
    log_info "已在 firewalld 中添加端口 $NEW_SSH_PORT/tcp"
  elif command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    # UFW (Ubuntu/Debian)
    ufw allow "$NEW_SSH_PORT/tcp"
    log_info "已在 ufw 中添加端口 $NEW_SSH_PORT/tcp"
  elif command -v iptables &>/dev/null; then
    # iptables
    iptables -A INPUT -p tcp --dport "$NEW_SSH_PORT" -j ACCEPT
    if command -v iptables-save &>/dev/null; then
      if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save
      elif [[ -d "/etc/iptables" ]]; then
        iptables-save > /etc/iptables/rules.v4
      fi
    fi
    log_info "已在 iptables 中添加端口 $NEW_SSH_PORT/tcp"
  fi
fi

# 17. 重启 SSH 服务
log_info "正在重启 SSH 服务以应用配置..."
if command -v systemctl &> /dev/null; then
  systemctl restart sshd || error_exit "使用 systemctl 重启 sshd 服务失败。"
else
  service ssh restart || service sshd restart || error_exit "使用 service 重启 ssh/sshd 服务失败。"
fi
log_info "SSH 服务已重启。"

# 18. 输出最终信息和连接说明
echo ""
echo "==================================================="
echo "           SSH 配置已成功完成                      "
echo "==================================================="
log_info "配置摘要:"
log_info "- 用户: $TARGET_USER"
log_info "- SSH端口: $NEW_SSH_PORT"
log_info "- 密码认证: $([ "$DISABLE_PASSWORD_AUTH" == "yes" ] && echo "已禁用" || echo "已启用")"
log_info "- Root直接登录: $([ "$DISABLE_ROOT_LOGIN" == "yes" ] && echo "已禁用" || echo "未改变")"
log_info "- Fail2Ban: $([ "$INSTALL_FAIL2BAN" == "yes" ] && echo "已安装和配置" || echo "未安装")"

echo ""
echo "重要提示:"
echo "1. 请立即在新的终端窗口中使用您的私钥测试连接:"
echo "   ssh -p $NEW_SSH_PORT $TARGET_USER@<服务器IP或主机名>"
echo "2. 在确认新连接可以正常工作之前，请【不要】关闭当前的 SSH 会话！"
echo "3. 如果出现问题，您可以使用备份文件恢复配置:"
echo "   - SSH 配置备份: ${SSHD_CONFIG_FILE}${BACKUP_SUFFIX}"
if [[ "$INSTALL_FAIL2BAN" == "yes" ]]; then
  echo "   - Fail2Ban 配置备份 (如果修改了): ${FAIL2BAN_JAIL_LOCAL}${BACKUP_SUFFIX}"
fi

if [[ "$CHANGE_PORT" == "yes" ]]; then
  echo "4. 新的SSH端口是: $NEW_SSH_PORT，请务必记住这个端口号！"
  echo ""
  echo "下次连接到此服务器时，请使用如下命令:"
  echo "ssh -p $NEW_SSH_PORT $TARGET_USER@<服务器IP或主机名>"
fi

if [[ "$DISABLE_PASSWORD_AUTH" == "no" ]]; then
  echo ""
  echo "安全提示: 您选择保留密码认证。为了增强安全性，建议在成功测试密钥登录后禁用密码认证。"
  echo "可以通过修改 $SSHD_CONFIG_FILE 文件，将 'PasswordAuthentication' 设置为 'no'，然后重启SSH服务实现。"
fi

echo ""
log_info "脚本执行完毕。"

exit 0
