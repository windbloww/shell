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

# --- 函数定义 ---

# 输出错误信息并退出
error_exit() {
  echo "错误: $1" >&2
  exit 1
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


# --- 主逻辑 ---

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


# 3. 提示用户粘贴公钥并进行基本验证
read -p "请粘贴用户 '$TARGET_USER' 的 SSH 公钥 (以 ssh-rsa, ssh-ed25519, ecdsa-sha2-nistp... 开头): " PUBLIC_KEY

# 验证公钥是否为空
if [[ -z "$PUBLIC_KEY" ]]; then
  error_exit "公钥不能为空。"
fi

# 基本格式验证 (检查是否以常见类型开头，后面跟空格)
if ! echo "$PUBLIC_KEY" | grep -Eq '^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519|sk-ecdsa-sha2-nistp256)\s+'; then
  error_exit "公钥格式似乎无效。请确保以 ssh-rsa, ssh-ed25519 等开头，并包含空格。"
fi

# 4. 创建 .ssh 目录并设置权限
SSH_DIR="$USER_HOME/.ssh"
AUTH_KEYS_FILE="$SSH_DIR/authorized_keys"

mkdir -p "$SSH_DIR" || error_exit "创建目录 $SSH_DIR 失败。"
chmod 700 "$SSH_DIR" || error_exit "设置 $SSH_DIR 权限失败。"

# 5. 检查公钥是否已存在，不存在则写入 authorized_keys 文件
if grep -qF "$PUBLIC_KEY" "$AUTH_KEYS_FILE" &>/dev/null; then
  log_info "公钥已存在于 $AUTH_KEYS_FILE 文件中，跳过添加。"
else
  log_info "正在将公钥添加到 $AUTH_KEYS_FILE 文件..."
  echo "$PUBLIC_KEY" >> "$AUTH_KEYS_FILE" || error_exit "写入公钥到 $AUTH_KEYS_FILE 失败。"
fi
chmod 600 "$AUTH_KEYS_FILE" || error_exit "设置 $AUTH_KEYS_FILE 权限失败。"

# 6. 确保用户拥有文件和目录的所有权 (用户和组)
TARGET_GROUP=$(id -gn "$TARGET_USER") || error_exit "获取用户 '$TARGET_USER' 的组失败。"
chown -R "${TARGET_USER}:${TARGET_GROUP}" "$SSH_DIR" || error_exit "设置 $SSH_DIR 所有权失败。"

# 7. 处理 SELinux 上下文 (如果系统使用 SELinux)
if command -v restorecon &> /dev/null && command -v getenforce &> /dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
  log_info "检测到 SELinux 启用，正在恢复 $SSH_DIR 的安全上下文..."
  restorecon -Rv "$SSH_DIR" || log_info "警告：restorecon 命令执行时遇到问题，但这可能不影响功能。" # 不要因为 restorecon 失败而退出
fi

# 8. 备份并修改 SSH 配置文件
log_info "检查 SSH 配置文件 $SSHD_CONFIG_FILE ..."
if [[ ! -f "$SSHD_CONFIG_FILE" ]]; then
    error_exit "SSH 配置文件 $SSHD_CONFIG_FILE 未找到。"
fi

backup_file "$SSHD_CONFIG_FILE"

# 获取当前 SSH 端口 (更健壮的方式)
# awk: 查找最后一个非注释的 Port 指令，如果没有则默认为 22
SSH_PORT=$(awk '/^[[:space:]]*Port[[:space:]]+/{p=$2} END{if(p) print p; else print 22}' "$SSHD_CONFIG_FILE")
log_info "当前 SSH 监听端口是: $SSH_PORT"

log_info "配置 SSH 服务以禁用密码登录并启用公钥认证..."
ensure_sshd_config "PubkeyAuthentication" "yes" "$SSHD_CONFIG_FILE"
ensure_sshd_config "PasswordAuthentication" "no" "$SSHD_CONFIG_FILE"
ensure_sshd_config "ChallengeResponseAuthentication" "no" "$SSHD_CONFIG_FILE"
# 可选：如果需要，可以禁用 root 登录
# ensure_sshd_config "PermitRootLogin" "no" "$SSHD_CONFIG_FILE"

# 9. 验证 SSH 配置
log_info "正在验证 SSH 配置..."
if sshd -t -f "$SSHD_CONFIG_FILE"; then
  log_info "SSH 配置验证成功。"
else
  error_exit "SSH 配置文件 ($SSHD_CONFIG_FILE) 语法错误！请在重启 SSH 服务前手动修复。备份文件位于 ${SSHD_CONFIG_FILE}${BACKUP_SUFFIX}"
fi

# 10. 重启 SSH 服务
log_info "正在重启 SSH 服务以应用配置..."
if command -v systemctl &> /dev/null; then
  systemctl restart sshd || error_exit "使用 systemctl 重启 sshd 服务失败。"
else
  service ssh restart || service sshd restart || error_exit "使用 service 重启 ssh/sshd 服务失败。"
fi
log_info "SSH 服务已重启。"

# 11. 更新 Fail2Ban 配置 (如果已安装)
if command -v fail2ban-client &>/dev/null; then
  log_info "检测到 Fail2Ban，检查其 SSH 端口配置..."
  if [[ -f "$FAIL2BAN_JAIL_LOCAL" ]]; then
    # 检查 [sshd] 部分是否存在
    if grep -q '^[[:space:]]*\[sshd\]' "$FAIL2BAN_JAIL_LOCAL"; then
      backup_file "$FAIL2BAN_JAIL_LOCAL"
      # 查找 [sshd] 部分内的 port 设置
      # 使用 awk 更精确地定位和修改或添加 port 行
      awk -v port="$SSH_PORT" '
      BEGIN { in_sshd_section = 0; port_found = 0; }
      /^[[:space:]]*\[sshd\]/ { in_sshd_section = 1; print; next; }
      /^[[:space:]]*\[.*\]/ { if(in_sshd_section && !port_found) { print "port = " port; port_found = 1 }; in_sshd_section = 0; }
      in_sshd_section {
          if (/^[#[:space:]]*port[[:space:]]*=/) {
              print "port = " port;
              port_found = 1;
          } else {
              print;
          }
          next;
      }
      { print }
      END { if(in_sshd_section && !port_found) { print "port = " port; } }
      ' "$FAIL2BAN_JAIL_LOCAL" > "${FAIL2BAN_JAIL_LOCAL}.tmp" && mv "${FAIL2BAN_JAIL_LOCAL}.tmp" "$FAIL2BAN_JAIL_LOCAL"

      log_info "Fail2Ban 配置 ($FAIL2BAN_JAIL_LOCAL) 中的 [sshd] port 已更新/添加为 $SSH_PORT。"

      # 重启 Fail2Ban 服务
      log_info "正在重启 Fail2Ban 服务..."
      if command -v systemctl &> /dev/null; then
        systemctl restart fail2ban || log_info "警告：使用 systemctl 重启 fail2ban 服务失败。"
      else
        service fail2ban restart || log_info "警告：使用 service 重启 fail2ban 服务失败。"
      fi
      log_info "Fail2Ban 服务已重启 (或尝试重启)。"
    else
      log_info "[sshd] 部分未在 $FAIL2BAN_JAIL_LOCAL 中找到，跳过 Fail2Ban 端口修改。"
      log_info "如果需要 Fail2Ban 监控 SSH，请手动在 $FAIL2BAN_JAIL_LOCAL 中添加或取消注释 [sshd] 部分并设置 'enabled = true' 和 'port = $SSH_PORT'。"
    fi
  else
    log_info "$FAIL2BAN_JAIL_LOCAL 文件不存在，跳过 Fail2Ban 配置。"
    log_info "如果安装了 Fail2Ban，建议创建 $FAIL2BAN_JAIL_LOCAL 文件并配置 SSH 监控。"
  fi
fi

# 12. 输出最终信息
echo ""
log_info "SSH 密钥登录已为用户 '$TARGET_USER' 配置完成，密码登录已禁用。"
log_info "使用的 SSH 端口是: $SSH_PORT"
echo ""
echo "重要提示:"
echo "1. 请立即在新的终端窗口中使用您的私钥测试连接:"
echo "   ssh -p $SSH_PORT $TARGET_USER@<服务器IP或主机名>"
echo "2. 在确认新连接可以正常工作之前，请【不要】关闭当前的 SSH 会话！"
echo "3. 如果出现问题，您可以使用备份文件恢复配置:"
echo "   - SSH 配置备份: ${SSHD_CONFIG_FILE}${BACKUP_SUFFIX}"
echo "   - Fail2Ban 配置备份 (如果修改了): ${FAIL2BAN_JAIL_LOCAL}${BACKUP_SUFFIX}"
echo ""
log_info "脚本执行完毕。"

exit 0
