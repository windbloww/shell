#!/bin/bash

# 开启严格模式，确保脚本在错误时退出
set -euo pipefail

# 检测是否以 root 用户运行
if [ "$(id -u)" -ne 0 ]; then
  echo "请以 root 用户运行此脚本。"
  exit 1
fi

# 提示用户粘贴公钥
read -p "请粘贴您的 SSH 公钥 (以 ssh-rsa 或 ssh-ed25519 开头): " PUBLIC_KEY

# 验证公钥是否为空
if [[ -z "$PUBLIC_KEY" ]]; then
  echo "公钥不能为空，请重新运行脚本并输入有效的公钥。"
  exit 1
fi

# 获取当前用户的家目录路径
USER_HOME=$(eval echo ~${SUDO_USER:-$USER})

# 创建 .ssh 目录并设置权限
mkdir -p "$USER_HOME/.ssh"
chmod 700 "$USER_HOME/.ssh"

# 写入公钥到 authorized_keys 文件
echo "$PUBLIC_KEY" >> "$USER_HOME/.ssh/authorized_keys"
chmod 600 "$USER_HOME/.ssh/authorized_keys"

# 确保用户拥有文件权限
chown -R "${SUDO_USER:-$USER}" "$USER_HOME/.ssh"

# 检测 SSH 配置文件路径
SSHD_CONFIG="/etc/ssh/sshd_config"

# 检测当前使用的 SSH 端口（默认值为22）
SSH_PORT=$(grep "^Port " $SSHD_CONFIG | awk '{print $2}' || echo "22")

echo "当前 SSH 使用的端口是: $SSH_PORT"

# 修改 SSH 配置以禁用密码登录和挑战响应认证
if grep -q "^PasswordAuthentication" "$SSHD_CONFIG"; then
  sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
else
  echo "PasswordAuthentication no" >> "$SSHD_CONFIG"
fi

if grep -q "^ChallengeResponseAuthentication" "$SSHD_CONFIG"; then
  sed -i 's/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$SSHD_CONFIG"
else
  echo "ChallengeResponseAuthentication no" >> "$SSHD_CONFIG"
fi

if ! grep -q "^PubkeyAuthentication yes" "$SSHD_CONFIG"; then
  echo "PubkeyAuthentication yes" >> "$SSHD_CONFIG"
fi

# 重启 SSH 服务应用更改
echo "重启 SSH 服务以应用配置..."
systemctl restart sshd || service ssh restart

# 检查 fail2ban 是否启用了自定义端口并更新规则（如果适用）
if command -v fail2ban-client &>/dev/null; then
  echo "检测到 Fail2Ban，检查其是否配置了正确的 SSH 端口..."
  FAIL2BAN_JAIL="/etc/fail2ban/jail.local"
  
  if [[ -f $FAIL2BAN_JAIL ]]; then
    if grep -q "\[sshd\]" $FAIL2BAN_JAIL; then
      sed -i "/\[sshd\]/,/^$/ s/^port =.*/port = $SSH_PORT/" $FAIL2BAN_JAIL
      echo "Fail2Ban 已更新为使用端口 $SSH_PORT。"
    else
      echo "[sshd] 未在 Fail2Ban 配置中找到，跳过修改。"
    fi
    
    # 重启 Fail2Ban 服务以应用更改
    systemctl restart fail2ban || service fail2ban restart
    echo "Fail2Ban 服务已重启。"
  fi
fi

echo "SSH 密钥登录已成功配置，密码登录已禁用。请使用您的私钥通过以下命令测试连接："
echo "ssh -p $SSH_PORT username@server_ip"

echo "注意：请勿关闭当前会话，直到确认新配置正常工作！"
