#!/bin/bash

# 检查是否以 root 用户运行
if [ "$(id -u)" -ne 0 ]; then
  echo "请以 root 用户运行此脚本。"
  exit 1
fi

# 提示用户输入公钥
read -p "请粘贴您的公钥内容 (以 ssh-rsa 开头): " PUBLIC_KEY

# 验证公钥是否为空
if [[ -z "$PUBLIC_KEY" ]]; then
  echo "公钥不能为空，请重新运行脚本并输入有效的公钥。"
  exit 1
fi

# 设置用户家目录路径（假设为当前登录用户）
USER_HOME=$(eval echo ~${SUDO_USER:-$USER})

# 创建 .ssh 目录并设置权限
mkdir -p "$USER_HOME/.ssh"
chmod 700 "$USER_HOME/.ssh"

# 将公钥写入 authorized_keys 文件
echo "$PUBLIC_KEY" >> "$USER_HOME/.ssh/authorized_keys"
chmod 600 "$USER_HOME/.ssh/authorized_keys"

# 修改 SSH 配置文件以禁用密码登录
SSHD_CONFIG="/etc/ssh/sshd_config"
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

# 重启 SSH 服务以应用更改
systemctl restart ssh

echo "SSH 密钥认证已成功配置，密码登录已禁用。请使用您的私钥登录服务器。"
