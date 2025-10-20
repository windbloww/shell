#!/bin/bash

#========================================================================================
#
#   脚本名称: Debian 软件源一键替换脚本 (国内服务器专用)
#   功能描述: 自动检测 Debian 版本 (12/13)，并替换为国内镜像源。
#   支持版本: Debian 12 (Bookworm), Debian 13 (Trixie)
#   日    期: 2025-10-19
#
#========================================================================================

# 字体颜色定义
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
NC="\033[0m" # No Color

# 确保脚本以 root 权限运行
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}错误: 请以 root 用户权限运行此脚本。${NC}"
    exit 1
fi

# --- 函数定义 ---

# 获取 Debian 版本代号 (codename)
get_debian_codename() {
    # . /etc/os-release 文件包含了所有需要的版本信息
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        # VERSION_CODENAME 变量存储了版本代号，如 "bookworm" 或 "trixie"
        echo "$VERSION_CODENAME"
    else
        echo ""
    fi
}

# 备份原始的 sources.list 文件
backup_sources_list() {
    # 检查文件是否存在
    if [ -f /etc/apt/sources.list ]; then
        # -v 参数会让 cp 命令显示操作信息
        cp -v /etc/apt/sources.list /etc/apt/sources.list.bak
        echo -e "${GREEN}原始源文件 /etc/apt/sources.list 已备份至 /etc/apt/sources.list.bak${NC}"
    else
        echo -e "${YELLOW}警告: /etc/apt/sources.list 文件不存在，无需备份。${NC}"
    fi
}

# 更新软件源
update_sources() {
    echo -e "\n${GREEN}开始更新软件包列表...${NC}"
    # apt update 会下载最新的软件包信息
    if apt update; then
        echo -e "${GREEN}软件包列表更新成功！${NC}"
        echo -e "${YELLOW}现在你可以使用 'apt upgrade' 来更新已安装的软件包。${NC}"
    else
        echo -e "${RED}软件包列表更新失败。请检查网络连接或源文件配置。${NC}"
    fi
}


# --- 主逻辑 ---

echo -e "${GREEN}=====================================================${NC}"
echo -e "${GREEN}     Debian 12/13 国内镜像源一键替换脚本     ${NC}"
echo -e "${GREEN}=====================================================${NC}"

# 1. 获取版本代号
CODENAME=$(get_debian_codename)

if [ -z "$CODENAME" ]; then
    echo -e "${RED}无法检测到 Debian 版本代号。脚本退出。${NC}"
    exit 1
fi

echo -e "检测到您的 Debian 版本代号为: ${YELLOW}$CODENAME${NC}"

# 2. 根据版本代号选择源
case "$CODENAME" in
    "bookworm")
        # Debian 12 (Bookworm) 的源
        SOURCES_CONTENT="
# 默认注释了源码镜像，以提高 apt update 速度，如有需要可自行取消注释
deb https://mirrors.aliyun.com/debian/ bookworm main contrib non-free non-free-firmware
# deb-src https://mirrors.aliyun.com/debian/ bookworm main contrib non-free non-free-firmware

deb https://mirrors.aliyun.com/debian/ bookworm-updates main contrib non-free non-free-firmware
# deb-src https://mirrors.aliyun.com/debian/ bookworm-updates main contrib non-free non-free-firmware

deb https://mirrors.aliyun.com/debian/ bookworm-backports main contrib non-free non-free-firmware
# deb-src https://mirrors.aliyun.com/debian/ bookworm-backports main contrib non-free non-free-firmware

deb https://mirrors.aliyun.com/debian-security bookworm-security main contrib non-free non-free-firmware
# deb-src https://mirrors.aliyun.com/debian-security bookworm-security main contrib non-free non-free-firmware
"
        ;;
    "trixie")
        # Debian 13 (Trixie) 的源
        SOURCES_CONTENT="
# 默认注释了源码镜像，以提高 apt update 速度，如有需要可自行取消注释
deb https://mirrors.aliyun.com/debian/ trixie main contrib non-free non-free-firmware
# deb-src https://mirrors.aliyun.com/debian/ trixie main contrib non-free non-free-firmware

deb https://mirrors.aliyun.com/debian/ trixie-updates main contrib non-free non-free-firmware
# deb-src https://mirrors.aliyun.com/debian/ trixie-updates main contrib non-free non-free-firmware

deb https://mirrors.aliyun.com/debian/ trixie-backports main contrib non-free non-free-firmware
# deb-src https://mirrors.aliyun.com/debian/ trixie-backports main contrib non-free non-free-firmware

# Debian 13 的 security 源目前可能还未正式设立，此处暂时使用 testing-security
# 未来 Trixie 稳定后，官方会提供 trixie-security 源
deb https://mirrors.aliyun.com/debian-security testing-security main contrib non-free non-free-firmware
# deb-src https://mirrors.aliyun.com/debian-security testing-security main contrib non-free non-free-firmware
"
        ;;
    *)
        echo -e "${RED}不支持的 Debian 版本: $CODENAME。此脚本仅支持 'bookworm' (12) 和 'trixie' (13)。${NC}"
        exit 1
        ;;
esac

# 3. 备份并写入新的源文件
echo -e "\n${YELLOW}即将执行以下操作:${NC}"
echo "1. 备份当前的源文件 /etc/apt/sources.list"
echo "2. 将源替换为适用于 ${CODENAME} 的阿里云镜像源"
echo "3. 运行 apt update 更新软件包列表"
read -p "是否继续? (y/N): " choice

# -z "$choice" 检查用户是否直接按了回车
if [[ "$choice" == "y" || "$choice" == "Y" || -z "$choice" ]]; then
    backup_sources_list
    echo -e "\n${GREEN}正在写入新的源文件...${NC}"
    # 使用 tee 命令将内容写入文件，同时在终端显示
    echo "$SOURCES_CONTENT" | tee /etc/apt/sources.list > /dev/null
    echo -e "${GREEN}新的源文件已成功写入 /etc/apt/sources.list${NC}"
    update_sources
else
    echo -e "${YELLOW}操作已取消。${NC}"
fi
