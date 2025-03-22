#!/bin/bash

# 设置为set -x来调试脚本
#set -x
# 脚本信息
AUTHOR="moonshot6"
VERSION="1.2"
SCRIPT_NAME="sing-box 一键安装脚本"
GITHUB_REPO="moonshot6/sing-box"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# 函数：输出信息
msg() {
    echo -e "${GREEN}[INFO]$(date +'%Y-%m-%d %H:%M:%S') ${1}${NC}"
}

# 函数：输出警告
warn() {
    echo -e "${YELLOW}[WARN]$(date +'%Y-%m-%d %H:%M:%S') ${1}${NC}"
}

# 函数：输出错误
error() {
    echo -e "${RED}[ERROR]$(date +'%Y-%m-%d %H:%M:%S') ${1}${NC}"
    exit 1
}

# 检查 root 权限
if [[ $EUID -ne 0 ]]; then
    error "请使用 root 用户运行此脚本。"
fi

# 检查系统类型
if ! command -v apt-get &>/dev/null && ! command -v yum &>/dev/null; then
    error "此脚本仅支持 Debian/Ubuntu 或 CentOS 系统。"
fi

# 定义变量
SB_VERSION="latest" # 默认使用最新版本，你可以修改它
SB_DIR="/usr/local/sing-box"
SB_BIN="${SB_DIR}/sing-box"
SB_CONFIG="/etc/sing-box/config.json"
SB_USER="singbox"
SB_LOG="/var/log/sing-box.log"
SYSTEMD_FILE="/etc/systemd/system/sing-box.service"

# 下载工具函数
download() {
  local url="$1"
  local filename="$2"

  msg "正在下载: ${url} -> ${filename}"
  if ! wget -q --show-progress --no-check-certificate -O "${filename}" "${url}"; then
    error "下载失败: ${url}"
  fi
}

# 安装依赖
install_dependencies() {
    msg "正在安装依赖..."
    if command -v apt-get &>/dev/null; then
        apt-get update &>/dev/null
        apt-get install -y wget curl jq iptables &>/dev/null
    elif command -v yum &>/dev/null; then
        yum install -y wget curl jq iptables &>/dev/null
    else
        error "不支持的包管理器."
    fi
}

# 获取 sing-box 二进制文件
get_sing_box() {
    local arch
    case "$(uname -m)" in
        x86_64)
            arch="amd64"
            ;;
        aarch64)
            arch="arm64"
            ;;
        *)
            error "不支持的系统架构."
            ;;
    esac

    # 如果指定了版本，则使用指定版本下载，否则下载latest版本，从github release获得
    if [ "$SB_VERSION" == "latest" ]; then
      SB_VERSION=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r .tag_name)
    fi

    local download_url="https://github.com/SagerNet/sing-box/releases/download/${SB_VERSION}/sing-box-${SB_VERSION:1}-linux-${arch}.tar.gz"
    local tar_file="/tmp/sing-box.tar.gz"
    download "${download_url}" "${tar_file}"

    msg "正在解压..."
    mkdir -p "${SB_DIR}"
    tar -xzf "${tar_file}" -C "${SB_DIR}" --strip-components=1
    rm -f "${tar_file}"

    chmod +x "${SB_BIN}"
}

# 创建 sing-box 用户
create_user() {
    msg "正在创建用户..."
    id -u "$SB_USER" &>/dev/null && warn "用户 ${SB_USER} 已经存在." && return
    useradd -r -s /sbin/nologin "$SB_USER"
}

# 生成 VLESS-Reality 配置文件
generate_default_config() {
    msg "正在生成默认 VLESS-Reality 配置文件..."
    local uuid=$(uuidgen)
    local port=$(( ( RANDOM % 16383 )  + 49152 )) # 随机生成端口
    local sni="www.google.com" # 默认 SNI

    # 自动生成 Reality 公钥和 Short ID
    public_key=$(openssl rand -hex 32)
    short_id=$(openssl rand -hex 8)

    local config=$(cat <<EOF
{
  "log": {
    "level": "info",
    "output": "file",
    "output_path": "${SB_LOG}"
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 10808,
      "sniff": true,
      "domain_strategy": "prefer_ipv4"
    }
  ],
  "outbounds": [
    {
      "type": "vless",
      "tag": "vless-out",
      "server": "127.0.0.1",
      "server_port": ${port},
      "uuid": "${uuid}",
      "encryption": "none",
      "flow": "",
      "tls": {
        "enabled": true,
        "server_name": "${sni}",
        "alpn": [
          "h2",
          "http/1.1"
        ],
        "reality_opts": {
          "enabled": true,
          "public_key": "${public_key}",
          "short_id": "${short_id}"
        }
      },
      "transport": {
        "type": "tcp",
        "tcp_opts": {
          "header": {
            "type": "none"
          }
        }
      }
    },
    {
      "type": "selector",
      "tag": "proxy",
      "outbounds": [
        "vless-out"
      ]
    },
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    },
    {
      "type": "dns",
      "tag": "dns-out"
    }
  ],
  "route": {
    "rules": [
      {
        "protocol": [
          "dns"
        ],
        "outbound": "dns-out"
      },
      {
        "domain": [
          "geosite:category-ads-all"
        ],
        "outbound": "block"
      },
      {
        "domain": [
          "geoip:private"
        ],
        "outbound": "direct"
      },
      {
        "port": [
          53,
          5353
        ],
        "outbound": "dns-out"
      }
    ],
    "auto_detect_interface": true,
    "final": "proxy"
  },
  "dns": {
    "strategy": "prefer_ipv4",
    "servers": [
      {
        "tag": "local",
        "address": "127.0.0.1",
        "detour": "direct"
      },
      {
        "tag": "bootstrap",
        "address": "https://1.1.1.1/dns-query",
        "strategy": "fixed",
        "detour": "direct",
        "use_domains": false
      }
    ]
  }
}
EOF
)

    mkdir -p /etc/sing-box/
    echo "${config}" >"${SB_CONFIG}"
    chown "$SB_USER":"$SB_USER" "${SB_CONFIG}"

    # 输出 URL，方便导入客户端
    local url="vless://${uuid}@${ip}:${port}?encryption=none&flow=&security=reality&sni=${sni}&pbk=${public_key}&sid=${short_id}&spdy=h2,http/1.1&type=tcp&headerType=none#Reality"
    msg "VLESS-Reality URL: ${url}"
}

# 设置 BBR
enable_bbr() {
    msg "正在启用 BBR..."
    echo "net.core.default_qdisc=fq" >>/etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.conf
    sysctl -p &>/dev/null
    lsmod | grep bbr &>/dev/null || warn "BBR 未生效，请检查内核版本是否支持 BBR。"
}

# 创建 systemd 服务
create_systemd_service() {
    msg "正在创建 systemd 服务..."
    local service_content=$(cat <<EOF
[Unit]
Description=sing-box 服务
After=network.target

[Service]
User=$SB_USER
Group=$SB_USER
WorkingDirectory=$SB_DIR
ExecStart=$SB_BIN run -c $SB_CONFIG
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
)

    echo "${service_content}" >"${SYSTEMD_FILE}"
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    msg "sing-box 服务已启动."
}

# 创建 sb 命令快捷方式
create_sb_command() {
    msg "正在创建 sb 命令..."
    echo "#!/bin/bash
${SB_BIN} \$@" > /usr/local/bin/sb
    chmod +x /usr/local/bin/sb
}

# 清理函数
cleanup() {
    msg "正在进行清理..."
    rm -f /tmp/sing-box.tar.gz
}

# 卸载函数
uninstall() {
  read -r -p "确定要卸载 sing-box 吗？(y/n) " input
  if [[ "$input" != "y" && "$input" != "Y" ]]; then
    msg "已取消卸载."
    exit 0
  fi

  msg "正在停止 sing-box 服务..."
  systemctl stop sing-box &>/dev/null
  systemctl disable sing-box &>/dev/null

  msg "正在删除文件..."
  rm -rf "${SB_DIR}"
  rm -f "${SB_CONFIG}"
  rm -f "${SYSTEMD_FILE}"
  rm -f /usr/local/bin/sb
  userdel "$SB_USER" &>/dev/null

  msg "卸载完成."
  exit 0
}

# 获取服务器 IP 地址
get_server_ip() {
  ip=$(curl -s ifconfig.me)
  if [ -z "$ip" ]; then
    error "无法获取服务器 IP 地址."
  fi
}

# 主函数
main() {
    msg "欢迎使用 ${SCRIPT_NAME} v${VERSION}!"

    # 检查是否需要卸载
    if [[ "$1" == "uninstall" ]]; then
      uninstall
      exit 0
    fi

    # 安装依赖
    install_dependencies

    # 获取 sing-box
    get_sing_box

    # 创建用户
    create_user

    # 获取服务器 IP 地址
    get_server_ip

    # 生成默认配置文件
    generate_default_config

    # 启用 BBR
    enable_bbr

    # 创建 systemd 服务
    create_systemd_service

    # 创建 sb 命令
    create_sb_command

    # 清理
    cleanup

    msg "安装完成！"
    msg "可以使用 sb 命令管理 sing-box."
}

# 运行主函数
main "$@"
