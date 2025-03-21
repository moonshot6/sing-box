#!/usr/bin/env bash

# 脚本版本
VERSION="v1.0.0 (2025.03.21)"

# 工作目录和临时目录
WORK_DIR="/etc/sing-box"
TEMP_DIR="/tmp/sing-box"

# 默认端口
VLESS_PORT_DEFAULT=443
VMESS_PORT_DEFAULT=80

# 默认 UUID
UUID_DEFAULT=$(cat /proc/sys/kernel/random/uuid)

# 默认域名（用于 Reality 和 WebSocket）
TLS_SERVER_DEFAULT="www.example.com"
VMESS_HOST_DEFAULT="vmess.example.com"

# 颜色输出函数
warning() { echo -e "\033[31m\033[01m$*\033[0m"; }
error() { echo -e "\033[31m\033[01m$*\033[0m" && exit 1; }
info() { echo -e "\033[32m\033[01m$*\033[0m"; }
hint() { echo -e "\033[33m\033[01m$*\033[0m"; }
reading() { read -rp "$(info "$1")" "$2"; }

# 检查 root 权限
check_root() {
  [ "$(id -u)" != 0 ] && error "This script must be run as root. Please use 'sudo -i' and try again."
}

# 检查系统支持
check_system() {
  if [ -s /etc/os-release ]; then
    SYS=$(awk -F '"' 'tolower($0) ~ /pretty_name/{print $2}' /etc/os-release)
  else
    error "Unsupported system. This script only supports Debian, Ubuntu, or CentOS."
  fi

  REGEX=("debian" "Ubuntu" "centos|red hat|kernel|alma|rocky")
  RELEASE=("Debian" "Ubuntu" "CentOS")
  MAJOR=("9" "20" "7")
  PACKAGE_UPDATE=("apt -y update" "apt -y update" "yum -y update --skip-broken")
  PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install")
  PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove")

  for i in "${!REGEX[@]}"; do
    if [[ "${SYS}" =~ ${REGEX[i]} ]]; then
      SYSTEM="${RELEASE[i]}"
      INT=$i
      break
    fi
  done

  [ -z "$SYSTEM" ] && error "Unsupported system: $SYS. This script only supports Debian, Ubuntu, or CentOS."
  VERSION_NUM=$(echo "$SYS" | sed "s/[^0-9.]//g" | cut -d. -f1)
  if [[ -z "$VERSION_NUM" || "$VERSION_NUM" -lt "${MAJOR[$INT]}" ]]; then
    error "System version too old: $SYS. Minimum supported version is ${RELEASE[$INT]} ${MAJOR[$INT]}."
  fi
}

# 检查处理器架构
check_arch() {
  case "$(uname -m)" in
    x86_64|amd64)
      ARCH="amd64"
      ;;
    aarch64|arm64)
      ARCH="arm64"
      ;;
    *)
      error "Unsupported architecture: $(uname -m). Only x86_64 and arm64 are supported."
  esac
}

# 安装依赖
install_dependencies() {
  info "Installing dependencies..."
  ${PACKAGE_UPDATE[$INT]}
  ${PACKAGE_INSTALL[$INT]} curl iptables
}

# 下载并验证 Sing-box
download_sing_box() {
  info "Downloading Sing-box..."
  mkdir -p $TEMP_DIR $WORK_DIR

  # 获取最新版本
  LATEST_VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep tag_name | cut -d '"' -f 4 | sed 's/^v//')
  [ -z "$LATEST_VERSION" ] && error "Failed to fetch the latest Sing-box version."

  # 下载 Sing-box
  SING_BOX_URL="https://github.com/SagerNet/sing-box/releases/download/v${LATEST_VERSION}/sing-box-${LATEST_VERSION}-linux-${ARCH}.tar.gz"
  curl -L -o $TEMP_DIR/sing-box.tar.gz "$SING_BOX_URL" || error "Failed to download Sing-box."

  # 验证 SHA256 校验和
  SHA256_URL="https://github.com/SagerNet/sing-box/releases/download/v${LATEST_VERSION}/SHA256SUMS"
  curl -L -o $TEMP_DIR/SHA256SUMS "$SHA256_URL" || error "Failed to download SHA256SUMS."
  EXPECTED_SHA256=$(grep "sing-box-${LATEST_VERSION}-linux-${ARCH}.tar.gz" $TEMP_DIR/SHA256SUMS | awk '{print $1}')
  ACTUAL_SHA256=$(sha256sum $TEMP_DIR/sing-box.tar.gz | awk '{print $1}')
  [ "$EXPECTED_SHA256" != "$ACTUAL_SHA256" ] && error "SHA256 checksum mismatch. Expected: $EXPECTED_SHA256, Actual: $ACTUAL_SHA256."

  # 解压并安装
  tar -xzf $TEMP_DIR/sing-box.tar.gz -C $TEMP_DIR || error "Failed to extract Sing-box."
  mv $TEMP_DIR/sing-box-${LATEST_VERSION}-linux-${ARCH}/sing-box $WORK_DIR/sing-box || error "Failed to move Sing-box binary."
  chmod +x $WORK_DIR/sing-box
}

# 输入 VLESS 和 VMESS 端口
input_ports() {
  info "Configuring ports..."
  reading "Enter VLESS port (default: $VLESS_PORT_DEFAULT): " VLESS_PORT
  VLESS_PORT=${VLESS_PORT:-$VLESS_PORT_DEFAULT}
  if ! [[ "$VLESS_PORT" =~ ^[0-9]+$ && "$VLESS_PORT" -ge 1 && "$VLESS_PORT" -le 65535 ]]; then
    error "Invalid VLESS port: $VLESS_PORT. Must be between 1 and 65535."
  fi
  ss -nltup | grep -q ":$VLESS_PORT" && error "Port $VLESS_PORT is already in use."

  reading "Enter VMESS port (default: $VMESS_PORT_DEFAULT): " VMESS_PORT
  VMESS_PORT=${VMESS_PORT:-$VMESS_PORT_DEFAULT}
  if ! [[ "$VMESS_PORT" =~ ^[0-9]+$ && "$VMESS_PORT" -ge 1 && "$VMESS_PORT" -le 65535 ]]; then
    error "Invalid VMESS port: $VMESS_PORT. Must be between 1 and 65535."
  fi
  ss -nltup | grep -q ":$VMESS_PORT" && error "Port $VMESS_PORT is already in use."
}

# 输入 UUID
input_uuid() {
  info "Configuring UUID..."
  reading "Enter UUID (default: $UUID_DEFAULT): " UUID
  UUID=${UUID:-$UUID_DEFAULT}
  if ! [[ ${#UUID} -eq 36 && "$UUID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    error "Invalid UUID: $UUID. Must be a valid UUID (36 characters, format: 8-4-4-4-12)."
  fi
}

# 输入域名
input_domains() {
  info "Configuring domains..."
  reading "Enter TLS server name for VLESS Reality (default: $TLS_SERVER_DEFAULT): " TLS_SERVER
  TLS_SERVER=${TLS_SERVER:-$TLS_SERVER_DEFAULT}

  reading "Enter VMESS WebSocket host domain (must be resolved in Cloudflare with origin rule to port $VMESS_PORT, default: $VMESS_HOST_DEFAULT): " VMESS_HOST
  VMESS_HOST=${VMESS_HOST:-$VMESS_HOST_DEFAULT}
}

# 配置 TUN 模式所需的系统设置
configure_tun() {
  info "Configuring system for TUN mode..."
  # 启用 IP 转发
  sysctl -w net.ipv4.ip_forward=1
  echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

  # 检查 TUN 设备
  [ -e /dev/net/tun ] || error "TUN device not found. Your VPS may not support TUN mode (e.g., OpenVZ)."

  # 设置 Sing-box 权限
  setcap cap_net_admin,cap_net_bind_service+ep $WORK_DIR/sing-box || error "Failed to set capabilities for Sing-box. TUN mode may not work."
}

# 生成 Sing-box 配置文件
generate_config() {
  info "Generating Sing-box configuration..."
  mkdir -p $WORK_DIR/conf

  # 生成 Reality 密钥对
  REALITY_KEYS=$($WORK_DIR/sing-box generate reality-keypair)
  REALITY_PRIVATE=$(echo "$REALITY_KEYS" | grep "PrivateKey" | awk '{print $2}')
  REALITY_PUBLIC=$(echo "$REALITY_KEYS" | grep "PublicKey" | awk '{print $2}')

  # Sing-box 配置文件
  cat > $WORK_DIR/config.json << EOF
{
  "log": {
    "level": "info"
  },
  "dns": {
    "servers": [
      {
        "tag": "remote",
        "address": "tls://8.8.8.8"
      },
      {
        "tag": "local",
        "address": "223.5.5.5",
        "detour": "direct"
      }
    ],
    "rules": [
      {
        "outbound": "direct",
        "server": "local"
      },
      {
        "outbound": "any",
        "server": "remote"
      }
    ],
    "fakeip": {
      "enabled": true,
      "inet4_range": "198.18.0.0/15"
    }
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": $VLESS_PORT,
      "users": [
        {
          "uuid": "$UUID",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$TLS_SERVER",
        "reality": {
          "enabled": true,
          "private_key": "$REALITY_PRIVATE",
          "public_key": "$REALITY_PUBLIC",
          "short_id": ["12345678"]
        }
      }
    },
    {
      "type": "vmess",
      "tag": "vmess-in",
      "listen": "::",
      "listen_port": $VMESS_PORT,
      "users": [
        {
          "uuid": "$UUID",
          "alterId": 0
        }
      ],
      "transport": {
        "type": "ws",
        "path": "/vmess",
        "headers": {
          "Host": "$VMESS_HOST"
        }
      }
    },
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "tun0",
      "mtu": 1500,
      "inet4_address": "172.19.0.1/30",
      "auto_route": true,
      "strict_route": true,
      "endpoint_independent_nat": false,
      "stack": "system",
      "include_interface": ["eth0"],
      "exclude_interface": []
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ],
  "route": {
    "rules": [
      {
        "geosite": ["cn"],
        "geoip": ["cn", "private"],
        "outbound": "direct"
      },
      {
        "ip_cidr": ["224.0.0.0/3", "ff00::/8"],
        "outbound": "block"
      }
    ],
    "final": "direct"
  }
}
EOF
}

# 设置 systemd 服务
setup_service() {
  info "Setting up systemd service..."
  cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=Sing-box Proxy Service
After=network.target

[Service]
Type=simple
ExecStart=$WORK_DIR/sing-box run -c $WORK_DIR/config.json
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable sing-box
  systemctl start sing-box
  [ "$(systemctl is-active sing-box)" = "active" ] || error "Failed to start Sing-box service."
}

# 显示节点信息
show_info() {
  info "Sing-box setup completed successfully!"
  echo -e "\n========================================\n"
  info "VLESS (Reality) Connection Info:"
  echo "Address: $(curl -s ifconfig.me)"
  echo "Port: $VLESS_PORT"
  echo "UUID: $UUID"
  echo "Flow: xtls-rprx-vision"
  echo "TLS Server Name: $TLS_SERVER"
  echo "Public Key: $REALITY_PUBLIC"
  echo "Short ID: 12345678"
  echo -e "\nVLESS URL: vless://$UUID@$(curl -s ifconfig.me):$VLESS_PORT?security=reality&sni=$TLS_SERVER&fp=chrome&pbk=$REALITY_PUBLIC&sid=12345678&flow=xtls-rprx-vision#VLESS-Reality"

  echo -e "\n----------------------------------------\n"
  info "VMESS (WebSocket) Connection Info:"
  echo "Address: $VMESS_HOST"
  echo "Port: $VMESS_PORT"
  echo "UUID: $UUID"
  echo "AlterId: 0"
  echo "Transport: ws"
  echo "Path: /vmess"
  echo -e "\nVMESS URL: vmess://$(echo -n "{\"v\":\"2\",\"ps\":\"VMESS-WS\",\"add\":\"$VMESS_HOST\",\"port\":$VMESS_PORT,\"id\":\"$UUID\",\"aid\":0,\"net\":\"ws\",\"type\":\"none\",\"host\":\"$VMESS_HOST\",\"path\":\"/vmess\",\"tls\":\"\"}" | base64 -w 0)"

  echo -e "\n========================================\n"
  info "TUN Mode is enabled. Use the above URLs in a client that supports TUN mode (e.g., Sing-box client)."
  info "Configuration file: $WORK_DIR/config.json"
}

# 主函数
main() {
  check_root
  check_system
  check_arch
  install_dependencies
  download_sing_box
  input_ports
  input_uuid
  input_domains
  configure_tun
  generate_config
  setup_service
  show_info
}

# 清理临时文件
trap "rm -rf $TEMP_DIR >/dev/null 2>&1" EXIT

main
