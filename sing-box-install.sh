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

  REGEX=("debian" "ubuntu" "centos|red hat|kernel|alma|rocky")
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

  reading "Enter VMESS
