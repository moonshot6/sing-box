#!/bin/bash

# Author: moonshot6
# GitHub: https://github.com/moonshot6/sing-box
# License: GPL-3.0

# Bash fonts colors
red='\e[31m'
yellow='\e[33m'
gray='\e[90m'
green='\e[92m'
blue='\e[94m'
magenta='\e[95m'
cyan='\e[96m'
none='\e[0m'
_red() { echo -e ${red}$@${none}; }
_blue() { echo -e ${blue}$@${none}; }
_cyan() { echo -e ${cyan}$@${none}; }
_green() { echo -e ${green}$@${none}; }
_yellow() { echo -e ${yellow}$@${none}; }
_magenta() { echo -e ${magenta}$@${none}; }
_red_bg() { echo -e "\e[41m$@${none}"; }

is_err=$(_red_bg 错误!)
is_warn=$(_red_bg 警告!)

err() {
    echo -e "\n$is_err $@\n" && exit 1
}

warn() {
    echo -e "\n$is_warn $@\n"
}

# Root check
[[ $EUID != 0 ]] && err "当前非 ${yellow}ROOT用户.${none}"

# Detect package manager
if type -P apt-get &>/dev/null; then
    cmd=apt-get
elif type -P yum &>/dev/null; then
    cmd=yum
elif type -P dnf &>/dev/null; then
    cmd=dnf
elif type -P pacman &>/dev/null; then
    cmd=pacman
elif type -P apk &>/dev/null; then
    cmd=apk
else
    err "此脚本仅支持 Ubuntu、Debian、CentOS、Fedora、Arch Linux 或 Alpine。"
fi

# Systemd check
[[ ! $(type -P systemctl) ]] && {
    err "此系统缺少 ${yellow}(systemctl)${none}, 请尝试执行:${yellow} ${cmd} update -y;${cmd} install systemd -y ${none}来修复此错误."
}

# Wget check
is_wget=$(type -P wget)
[[ ! $is_wget ]] && err "此系统缺少 ${yellow}(wget)${none}, 请尝试执行:${yellow} ${cmd} update -y;${cmd} install wget -y ${none}来修复此错误."

# Architecture check
case $(uname -m) in
amd64 | x86_64)
    is_arch=amd64
    ;;
*aarch64* | *armv8*)
    is_arch=arm64
    ;;
*)
    err "此脚本仅支持 64 位系统..."
    ;;
esac

# Variables
is_core=sing-box
is_core_name=sing-box
is_core_dir=/etc/$is_core
is_core_bin=$is_core_dir/bin/$is_core
is_core_repo=SagerNet/$is_core
is_conf_dir=$is_core_dir/conf
is_log_dir=/var/log/$is_core
is_sh_bin=/usr/local/bin/$is_core
is_sh_dir=$is_core_dir/sh
is_pkg="wget tar jq"
is_config_json=$is_core_dir/config.json
is_subscribe_dir=$is_core_dir/subscribe
tmp_var_lists=(
    tmpcore
    is_core_ok
)

# Temporary directory
tmpdir=$(mktemp -u)
[[ ! $tmpdir ]] && {
    tmpdir=/tmp/tmp-$RANDOM
}

# Set up variables
for i in ${tmp_var_lists[*]}; do
    export $i=$tmpdir/$i
done

# Wget with proxy support
_wget() {
    [[ $proxy ]] && export https_proxy=$proxy
    wget --no-check-certificate $*
}

# Print message
msg() {
    case $1 in
    warn)
        local color=$yellow
        ;;
    err)
        local color=$red
        ;;
    ok)
        local color=$green
        ;;
    esac

    echo -e "${color}$(date +'%T')${none}) ${2}"
}

# Show help message
show_help() {
    echo -e "Usage: $0 [-f xxx | -p xxx | -v xxx | -h]"
    echo -e "  -f, --core-file <path>          自定义 $is_core_name 文件路径, e.g., -f /root/$is_core-linux-amd64.tar.gz"
    echo -e "  -p, --proxy <addr>              使用代理下载, e.g., -p http://127.0.0.1:2333 or -p socks5://127.0.0.1:2333"
    echo -e "  -v, --core-version <ver>        自定义 $is_core_name 版本, e.g., -v v1.8.13"
    echo -e "  -h, --help                      显示此帮助界面\n"

    exit 0
}

# Install dependent packages
install_pkg() {
    cmd_not_found=
    for i in $*; do
        [[ ! $(type -P $i) ]] && cmd_not_found="$cmd_not_found,$i"
    done
    if [[ $cmd_not_found ]]; then
        pkg=$(echo $cmd_not_found | sed 's/,/ /g')
        msg warn "安装依赖包 >${pkg}"
        if [[ $cmd == "apt-get" ]]; then
            $cmd update -y && $cmd install -y $pkg
        elif [[ $cmd == "yum" ]]; then
            $cmd install epel-release -y && $cmd install -y $pkg
        elif [[ $cmd == "dnf" ]]; then
            $cmd install -y $pkg
        elif [[ $cmd == "pacman" ]]; then
            $cmd -Syu --noconfirm $pkg
        elif [[ $cmd == "apk" ]]; then
            $cmd add $pkg
        fi
        [[ $? != 0 ]] && {
            msg err "安装依赖包失败"
            msg err "请尝试手动安装依赖包: $cmd update -y; $cmd install -y $pkg"
            exit 1
        }
    fi
}

# Download file with SHA256 verification
download() {
    case $1 in
    core)
        [[ ! $is_core_ver ]] && is_core_ver=$(_wget -qO- "https://api.github.com/repos/${is_core_repo}/releases/latest?v=$RANDOM" | grep tag_name | egrep -o 'v([0-9.]+)')
        [[ $is_core_ver ]] && {
            link="https://github.com/${is_core_repo}/releases/download/${is_core_ver}/${is_core}-${is_core_ver:1}-linux-${is_arch}.tar.gz"
            expected_sha256=$(_wget -qO- "https://github.com/${is_core_repo}/releases/download/${is_core_ver}/sha256sums.txt" | grep "${is_core}-${is_core_ver:1}-linux-${is_arch}.tar.gz" | awk '{print $1}')
        }
        name=$is_core_name
        tmpfile=$tmpcore
        is_ok=$is_core_ok
        ;;
    esac

    [[ $link ]] && {
        # Check if expected_sha256 is empty
        if [[ -z $expected_sha256 ]]; then
            msg err "无法获取 ${name} 的 SHA256 校验值，请检查网络或 GitHub 仓库。"
            exit 1
        fi

        msg warn "下载 ${name} > ${link}"
        for i in {1..3}; do
            if _wget -t 3 -q -c $link -O $tmpfile; then
                computed_sha256=$(sha256sum $tmpfile | awk '{print $1}')
                [[ "$computed_sha256" != "$expected_sha256" ]] && {
                    msg err "${name} 文件校验失败！"
                    msg err "预期 SHA256: $expected_sha256"
                    msg err "实际 SHA256: $computed_sha256"
                    exit 1
                }
                mv -f $tmpfile $is_ok
                break
            fi
            [[ $i -eq 3 ]] && {
                msg err "下载 ${name} 失败，请检查网络或使用代理（--proxy）。"
                exit 1
            }
            sleep 2
        done
    }
}

# Get server IP (optional)
get_ip() {
    read -p "是否获取服务器公网 IP？(y/n, 默认 n): " choice
    [[ "$choice" != "y" ]] && return
    export "$(_wget -4 -qO- https://one.one.one.one/cdn-cgi/trace | grep ip=)" &>/dev/null
    [[ -z $ip ]] && export "$(_wget -6 -qO- https://one.one.one.one/cdn-cgi/trace | grep ip=)" &>/dev/null
    [[ -z $ip ]] && msg warn "获取服务器 IP 失败。"
}

# Check TUN support
check_tun() {
    if [[ ! -e /dev/net/tun ]]; then
        msg warn "系统不支持 TUN 设备，TUN 模式不可用。"
        msg warn "请联系 VPS 厂商开启 TUN 支持，或更换支持 TUN 的 VPS。"
        return 1
    fi
    return 0
}

# Generate UUID
generate_uuid() {
    uuid=$(cat /proc/sys/kernel/random/uuid)
    echo $uuid
}

# Generate key pair for reality
generate_keypair() {
    keypair=$($is_core_bin generate reality-keypair)
    private_key=$(echo "$keypair" | grep "PrivateKey" | awk '{print $2}')
    public_key=$(echo "$keypair" | grep "PublicKey" | awk '{print $2}')
}

# Create systemd service
create_systemd_service() {
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=Sing-box Service
After=network.target

[Service]
Type=simple
ExecStart=$is_core_bin run -c $is_config_json
Restart=on-failure
RestartSec=5s
StandardOutput=append:$is_log_dir/sing-box.log
StandardError=append:$is_log_dir/sing-box.log
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
}

# Create default config with reality and TUN
create_default_config() {
    uuid=$(generate_uuid)
    generate_keypair

    cat > $is_config_json << EOF
{
    "log": {
        "level": "info",
        "timestamp": true
    },
    "inbounds": [
        {
            "type": "vless",
            "tag": "vless-reality",
            "listen": "::",
            "listen_port": 443,
            "users": [
                {
                    "uuid": "$uuid",
                    "flow": "xtls-rprx-vision"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "www.microsoft.com",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "www.microsoft.com",
                        "server_port": 443
                    },
                    "private_key": "$private_key",
                    "public_key": "$public_key",
                    "short_id": ["12345678"]
                }
            }
        },
        {
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "tun0",
            "mtu": 1500,
            "address": [
                "172.19.0.1/30",
                "fdfe:dcba:9876:5432::1/126"
            ],
            "auto_route": true,
            "strict_route": true,
            "stack": "system",
            "endpoint_independent_nat": false,
            "sniff": true,
            "sniff_override_destination": true
        }
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        }
    ]
}
EOF
}

# Create client config with TUN
create_client_config() {
    mkdir -p $is_subscribe_dir
    cat > $is_subscribe_dir/sing-box-pc.json << EOF
{
    "log": {
        "level": "info",
        "timestamp": true
    },
    "inbounds": [
        {
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "tun0",
            "mtu": 1500,
            "address": [
                "172.19.0.1/30",
                "fdfe:dcba:9876:5432::1/126"
            ],
            "auto_route": true,
            "strict_route": true,
            "stack": "system",
            "endpoint_independent_nat": false,
            "sniff": true,
            "sniff_override_destination": true
        }
    ],
    "outbounds": [
        {
            "type": "vless",
            "tag": "vless-out",
            "server": "$ip",
            "server_port": 443,
            "uuid": "$uuid",
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": true,
                "server_name": "www.microsoft.com",
                "reality": {
                    "enabled": true,
                    "public_key": "$public_key",
                    "short_id": "12345678"
                }
            }
        }
    ],
    "route": {
        "rules": [
            {
                "inbound": "tun-in",
                "outbound": "vless-out"
            }
        ]
    }
}
EOF
    cat > $is_subscribe_dir/sing-box-phone.json << EOF
{
    "log": {
        "level": "info",
        "timestamp": true
    },
    "inbounds": [
        {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 1080
        }
    ],
    "outbounds": [
        {
            "type": "vless",
            "tag": "vless-out",
            "server": "$ip",
            "server_port": 443,
            "uuid": "$uuid",
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": true,
                "server_name": "www.microsoft.com",
                "reality": {
                    "enabled": true,
                    "public_key": "$public_key",
                    "short_id": "12345678"
                }
            }
        }
    ],
    "route": {
        "rules": [
            {
                "inbound": "mixed-in",
                "outbound": "vless-out"
            }
        ]
    }
}
EOF
}

# Create management script
create_management_script() {
    cat > $is_sh_dir/sing-box.sh << 'EOF'
#!/bin/bash

# Management script for Sing-box

red='\e[31m'
yellow='\e[33m'
green='\e[92m'
none='\e[0m'
_red() { echo -e ${red}$@${none}; }
_yellow() { echo -e ${yellow}$@${none}; }
_green() { echo -e ${green}$@${none}; }

err() {
    echo -e "\n$(_red 错误!) $@\n" && exit 1
}

is_core_dir=/etc/sing-box
is_config_json=$is_core_dir/config.json
is_conf_dir=$is_core_dir/conf
is_subscribe_dir=$is_core_dir/subscribe

# Generate UUID
generate_uuid() {
    uuid=$(cat /proc/sys/kernel/random/uuid)
    echo $uuid
}

# Generate key pair for reality
generate_keypair() {
    keypair=$(/etc/sing-box/bin/sing-box generate reality-keypair)
    private_key=$(echo "$keypair" | grep "PrivateKey" | awk '{print $2}')
    public_key=$(echo "$keypair" | grep "PublicKey" | awk '{print $2}')
}

# Enable BBR
enable_bbr() {
    # Check kernel version (BBR requires 4.9 or higher)
    kernel_version=$(uname -r | awk -F. '{print $1"."$2}')
    kernel_major=$(echo $kernel_version | awk -F. '{print $1}')
    kernel_minor=$(echo $kernel_version | awk -F. '{print $2}')
    if [[ $kernel_major -lt 4 || ($kernel_major -eq 4 && $kernel_minor -lt 9) ]]; then
        _red "当前内核版本 ($kernel_version) 不支持 BBR，需要 4.9 或更高版本。"
        return 1
    fi

    # Check if BBR is already enabled
    current_congestion=$(sysctl -n net.ipv4.tcp_congestion_control)
    if [[ "$current_congestion" == "bbr" ]]; then
        _green "BBR 已启用，无需重复操作。"
        return 0
    fi

    # Load BBR module
    modprobe tcp_bbr
    if ! lsmod | grep -q tcp_bbr; then
        _red "无法加载 tcp_bbr 模块，BBR 可能不被支持。"
        return 1
    fi

    # Set sysctl parameters
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p

    # Verify
    if [[ $(sysctl -n net.ipv4.tcp_congestion_control) != "bbr" ]]; then
        _red "BBR 启用失败，请检查系统设置。"
        return 1
    fi

    _green "BBR 已成功启用！"
}

# Add protocol
add_protocol() {
    echo "支持的协议："
    protocols=(
        "Hysteria2"
        "VMess-WS"
        "VMess-TCP"
        "VMess-HTTP"
        "VMess-QUIC"
        "VLESS-WS-TLS"
        "VLESS-H2-TLS"
        "Trojan-H2-TLS"
        "Trojan-WS-TLS"
        "VMess-HTTPUpgrade-TLS"
        "VLESS-HTTPUpgrade-TLS"
        "VLESS-REALITY"
        "VLESS-HTTP2-REALITY"
        "退出"
    )
    select protocol in "${protocols[@]}"; do
        case $protocol in
            "Hysteria2")
                uuid=$(generate_uuid)
                port=8443
                cat >> $is_config_json << EOT
,
        {
            "type": "hysteria2",
            "tag": "hysteria2-in",
            "listen": "::",
            "listen_port": $port,
            "users": [
                {
                    "password": "$uuid"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "www.microsoft.com",
                "certificate_path": "/etc/sing-box/cert.pem",
                "key_path": "/etc/sing-box/key.pem"
            }
        }
EOT
                _green "已
