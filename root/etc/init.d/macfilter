#!/bin/sh /etc/rc.common

START=99
USE_PROCD=1

validate_mac() {
    echo "$1" | grep -qiE '^([0-9A-F]{2}:){5}[0-9A-F]{2}$'
}

get_operation_mode() {
    local mode=$(uci -q get macfilter.access_control.mode 2>/dev/null)
    case "$mode" in
        whitelist) echo "whitelist" ;;
        blacklist) echo "blacklist" ;;
        *)         echo "blacklist" ;; # 默认模式
    esac
}

start_service() {
    reload_service
}

reload_service() {
    # 获取当前工作模式
    local mode=$(get_operation_mode)
    
    # 清理旧规则
    iptables -D FORWARD -j MAC_FILTER 2>/dev/null || true
    iptables -F MAC_FILTER 2>/dev/null || true
    iptables -X MAC_FILTER 2>/dev/null || true
    ipset destroy macfilter 2>/dev/null || true

    # 创建新规则体系
    ipset create macfilter hash:mac maxelem 1024
    iptables -N MAC_FILTER
    
    # 根据模式设置过滤逻辑
    case "$mode" in
        whitelist)
            # 白名单模式：仅允许列表中的设备
            iptables -A MAC_FILTER -m set ! --match-set macfilter src -j DROP
            logger -t macfilter "启动白名单模式，仅允许授权设备"
            ;;
        *)
            # 黑名单模式：默认阻止列表中的设备
            iptables -A MAC_FILTER -m set --match-set macfilter src -j DROP
            logger -t macfilter "启动黑名单模式，阻止列表设备"
            ;;
    esac

    # 插入到FORWARD链首确保优先处理
    iptables -I FORWARD 1 -j MAC_FILTER

    # 加载所有配置的MAC地址
    uci -q show macfilter | awk -F= '/\.mac=/ {
        gsub(/[^0-9A-Fa-f:]/, "", $2)
        print $2
    }' | while read raw_mac; do
        # MAC地址标准化处理
        std_mac=$(echo "$raw_mac" | tr 'a-f' 'A-F' | tr '-' ':')
        
        if validate_mac "$std_mac"; then
            ipset add macfilter "$std_mac"
            logger -t macfilter "已加载MAC地址：$std_mac（模式：$mode）"
        else
            logger -t macfilter "忽略无效MAC地址：$raw_mac"
        fi
    done

    # 持久化防火墙规则
    ipset save macfilter > /etc/firewall.macfilter 2>/dev/null
}

stop_service() {
    # 完全清除规则链
    iptables -D FORWARD -j MAC_FILTER 2>/dev/null || true
    iptables -F MAC_FILTER 2>/dev/null || true
    iptables -X MAC_FILTER 2>/dev/null || true
    ipset destroy macfilter 2>/dev/null || true
    logger -t macfilter "服务已停止，所有规则已清除"
}
