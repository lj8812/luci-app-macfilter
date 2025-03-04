-- luasrc/model/cbi/macfilter.lua
local m, s, o
local sys = require "luci.sys"
local uci = require "luci.model.uci".cursor()

-- 增强版设备发现（仅IPv4）
local function get_connected_clients()
    local devices = {}
    
    -- 核心方法：ARP表扫描（仅IPv4）
    local arp_cmd = "ip neigh show 2>/dev/null | awk '$1 ~ /^[0-9]{1,3}\\./{print $1,$5}'"
    local arp_scan = sys.exec(arp_cmd)
    for ip, mac in arp_scan:gmatch("(%S+)%s+(%S+)") do
        if mac ~= "00:00:00:00:00:00" and ip:match("^%d+%.%d+%.%d+%.%d+$") then
            mac = mac:upper():gsub("-", ":")
            devices[mac] = string.format("%s (%s)", mac, ip)
        end
    end

    -- 补充DHCP租约（仅IPv4）
    local dhcp_leases = sys.exec("cat /tmp/dhcp.leases 2>/dev/null")
    for ts, mac, ip, name in dhcp_leases:gmatch("(%d+) (%S+) (%S+) (%S+)\n?") do
        if ip:match("^%d+%.%d+%.%d+%.%d+$") then
            local norm_mac = mac:upper():gsub("-", ":")
            if not devices[norm_mac] then
                devices[norm_mac] = string.format("%s (%s)", norm_mac, ip)
            end
        end
    end

    return devices
end

m = Map("macfilter", translate("MAC地址过滤"), 
    translate("实时阻断指定设备的网络访问（仅显示IPv4设备）"))

m.apply_on_parse = true
function m.on_after_commit(self)
    os.execute("/etc/init.d/macfilter reload >/dev/null 2>&1")
end

s = m:section(TypedSection, "rule", translate("设备列表"))
s.template = "cbi/tblsection"
s.addremove = true
s.anonymous = true

o = s:option(ListValue, "mac", translate("选择设备"))
o:value("", "-- 请选择在线设备 --")

local clients = get_connected_clients()
for mac, desc in pairs(clients) do
    o:value(mac, desc)
end

o.widget = "select"
o:depends({mode = "blacklist"})

function o.validate(self, value)
    if value ~= "" then
        if not value:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$") then
            return nil, translate("MAC地址格式错误")
        end
    end
    return value
end

return m
