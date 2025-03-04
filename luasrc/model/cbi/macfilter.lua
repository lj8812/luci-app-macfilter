-- luasrc/model/cbi/macfilter.lua
package.path = package.path .. ";/usr/lib/lua/?.lua;/usr/lib/lua/luci/?.lua"

local m, s, o
local nixio = require "nixio"
local sys = require "luci.sys"
local uci = require "luci.model.uci".cursor()

-- 修正后的IPv4验证函数
local function validate_ipv4(ip)
    if not ip then return false end
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return false end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    return a < 256 and b < 256 and c < 256 and d < 256
end

-- MAC地址格式化（保留原始代码）
local function sanitize_mac(mac)
    mac = mac:upper()
        :gsub("O", "0")
        :gsub("Z", "2")
        :gsub("[:-]", "")
        :gsub("%s+", "")
    
    if #mac == 12 and not mac:match("[^0-9A-F]") then
        return mac:sub(1,2)..":"..mac:sub(3,4)..":"..mac:sub(5,6)..":"..
               mac:sub(7,8)..":"..mac:sub(9,10)..":"..mac:sub(11,12)
    end
    return nil
end

-- 设备发现函数（关键修复）
local function get_connected_clients()
    local devices = {}
    
    -- 修正ARP解析
    local arp_cmd = "ip -4 neigh show nud reachable | awk '$1 ~ /^[0-9]{1,3}\\./{print $1,$5}' 2>/dev/null"
    local arp_scan = sys.exec(arp_cmd) or ""
    for ip, mac in arp_scan:gmatch("(%S+)%s+(%S+)") do
        local clean_mac = sanitize_mac(mac)
        if clean_mac and validate_ipv4(ip) then
            devices[clean_mac] = ip
        end
    end

    -- 修正DHCP解析
    local dhcp_leases = sys.exec("cat /tmp/dhcp.leases 2>/dev/null") or ""
    for ts, mac, ip in dhcp_leases:gmatch("(%d+)%s+(%S+)%s+(%S+)") do
        local clean_mac = sanitize_mac(mac)
        if clean_mac and validate_ipv4(ip) then
            devices[clean_mac] = ip  -- 最后出现的记录优先
        end
    end

    -- 生成有序列表
    local sorted = {}
    for mac, ip in pairs(devices) do
        sorted[#sorted+1] = {
            mac = mac,
            ip = ip,
            display = string.format("%s (%s)", mac, ip)
        }
    end
    table.sort(sorted, function(a, b) return a.mac < b.mac end)
    
    return sorted
end

-- 界面初始化保持不变
m = Map("macfilter", translate("MAC地址过滤"), 
    translate("实时阻断指定设备的网络访问（严格格式验证）"))

m.on_after_commit = function(self)
    os.execute("/etc/init.d/macfilter reload >/dev/null 2>&1")
end

s = m:section(TypedSection, "rule", translate("设备列表"))
s.template = "cbi/tblsection"
s.addremove = true
s.anonymous = true

o = s:option(ListValue, "mac", translate("选择设备"))
o:value("", "-- 请选择在线设备 --")

local clients = get_connected_clients()
if #clients == 0 then
    o:value("", "-- 未检测到在线设备 --")
else
    for _, client in ipairs(clients) do
        o:value(client.mac, client.display)
    end
end

-- 输入验证
function o.validate(self, value)
    if value ~= "" and not sanitize_mac(value) then
        return nil, translate("MAC地址格式错误（正确示例：00:11:22:33:44:55）")
    end
    return value
end

return m
