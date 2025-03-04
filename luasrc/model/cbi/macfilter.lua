-- luasrc/model/cbi/macfilter.lua
package.path = package.path .. ";/usr/lib/lua/?.lua;/usr/lib/lua/luci/?.lua"

local m, s, o
local nixio = require "nixio"
local sys = require "luci.sys"
local uci = require "luci.model.uci".cursor()

-- IPv4验证函数（保持不变）
local function validate_ipv4(ip)
    if not ip then return false end
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return false end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    return a < 256 and b < 256 and c < 256 and d < 256
end

-- MAC地址格式化（保持不变）
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

-- 新增：获取静态绑定信息
local function get_static_entries()
    local static_devices = {}
    
    -- 解析/etc/ethers文件
    local ethers = io.open("/etc/ethers", "r")
    if ethers then
        for line in ethers:lines() do
            local mac, ip = line:match("^%s*([0-9A-Fa-f:-]+)%s+(%S+)")
            if mac and ip then
                local clean_mac = sanitize_mac(mac)
                if clean_mac and validate_ipv4(ip) then
                    static_devices[clean_mac] = ip
                end
            end
        end
        ethers:close()
    end

    -- 解析静态DHCP租约
    uci:foreach("dhcp", "host", function(s)
        if s.mac and s.ip then
            local clean_mac = sanitize_mac(s.mac)
            if clean_mac and validate_ipv4(s.ip) then
                static_devices[clean_mac] = s.ip
            end
        end
    end)

    return static_devices
end

-- 重构设备发现函数
local function get_connected_clients()
    local devices = {}
    
    -- 获取动态信息（ARP+DHCP）
    local arp_cmd = "ip -4 neigh show | awk '$1 ~ /^[0-9]{1,3}\\./{print $1,$5}' 2>/dev/null"
    local arp_scan = sys.exec(arp_cmd) or ""
    for ip, mac in arp_scan:gmatch("(%S+)%s+(%S+)") do
        local clean_mac = sanitize_mac(mac)
        if clean_mac and validate_ipv4(ip) then
            devices[clean_mac] = {
                ip = ip,
                type = "动态",
                active = true
            }
        end
    end

    -- 合并DHCP租约（包含过期记录）
    local dhcp_leases = sys.exec("cat /tmp/dhcp.leases 2>/dev/null") or ""
    for ts, mac, ip in dhcp_leases:gmatch("(%d+)%s+(%S+)%s+(%S+)") do
        local clean_mac = sanitize_mac(mac)
        if clean_mac and validate_ipv4(ip) then
            devices[clean_mac] = {
                ip = ip,
                type = "DHCP",
                active = os.time() - tonumber(ts) < 3600 -- 1小时内活跃
            }
        end
    end

    -- 合并静态绑定信息
    local static_devices = get_static_entries()
    for mac, ip in pairs(static_devices) do
        devices[mac] = {
            ip = ip,
            type = "静态",
            active = devices[mac] and devices[mac].active or false
        }
    end

    -- 生成最终列表
    local sorted = {}
    for mac, data in pairs(devices) do
        sorted[#sorted+1] = {
            mac = mac,
            ip = data.ip,
            display = string.format("%s %s (%s)", 
                data.active and "●" or "○",  -- 在线状态指示
                mac, 
                data.ip
            ),
            active = data.active
        }
    end

    -- 排序：在线设备优先，按MAC排序
    table.sort(sorted, function(a, b)
        if a.active ~= b.active then
            return a.active
        end
        return a.mac < b.mac
    end)

    return sorted
end

-- 界面初始化
m = Map("macfilter", translate("MAC地址过滤"), 
    translate("支持动态/静态设备显示（●表示在线设备）"))

m.on_after_commit = function(self)
    os.execute("/etc/init.d/macfilter reload >/dev/null 2>&1")
end

s = m:section(TypedSection, "rule", translate("设备列表"))
s.template = "cbi/tblsection"
s.addremove = true
s.anonymous = true

-- 优化后的下拉列表
o = s:option(ListValue, "mac", translate("选择设备"))
o:value("", "-- 请选择设备 --")

local clients = get_connected_clients()
if #clients == 0 then
    o:value("", "-- 未检测到任何设备 --")
else
    for _, client in ipairs(clients) do
        local desc = client.display
        if client.type == "静态" then
            desc = desc .. " [静态绑定]"
        end
        o:value(client.mac, desc)
    end
end

-- 输入验证（保持不变）
function o.validate(self, value)
    if value ~= "" and not sanitize_mac(value) then
        return nil, translate("MAC地址格式错误（正确示例：00:11:22:33:44:55）")
    end
    return value
end

return m
