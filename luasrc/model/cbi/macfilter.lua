-- luasrc/model/cbi/macfilter.lua
package.path = package.path .. ";/usr/lib/lua/?.lua;/usr/lib/lua/luci/?.lua"

local m, s, o
local nixio = require "nixio"
local sys = require "luci.sys"
local uci = require "luci.model.uci".cursor()

-- IPv4验证函数
local function validate_ipv4(ip)
    if not ip then return false end
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return false end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    return a < 256 and b < 256 and c < 256 and d < 256
end

-- MAC地址格式化
local function sanitize_mac(mac)
    mac = mac:upper()
        :gsub("O", "0")    -- 替换常见错误字符
        :gsub("Z", "2")
        :gsub("[:-]", "")  -- 移除分隔符
        :gsub("%s+", "")    -- 移除空格
    
    -- 验证并重新格式化MAC地址
    if #mac == 12 and not mac:match("[^0-9A-F]") then
        return mac:sub(1,2)..":"..mac:sub(3,4)..":"..mac:sub(5,6)..":"..
               mac:sub(7,8)..":"..mac:sub(9,10)..":"..mac:sub(11,12)
    end
    return nil
end

-- 获取静态绑定信息
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

-- 重构后的设备发现函数
local function get_connected_clients()
    local devices = {}
    
    -- 获取ARP表信息（实时在线状态）
    local arp_cmd = "ip -4 neigh show | awk '$1 ~ /^[0-9]{1,3}\\./{print $1,$5}' 2>/dev/null"
    local arp_scan = sys.exec(arp_cmd) or ""
    for ip, mac in arp_scan:gmatch("(%S+)%s+(%S+)") do
        local clean_mac = sanitize_mac(mac)
        if clean_mac and validate_ipv4(ip) then
            devices[clean_mac] = {
                ip = ip,
                type = "动态",
                active = true  -- ARP检测到的在线设备
            }
        end
    end

    -- 改进的DHCP租约解析
    local dhcp_leases = sys.exec("cat /tmp/dhcp.leases 2>/dev/null") or ""
    for line in dhcp_leases:gmatch("[^\r\n]+") do
        local parts = {}
        for word in line:gmatch("%S+") do
            parts[#parts + 1] = word
        end
        if #parts >= 3 then
            local ts, mac, ip = parts[1], parts[2], parts[3]
            local clean_mac = sanitize_mac(mac)
            if clean_mac and validate_ipv4(ip) then
                if not devices[clean_mac] then
                    devices[clean_mac] = {
                        ip = ip,
                        type = "DHCP",
                        active = os.time() - tonumber(ts) < 3600  -- 1小时内活跃
                    }
                else
                    -- 保留现有active状态，仅更新IP和类型
                    devices[clean_mac].ip = ip
                    devices[clean_mac].type = "DHCP"
                end
            end
        end
    end

    -- 合并静态设备信息（优先级最低）
    local static_devices = get_static_entries()
    for mac, ip in pairs(static_devices) do
        if devices[mac] then
            -- 保留现有状态，仅更新IP和类型
            devices[mac].ip = ip
            devices[mac].type = "静态"
        else
            devices[mac] = {
                ip = ip,
                type = "静态",
                active = false  -- 默认离线状态
            }
        end
    end

    -- 生成最终列表
    local sorted = {}
    for mac, data in pairs(devices) do
        sorted[#sorted+1] = {
            mac = mac,
            ip = data.ip,
            display = string.format("%s %s (%s) [%s]", 
                data.active and "●" or "○",  -- 在线状态指示
                mac,
                data.ip,
                data.type
            ),
            active = data.active
        }
    end

    -- 排序逻辑：在线设备优先，MAC地址升序
    table.sort(sorted, function(a, b)
        if a.active ~= b.active then
            return a.active  -- 在线设备排在前
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

-- 设备选择下拉列表
o = s:option(ListValue, "mac", translate("选择设备"))
o:value("", "-- 请选择设备 --")

local clients = get_connected_clients()
if #clients == 0 then
    o:value("", "-- 未检测到任何设备 --")
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
