-- luasrc/model/cbi/macfilter.lua
package.path = package.path .. ";/usr/lib/lua/?.lua;/usr/lib/lua/luci/?.lua"

local m, s, o
local nixio = require "nixio"
local sys = require "luci.sys"
local uci = require "luci.model.uci".cursor()

-- 用户信息映射表（需手动维护）
local USER_MAPPING = {
    ["00:11:22:33:44:55"] = "我的手机",
    ["AA:BB:CC:DD:EE:FF"] = "办公电脑"
}

-- IPv4验证函数
local function validate_ipv4(ip)
    if not ip then return false end
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return false end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    return a < 256 and b < 256 and c < 256 and d < 256
end

-- MAC地址处理函数
local function format_mac_display(raw)
    local clean = raw:upper()
        :gsub("O", "0")
        :gsub("Z", "2")
        :gsub("[:-]", "")
        :gsub("%s+", "")
    
    if #clean == 12 then
        return clean:sub(1,2)..":"..clean:sub(3,4)..":"..
               clean:sub(5,6)..":"..clean:sub(7,8)..":"..
               clean:sub(9,10)..":"..clean:sub(11,12)
    end
    return nil
end

-- 增强版设备发现
local function get_network_devices()
    local devices = {}
    local hostnames = {}
    
    -- 获取静态主机名
    uci:foreach("dhcp", "host", function(s)
        if s.mac and s.ip and s.name then
            local mac = format_mac_display(s.mac)
            if mac then
                hostnames[mac] = s.name
            end
        end
    end)
    
    -- 读取DHCP租约
    local leases = {}
    if nixio.fs.access("/tmp/dhcp.leases") then
        for line in io.lines("/tmp/dhcp.leases") do
            local ts, raw_mac, ip_addr, name = line:match("^(%d+) (%S+) (%S+) (%S+)")
            if raw_mac and ip_addr and name and name ~= "*" then
                local mac = format_mac_display(raw_mac)
                if mac then
                    leases[mac] = name
                end
            end
        end
    end
    
    -- 扫描ARP设备
    local arp_scan = sys.exec([[
        ip -4 neigh show 2>/dev/null | awk '
            $NF == "REACHABLE" || $NF == "STALE" {
                split($5, mac, /@/);
                print $1, mac[1];
            }'
    ]])
    
    -- 处理在线设备
    for line in arp_scan:gmatch("[^\r\n]+") do
        local ip_addr, raw_mac = line:match("^(%S+)%s+(%S+)$")
        if ip_addr and raw_mac then
            local mac = format_mac_display(raw_mac)
            if mac and validate_ipv4(ip_addr) then
                devices[mac] = {
                    ip = ip_addr,
                    hostname = leases[mac] or hostnames[mac] or "",
                    static = false,
                    active = true
                }
            end
        end
    end
    
    -- 补充静态设备
    uci:foreach("dhcp", "host", function(s)
        if s.mac and s.ip then
            local mac = format_mac_display(s.mac)
            if mac and validate_ipv4(s.ip) and not devices[mac] then
                devices[mac] = {
                    ip = s.ip,
                    hostname = hostnames[mac] or "",
                    static = true,
                    active = false
                }
            end
        end
    end)
    
    -- 格式转换和排序
    local sorted = {}
    for mac, data in pairs(devices) do
        -- 修正显示格式（移除状态显示）
        local display_str
        local display_name = USER_MAPPING[mac] or data.hostname
        
        if display_name and display_name ~= "" then
            display_str = string.format(
                "%s | %s (%s) | %s",  -- 移除了状态字段
                mac,
                display_name:sub(1, 14),
                data.ip,
                data.static and "静态" or "动态"
            )
        else
            display_str = string.format(
                "%s | %s | %s",  -- 移除了状态字段
                mac,
                data.ip,
                data.static and "静态" or "动态"
            )
        end

        sorted[#sorted+1] = {
            mac = mac,
            display = display_str,
            active = data.active  -- 保留用于排序
        }
    end
    
    -- 保持在线设备优先排序
    table.sort(sorted, function(a, b)
        if a.active ~= b.active then
            return a.active
        end
        return a.mac < b.mac
    end)
    
    return sorted
end

-- 界面配置
m = Map("macfilter", translate("MAC地址过滤"), 
    translate("设备列表显示格式：MAC | 设备信息 (IP) | 类型"))

m.on_after_commit = function(self)
    os.execute("/etc/init.d/macfilter reload >/dev/null 2>&1")
end

-- 全局设置部分
s = m:section(NamedSection, "access_control", "feature", translate("全局设置"))
local mode = s:option(ListValue, "mode", translate("工作模式"))
mode:value("blacklist", translate("黑名单模式（禁止列表设备联网）"))
mode:value("whitelist", translate("白名单模式（仅允许列表设备联网）"))
mode.default = "blacklist"

-- 批量添加按钮
local btn = s:option(Button, "_addall", translate("批量操作"))
btn.inputtitle = translate("一键添加所有设备")
btn.inputstyle = "apply"

function btn.write(self, section)
    local clients = get_network_devices()
    local existing = {}
    
    uci:foreach("macfilter", "rule", function(s)
        if s.mac then existing[s.mac] = true end  -- 直接使用显示格式MAC
    end)
    
    local added = 0
    for _, client in ipairs(clients) do
        local display_mac = client.mac
        if display_mac and not existing[display_mac] then
            uci:set("macfilter", uci:add("macfilter", "rule"), "mac", display_mac)
            added = added + 1
        end
    end
    
    if added > 0 then
        uci:commit("macfilter")
        luci.http.header("Cache-Control", "no-cache")
        luci.http.redirect(luci.dispatcher.build_url("admin/services/macfilter"))
    end
end

-- 删除规则按钮（已恢复）
local del_btn = s:option(Button, "_delall", translate("删除规则"))
del_btn.inputtitle = translate("立即清空所有规则")
del_btn.inputstyle = "remove"

function del_btn.write()
    uci:delete_all("macfilter", "rule")
    uci:commit("macfilter")
    luci.http.redirect(luci.dispatcher.build_url("admin/services/macfilter"))
end

-- 过滤规则部分
s = m:section(TypedSection, "rule", translate("过滤规则"))
s.template = "cbi/tblsection"
s.addremove = true
s.anonymous = true

-- 设备选择下拉列表（修正显示格式）
local mac_list = s:option(ListValue, "mac", translate("选择设备"))
mac_list:value("", "-- 请选择设备 --")

local clients = get_network_devices()
if #clients == 0 then
    mac_list:value("", "-- 未检测到任何设备 --")
else
    for _, client in ipairs(clients) do
        mac_list:value(client.mac, client.display)
    end
end

function mac_list.validate(self, value)
    return format_mac_display(value) or nil
end

return m
