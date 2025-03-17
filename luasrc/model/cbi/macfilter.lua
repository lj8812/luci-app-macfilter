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

-- MAC地址格式化
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

-- 获取用户显示信息
local function get_display_info(mac, ip, hostname, static_name)
    -- 显示优先级：用户映射 > DHCP主机名 > 静态名称 > IP
    return USER_MAPPING[mac] 
        or hostname 
        or static_name 
        or ip
end

-- 获取静态绑定信息
local function get_static_entries()
    local static_devices = {}
    
    -- 解析/etc/ethers
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
            if clean_mac then
                static_devices[clean_mac] = {
                    ip = s.ip,
                    name = s.name  -- 获取静态配置名称
                }
            end
        end
    end)

    return static_devices
end

-- 设备发现函数
local function get_connected_clients()
    local devices = {}
    
    -- 解析ARP表（标记为动态）
    local arp_cmd = "ip -4 neigh show | awk '$1 ~ /^[0-9]{1,3}\\./{print $1,$5}'"
    local arp_scan = sys.exec(arp_cmd) or ""
    for ip, mac in arp_scan:gmatch("(%S+)%s+(%S+)") do
        local clean_mac = sanitize_mac(mac)
        if clean_mac and validate_ipv4(ip) then
            devices[clean_mac] = {
                ip = ip,
                type = "动态",  -- 直接标记为动态
                active = true
            }
        end
    end

    -- 解析DHCP租约（包含主机名）
    local dhcp_leases = sys.exec("cat /tmp/dhcp.leases 2>/dev/null") or ""
    for line in dhcp_leases:gmatch("[^\r\n]+") do
        local parts = {}
        for word in line:gmatch("%S+") do
            parts[#parts + 1] = word
        end
        if #parts >= 5 then
            local ts, mac, ip, hostname = parts[1], parts[2], parts[3], parts[4]
            local clean_mac = sanitize_mac(mac)
            if clean_mac and validate_ipv4(ip) then
                devices[clean_mac] = {
                    ip = ip,
                    type = "动态",  -- DHCP设备标记为动态
                    active = os.time() - tonumber(ts) < 3600,
                    hostname = hostname ~= "*" and hostname or nil
                }
            end
        end
    end

    -- 合并静态设备信息
    local static_devices = get_static_entries()
    for mac, info in pairs(static_devices) do
        if type(info) == "table" then  -- 静态DHCP配置
            if devices[mac] then
                devices[mac].type = "静态"
                devices[mac].static_name = info.name
            else
                devices[mac] = {
                    ip = info.ip,
                    type = "静态",
                    active = false,
                    static_name = info.name
                }
            end
        else  -- /etc/ethers配置
            if devices[mac] then
                devices[mac].type = "静态"
            else
                devices[mac] = {
                    ip = info,
                    type = "静态",
                    active = false
                }
            end
        end
    end

    -- 生成显示列表（修改后的格式）
    local sorted = {}
    for mac, data in pairs(devices) do
        -- 获取显示名称（优先用户映射名称）
        local display_name = get_display_info(mac, data.ip, data.hostname, data.static_name)
        
        -- 构建显示字符串
        local display_str
        if data.hostname or data.static_name then
            display_str = string.format(
                "%s | %s (%s) | %s",
                mac,
                display_name:sub(1, 14),  -- 限制名称长度
                data.ip,
                data.type
            )
        else
            display_str = string.format(
                "%s | %s | %s",
                mac,
                data.ip,
                data.type
            )
        end

        sorted[#sorted+1] = {
            mac = mac,
            display = display_str,
            active = data.active
        }
    end

    -- 排序逻辑（在线设备优先，MAC地址排序）
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
    translate("设备列表显示格式：MAC | 设备信息 (IP) | 类型 或 MAC | IP | 类型"))

m.on_after_commit = function(self)
    os.execute("/etc/init.d/macfilter reload >/dev/null 2>&1")
end

-- 全局设置部分
s = m:section(NamedSection, "access_control", "feature", 
    translate("全局设置"))  -- 移除第二个描述参数
local mode = s:option(ListValue, "mode", translate("工作模式"))
mode:value("blacklist", translate("黑名单模式（禁止列表设备联网）"))
mode:value("whitelist", translate("白名单模式（仅允许列表设备联网）"))
mode.default = "blacklist"

-- 添加批量操作按钮（在mode之后）
local btn = s:option(Button, "_addall", translate("添加规则"))
btn.inputtitle = translate("一键添加所有设备")
btn.inputstyle = "apply"
btn.disabled = false

function btn.write(self, section)
    local clients = get_connected_clients()
    local existing = {}
    
    -- 收集已有规则
    uci:foreach("macfilter", "rule", function(s)
        if s.mac then
            existing[sanitize_mac(s.mac) or ""] = true
        end
    end)
    
    -- 批量添加新设备
    local added = 0
    for _, client in ipairs(clients) do
        local clean_mac = sanitize_mac(client.mac)
        if clean_mac and not existing[clean_mac] then
            local rule = uci:add("macfilter", "rule")
            uci:set("macfilter", rule, "mac", clean_mac)
            added = added + 1
        end
    end
    
    if added > 0 then
        uci:commit("macfilter")
        luci.http.redirect(luci.dispatcher.build_url("admin/services/macfilter"))
    else
        self.disabled = true
    end
end

-- 在全局设置部分添加删除按钮（位于工作模式之后）
local del_btn = s:option(Button, "_delall", translate("删除规则"))
del_btn.inputtitle = translate("立即清空所有规则")
del_btn.inputstyle = "remove"

function del_btn.write()
    -- 清空所有rule类型的section
    uci:delete_all("macfilter", "rule")
    uci:commit("macfilter")
    luci.http.redirect(luci.dispatcher.build_url("admin/services/macfilter"))
end

-- 过滤规则部分
s = m:section(TypedSection, "rule", translate("过滤规则"))
s.template = "cbi/tblsection"
s.addremove = true
s.anonymous = true

-- 设备选择下拉列表（在按钮之后定义）
local mac_list = s:option(ListValue, "mac", translate("选择设备"))
mac_list:value("", "-- 请选择设备 --")

local clients = get_connected_clients()
if #clients == 0 then
    mac_list:value("", "-- 未检测到任何设备 --")
else
    for _, client in ipairs(clients) do
        mac_list:value(client.mac, client.display)
    end
end

mac_list.description = translate("已连接设备自动刷新，点击上方按钮可批量添加所有设备")

-- 输入验证
function mac_list.validate(self, value)
    if value ~= "" and not sanitize_mac(value) then
        return nil, translate("MAC地址格式错误（正确示例：00:11:22:33:44:55）")
    end
    return value
end

return m
