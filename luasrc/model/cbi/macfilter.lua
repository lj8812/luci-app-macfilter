local m, s, o
local uci = require "luci.model.uci".cursor()
local sys = require "luci.sys"

-- 动态获取在线设备的MAC地址列表（带IP地址）
local function get_connected_clients()
    local devices = {}
    
    -- 方法1：通过dhcp租约获取（兼容性更好）
    sys.net.arptable(function(entry)
        if entry["HW address"] and entry["IP address"] then
            devices[entry["HW address"]] = 
                string.format("%s (%s)", 
                entry["HW address"], 
                entry["IP address"])
        end
    end)

    -- 方法2：通过无线客户端列表补充（需要无线驱动支持）
    if luci.http.formvalue("cbid.macfilter.global.enabled") == "1" then
        sys.wifi.getiwinfo(function(dev, raw)
            if raw and raw.assoclist then
                for mac, client in pairs(raw.assoclist) do
                    if not devices[mac] then
                        devices[mac] = string.format("%s (%s)", mac, "无线客户端")
                    end
                end
            end
        end)
    end

    return devices
end

m = Map("macfilter", translate("MAC地址过滤"), 
    translate("实时阻断指定设备的网络访问（自动刷新在线设备列表）"))

m.apply_on_parse = true
function m.on_after_commit(self)
    os.execute("/etc/init.d/macfilter reload >/dev/null 2>&1")
end

-- 全局设置
s = m:section(NamedSection, "global", "global", translate("全局设置"))
s.anonymous = true

o = s:option(Flag, "enabled", translate("启用过滤"))
o.default = 0

o = s:option(ListValue, "mode", translate("过滤模式"))
o:value("blacklist", translate("黑名单（禁止列表中的设备）"))
o:value("whitelist", translate("白名单（仅允许列表中的设备）"))

-- MAC地址列表（带动态下拉）
s = m:section(TypedSection, "rule", translate("设备列表"), 
    translate("从下拉菜单中选择在线设备或手动输入MAC地址"))
s.template = "cbi/tblsection"
s.addremove = true
s.anonymous = true

o = s:option(Value, "mac", translate("选择设备"))
o.template = "cbi/network_netlist"
o.widget = "select"
o.nocreate = true
o.size = 15
o:value("", "-- 请选择 --")

-- 动态加载设备列表
local clients = get_connected_clients()
for mac, text in pairs(clients) do
    o:value(mac, text)
end

-- 手动输入校验
function o.validate(self, value, sid)
    if value ~= "" then
        if not value:match("^[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]$") then
            return nil, translate("MAC地址格式错误，示例：00:11:22:33:44:55")
        end
    end
    return value
end

return m
