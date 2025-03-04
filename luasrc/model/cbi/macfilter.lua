local uci = luci.model.uci.cursor()
local sys = require "luci.sys"

m = Map("webrestrict", translate("访问限制"),
    translate("基于MAC地址的实时网络控制（使用iptables/ipset）"))

m.on_after_commit = function(self)
    os.execute("/usr/lib/webrestrict/apply_rules.sh >/dev/null 2>&1")
end

s = m:section(TypedSection, "basic", translate("全局设置"))
s.anonymous = true

o = s:option(Flag, "enabled", translate("启用控制"))
o.rmempty = false

mode = s:option(ListValue, "mode", translate("控制模式"))
mode:value("blacklist", translate("黑名单模式（禁止列表设备）"))
mode:value("whitelist", translate("白名单模式（仅允许列表设备）"))

clients = m:section(TypedSection, "client", translate("受控设备"), 
    translate("MAC地址格式：00:11:22:33:44:55"))
clients.template = "cbi/tblsection"
clients.addremove = true

mac = clients:option(Value, "mac", translate("MAC地址"))
mac.datatype = "macaddr"
mac.rmempty = false

sys.net.mac_hints(function(mac, name)
    mac:value(mac, "%s (%s)" %{mac, name or "未知设备"})
end)

return m
