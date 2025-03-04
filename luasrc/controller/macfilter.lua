module("luci.controller.macfilter", package.seeall)

function index()
    -- 在"服务"菜单下添加条目
    entry({"admin", "services", "macfilter"}, cbi("macfilter"), _("MAC过滤"), 30).dependent = false
end
