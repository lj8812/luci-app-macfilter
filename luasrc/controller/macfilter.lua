module("luci.controller.webrestrict", package.seeall)

function index()
    entry({"admin", "services", "webrestrict"}, cbi("webrestrict"), _("访问限制"), 60)
end
