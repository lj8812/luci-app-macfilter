include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-macfilter
PKG_VERSION:=3.2
PKG_RELEASE:=1

LUCI_TITLE:=MAC Address Filtering Plugin
LUCI_DEPENDS:=+luci-compat +kmod-ipt-filter  # ✅ 精简依赖
LUCI_PKGARCH:=all

include $(TOPDIR)/feeds/luci/luci.mk

define Package/$(PKG_NAME)/install
	# 安装LuCI组件（必须用TAB缩进）
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./luasrc/controller/macfilter.lua $(1)/usr/lib/lua/luci/controller/
	
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi
	$(INSTALL_DATA) ./luasrc/model/cbi/macfilter.lua $(1)/usr/lib/lua/luci/model/cbi/

	# 安装配置文件和初始化脚本
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./root/etc/config/macfilter $(1)/etc/config/
	
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./root/etc/init.d/macfilter $(1)/etc/init.d/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
