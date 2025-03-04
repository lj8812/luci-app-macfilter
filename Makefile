include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-macfilter
PKG_VERSION:=2.0
PKG_RELEASE:=1

LUCI_TITLE:=MAC Address Filtering Plugin
LUCI_DEPENDS:=+luci-base +luci-compat +luci-lib-ip +luci-lib-nixio +iptables +ipset +kmod-ipt-ipset +dnsmasq  +kmod-ipt-conntrack
LUCI_PKGARCH:=all

include $(TOPDIR)/feeds/luci/luci.mk

define Package/$(PKG_NAME)/install
    # 安装LuCI组件
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

# 国际化支持
PO_CONFIG:=../../build/i18n-config
PO_LANGUAGES:=zh_Hans

$(eval $(call BuildPackage,$(PKG_NAME)))
