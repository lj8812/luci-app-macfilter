include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-custom-dhcp
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_MAINTAINER:=Your Name <your.email@example.com>

LUCI_TITLE:=Custom DHCP Client Management
LUCI_DEPENDS:=+luci-base +luci-compat +uci
LUCI_PKGARCH:=all

# 国际化配置
PO_DIR:=./po
PO:=custom-dhcp

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/luci/luci.mk

define Package/$(PKG_NAME)/install
    # 控制器
    $(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller/admin
    $(INSTALL_DATA) ./luasrc/controller/admin/custom-dhcp.lua $(1)/usr/lib/lua/luci/controller/admin/
    
    # CBI模块
    $(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi/admin_custom-dhcp
    $(INSTALL_DATA) ./luasrc/model/cbi/admin_custom-dhcp/clients.lua $(1)/usr/lib/lua/luci/model/cbi/admin_custom-dhcp/
    
    # 配置文件
    $(INSTALL_DIR) $(1)/etc/config
    $(INSTALL_CONF) ./root/etc/config/custom-dhcp $(1)/etc/config/
    
    # 国际化文件（关键！）
    $(INSTALL_DIR) $(1)/usr/lib/lua/luci/i18n
    $(INSTALL_DATA) $(PKG_BUILD_DIR)/i18n/*.lmo $(1)/usr/lib/lua/luci/i18n/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
