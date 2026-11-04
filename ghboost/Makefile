include $(TOPDIR)/rules.mk

PKG_NAME:=ghboost
PKG_VERSION:=1.2.5
PKG_RELEASE:=2
PKG_MAINTAINER:=wzdddyy
PKG_LICENSE:=Apache-2.0

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

PKG_BUILD_DEPENDS:=golang/host
GO_PKG:=github.com/wzdddyy/ghboost
GO_PKG_LDFLAGS_X:=main.version=$(PKG_VERSION) main.statusVersion=$(PKG_VERSION)

include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(CURDIR)/*.go $(CURDIR)/go.mod $(PKG_BUILD_DIR)/
endef

define Package/ghboost
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=GitHub Access Optimization (nat redirect)
  URL:=https://github.com/wzdddyy/luci-app-ghboost
  DEPENDS:=$(GO_ARCH_DEPENDS) +kmod-nft-nat +ca-bundle
endef

define Package/ghboost/description
  A plugin for accelerating access to GitHub.
endef

define Package/ghboost/conffiles
/etc/config/ghboost
endef

define Package/ghboost/install
	$(call GoPackage/Package/Install/Bin,$(1))

	$(INSTALL_DIR) $(1)/usr/share/ghboost
	$(INSTALL_DATA) $(CURDIR)/files/usr/share/ghboost/domains.conf \
		$(1)/usr/share/ghboost/domains.conf

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(CURDIR)/files/etc/init.d/ghboost $(1)/etc/init.d/ghboost

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(CURDIR)/files/etc/config/ghboost $(1)/etc/config/ghboost

	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) $(CURDIR)/files/etc/uci-defaults/97-ghboost-migrate \
		$(1)/etc/uci-defaults/97-ghboost-migrate
	$(INSTALL_BIN) $(CURDIR)/files/etc/uci-defaults/99-ghboost \
		$(1)/etc/uci-defaults/99-ghboost

	$(INSTALL_DIR) $(1)/etc/hotplug.d/iface
	$(INSTALL_BIN) $(CURDIR)/files/etc/hotplug.d/iface/99-ghboost \
		$(1)/etc/hotplug.d/iface/99-ghboost
endef

define Package/ghboost/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	if [ "$$(uci -q get ghboost.main.enabled 2>/dev/null)" = "1" ]; then
		/etc/init.d/ghboost enable >/dev/null 2>&1 || true
		/etc/init.d/ghboost restart >/dev/null 2>&1 || true
	else
		/etc/init.d/ghboost disable >/dev/null 2>&1 || true
		/etc/init.d/ghboost stop >/dev/null 2>&1 || true
	fi
	rm -f /tmp/luci-indexcache /tmp/luci-modulecache/*
}
exit 0
endef

define Package/ghboost/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	/etc/init.d/ghboost disable >/dev/null 2>&1 || true
	/etc/init.d/ghboost stop >/dev/null 2>&1
	uci -q batch <<-EOF >/dev/null 2>&1
		delete ucitrack.@ghboost[-1]
		commit ucitrack
	EOF
}
exit 0
endef

define Package/ghboost/postrm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	if uci -q get dhcp.@dnsmasq[0] >/dev/null 2>&1; then
		cidr="$$(sed -n 's/^cidr=//p' /tmp/ghboost.runtime 2>/dev/null)"
		[ -n "$$cidr" ] || cidr="$$(uci -q get ghboost.main.fake_cidr 2>/dev/null)"
		[ -n "$$cidr" ] || cidr="100.64.0.0/24"
		pfx="$$(printf '%s' "$$cidr" | cut -d/ -f1 | cut -d. -f1-3)"
		changed=0
		for rule in $$(uci -q get dhcp.@dnsmasq[0].address 2>/dev/null | tr ' ' '\n' | grep -F "/$$pfx."); do
			[ -n "$$rule" ] || continue
			uci -q del_list "dhcp.@dnsmasq[0].address=$$rule" && changed=1
		done
		if [ "$$changed" = "1" ]; then
			uci -q commit dhcp
			/etc/init.d/dnsmasq restart >/dev/null 2>&1
		fi
	fi
	rm -f /tmp/dnsmasq.d/ghboost /tmp/hosts/ghboost
	rm -f /tmp/luci-indexcache /tmp/luci-modulecache/*
	rm -f /etc/rc.d/S99ghboost /etc/rc.d/K*ghboost
}
exit 0
endef

$(eval $(call BuildPackage,ghboost))
