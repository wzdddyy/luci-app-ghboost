include $(TOPDIR)/rules.mk

PKG_NAME:=ghboost
PKG_VERSION:=1.2.5
PKG_RELEASE:=1
PKG_MAINTAINER:=wzdddyy
PKG_LICENSE:=Apache-2.0

include $(INCLUDE_DIR)/package.mk

GH_BIN:=$(CURDIR)/files/usr/bin/ghboost

ifeq ($(ARCH),aarch64)
  GH_BIN_MAGIC:=aarch64
else ifeq ($(ARCH),x86_64)
  GH_BIN_MAGIC:=x86-64
else ifeq ($(ARCH),arm)
  GH_BIN_MAGIC:=32-bit LSB executable, ARM
endif

define Package/ghboost
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=GitHub Access Optimization (nat redirect)
  URL:=https://github.com/wzdddyy/luci-app-ghboost
  DEPENDS:=+kmod-nft-nat +ca-bundle
endef

define Package/ghboost/description
  A plugin for accelerating access to GitHub.
endef

define Package/ghboost/conffiles
/etc/config/ghboost
endef

define Build/Compile
endef

define Package/ghboost/install
	@test -f $(GH_BIN) || { \
		echo "ERROR: $(GH_BIN) not found, run 'make -C ghboost stage GOARCH=arm64|amd64|arm' first" >&2; \
		exit 1; }
	@if command -v file >/dev/null 2>&1 && [ -n "$(GH_BIN_MAGIC)" ]; then \
		file $(GH_BIN) | grep -qE '$(GH_BIN_MAGIC)' || { \
			echo "ERROR: $(GH_BIN) architecture mismatch (need $(GH_BIN_MAGIC) / $(ARCH))" >&2; \
			file $(GH_BIN) >&2; exit 1; }; \
	fi
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(GH_BIN) $(1)/usr/bin/ghboost

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

PKG_NAME:=luci-app-ghboost

LUCI_TITLE:=LuCI app for 黑猫加速 (ghboost)
LUCI_PKGARCH:=all
LUCI_DEPENDS:=+luci-base +luci-compat
LUCI_DESCRIPTION:=Web UI for GitHub access optimization (ghboost): start/stop, status dashboard (per-host IP/latency), self-diagnose, editable domain table, log viewer.

include $(TOPDIR)/feeds/luci/luci.mk

