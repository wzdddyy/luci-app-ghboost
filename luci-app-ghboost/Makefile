include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-ghboost
PKG_VERSION:=1.2.5
PKG_RELEASE:=3
PKG_MAINTAINER:=wzdddyy
PKG_LICENSE:=Apache-2.0

LUCI_TITLE:=LuCI app for 黑猫加速 (ghboost)
LUCI_PKGARCH:=all
LUCI_DEPENDS:=+luci-base +luci-compat
LUCI_DESCRIPTION:=Web UI for GitHub access optimization (ghboost): start/stop, status dashboard (per-host IP/latency), self-diagnose, editable domain table, log viewer.

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
