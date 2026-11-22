#!/bin/sh
# ghboost 快速安装脚本
#
# 用法:
#   wget -qO- https://raw.githubusercontent.com/wzdddyy/luci-app-ghboost/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/wzdddyy/luci-app-ghboost/main/install.sh | sh

set -eu

BASE="https://github.com/wzdddyy/luci-app-ghboost/releases/download/latest"
SUPPORTED="aarch64_cortex-a53 aarch64_cortex-a72 aarch64_generic arm_cortex-a7_neon-vfpv4 arm_cortex-a9 arm_cortex-a9_neon x86_64"
TMP="${TMPDIR:-/tmp}"

say() { printf '%s\n' "$*"; }
die() { printf '错误: %s\n' "$*" >&2; exit 1; }

if command -v opkg >/dev/null 2>&1; then
	MGR=opkg
	EXT=ipk
elif command -v apk >/dev/null 2>&1; then
	MGR=apk
	EXT=apk
else
	die "未检测到 opkg 或 apk，本脚本仅适用于 OpenWrt"
fi

pkg_arch_candidates() {
	if [ -r /etc/openwrt_release ]; then
		sed -n "s/^DISTRIB_ARCH=['\"]*\([^'\"]*\)['\"]*$/\1/p" /etc/openwrt_release | head -n1
	fi
	if [ -r /etc/apk/arch ]; then
		head -n1 /etc/apk/arch
	fi
	if [ -r /lib/apk/db/installed ]; then
		sed -n 's/^A://p' /lib/apk/db/installed | sort | uniq -c | sort -rn | head -n1 | awk '{print $2}'
	elif [ -r /usr/lib/apk/db/installed ]; then
		sed -n 's/^A://p' /usr/lib/apk/db/installed | sort | uniq -c | sort -rn | head -n1 | awk '{print $2}'
	fi
	sed -n 's#.*/packages/\([^/]*\)/.*#\1#p' \
		/etc/apk/repositories /etc/apk/repositories.d/*.list /etc/opkg/distfeeds.conf 2>/dev/null | head -n1
	if [ "$MGR" = opkg ]; then
		opkg print-architecture 2>/dev/null | awk '!/all|noarch/{a=$2}END{print a}'
	else
		apk --print-arch 2>/dev/null || true
	fi
}

CANDIDATES=$(pkg_arch_candidates)
RAW=$(printf '%s\n' "$CANDIDATES" | head -n1)
ARCH=$(printf '%s\n' "$CANDIDATES" | awk -v s=" $SUPPORTED " 'index(s, " " $0 " "){print; exit}')

if [ -z "$ARCH" ]; then
	case "$(uname -m)" in
	aarch64|arm64) ARCH=aarch64_cortex-a53 ;;
	x86_64|amd64) ARCH=x86_64 ;;
	armv7l|armv7) ARCH=arm_cortex-a7_neon-vfpv4 ;;
	esac
	if [ -n "$ARCH" ]; then
		say "未识别到精确架构（检测值: ${RAW:-无}），按 $(uname -m) 选用通用包: $ARCH"
	fi
fi

[ -n "$ARCH" ] || die "无法识别设备架构（检测值: ${RAW:-无}），请在 GitHub Issues 反馈 uname -m 输出"

say "包管理器: $MGR"
say "设备架构: $ARCH"

CORE="ghboost_${ARCH}.${EXT}"
UI="luci-app-ghboost_all.${EXT}"

fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fL --connect-timeout 15 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -O "$2" "$1"
	else
		die "缺少 curl / wget，无法下载"
	fi
}

for f in "$CORE" "$UI"; do
	say "下载 $f"
	if ! fetch "$BASE/$f" "$TMP/$f"; then
		say "下载失败: $BASE/$f"
		die "可在可访问 GitHub 的电脑上下载后，scp 到路由器的 $TMP 目录再执行: $MGR install $TMP/$f"
	fi
	[ -s "$TMP/$f" ] || die "下载文件为空: $BASE/$f"
done

pkg_installed() {
	if [ "$MGR" = "opkg" ]; then
		opkg list-installed 2>/dev/null | awk '{print $1}' | grep -qx "$1"
	else
		grep -qx "P:$1" /lib/apk/db/installed 2>/dev/null ||
			grep -qx "P:$1" /usr/lib/apk/db/installed 2>/dev/null
	fi
}

missing=""
for p in kmod-nft-nat ca-bundle; do
	pkg_installed "$p" || missing="$missing $p"
done

if [ -n "$missing" ]; then
	say "缺少依赖:$missing，刷新软件源后安装（首次较慢，请等待）"
	if [ "$MGR" = "opkg" ]; then
		opkg update || say "警告: opkg update 失败，继续尝试"
		opkg install $missing || say "警告: 依赖安装失败，请检查软件源"
	else
		apk update || say "警告: apk update 失败，继续尝试"
		apk add $missing || say "警告: 依赖安装失败，请检查软件源"
	fi
else
	say "依赖 kmod-nft-nat ca-bundle 已安装，跳过软件源刷新"
fi

if [ "$MGR" = "opkg" ]; then
	if ! opkg install "$TMP/$CORE" "$TMP/$UI"; then
		say "安装失败，可手动执行: opkg install $TMP/$CORE $TMP/$UI"
		exit 1
	fi
else
	if ! apk add --allow-untrusted "$TMP/$CORE" "$TMP/$UI"; then
		say "安装失败，可手动执行: apk add --allow-untrusted $TMP/$CORE $TMP/$UI"
		exit 1
	fi
fi

rm -f "$TMP/$CORE" "$TMP/$UI"

# 首次安装时补齐默认配置
for s in /etc/uci-defaults/98-ghboost-config /etc/uci-defaults/99-ghboost; do
	[ -x "$s" ] && "$s" >/dev/null 2>&1 || true
done

rm -f /tmp/luci-indexcache
rm -f /tmp/luci-modulecache/* 2>/dev/null || true
/etc/init.d/uhttpd restart >/dev/null 2>&1 || true

say ""
say "安装完成。"
say "1. 打开 LuCI -> 服务 -> 黑猫加速，点击启用"
say "2. 在该页面「CA 证书」中下载 ghboost-ca.crt，安装到客户端"
say "3. 未安装证书前，客户端访问 GitHub 会提示证书错误"
