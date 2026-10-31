module("luci.controller.ghboost", package.seeall)

local fs = require "nixio.fs"
local http = require "luci.http"
local util = require "luci.util"
local jsonc = require "luci.jsonc"

local STATS_FILE = "/tmp/ghboost.status.json"
local DNSCHECK_FILE = "/tmp/ghboost.dnscheck"
local RUNTIME_FILE = "/tmp/ghboost.runtime"
local DEFAULT_DOMAINS = "/usr/share/ghboost/domains.conf"

function index()
	local page = entry({"admin", "services", "ghboost"},
		alias("admin", "services", "ghboost", "base"),
		_("黑猫加速"), 60)
	page.dependent = true
	page.acl_depends = { "luci-app-ghboost" }

	entry({"admin", "services", "ghboost", "base"},
		cbi("ghboost/base"), _("主界面"), 1).leaf = true

	entry({"admin", "services", "ghboost", "log"},
		cbi("ghboost/log"), _("日志"), 2).leaf = true

	entry({"admin", "services", "ghboost", "ca"},
		cbi("ghboost/ca"), _("CA 证书"), 3).leaf = true

	entry({"admin", "services", "ghboost", "status"},
		call("act_status")).leaf = true
	entry({"admin", "services", "ghboost", "toggle"},
		call("act_toggle")).leaf = true
	entry({"admin", "services", "ghboost", "log_api"},
		call("act_log")).leaf = true
	entry({"admin", "services", "ghboost", "ca_cert"},
		call("act_ca_cert")).leaf = true
end

local function runCmd(cmd, seconds)
	if luci.sys.call("command -v timeout >/dev/null 2>&1") == 0 then
		cmd = "timeout " .. tostring(seconds) .. " sh -c " .. util.shellquote(cmd)
	end
	return luci.sys.exec(cmd)
end


local function readRuntime()
	local rt = {}
	local raw = fs.readfile(RUNTIME_FILE)
	if not raw then
		return rt
	end
	for line in raw:gmatch("[^\r\n]+") do
		local k, v = line:match("^(%w+)=(.*)$")
		if k and v ~= "" then
			rt[k] = v
		end
	end
	return rt
end


local function trim(s)
	return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function fieldOf(block, key)
	for line in block:gmatch("[^\r\n]+") do
		local v = line:match("^" .. key .. ":%s*(.+)$")
		if v then
			return trim(v)
		end
	end
	return nil
end

local function parseOpkg(raw, name)
	for block in (raw .. "\n\n"):gmatch("(.-)\n\n") do
		if fieldOf(block, "Package") == name then
			local v = fieldOf(block, "Version")
			if v then
				return v
			end
		end
	end
	return nil
end

local function parseApk(raw, name)
	for block in (raw .. "\n\n"):gmatch("(.-)\n\n") do
		local p = block:match("^P:([^\r\n]+)") or block:match("\nP:([^\r\n]+)")
		if p and trim(p) == name then
			local v = block:match("^V:([^\r\n]+)") or block:match("\nV:([^\r\n]+)")
			if v then
				return trim(v)
			end
		end
	end
	return nil
end

local function pkgVersionUncached(name)
	local raw = fs.readfile("/usr/lib/opkg/info/" .. name .. ".control")
	if raw then
		local v = fieldOf(raw, "Version")
		if v then
			return v
		end
	end

	for _, path in ipairs({ "/lib/apk/db/installed", "/usr/lib/apk/db/installed" }) do
		raw = fs.readfile(path)
		if raw then
			local v = parseApk(raw, name)
			if v then
				return v
			end
		end
	end

	raw = fs.readfile("/usr/lib/opkg/status")
	if raw then
		local v = parseOpkg(raw, name)
		if v then
			return v
		end
	end

	return nil
end

local function pkgVersion(name)
	local cache = "/tmp/ghboost.pkg." .. name
	local cacheMt = fs.stat(cache, "mtime") or 0
	local newest = 0

	for _, path in ipairs({ "/usr/lib/opkg/status", "/lib/apk/db/installed", "/usr/lib/apk/db/installed" }) do
		local m = fs.stat(path, "mtime")
		if m and m > newest then
			newest = m
		end
	end

	if cacheMt > 0 and cacheMt >= newest then
		local cached = fs.readfile(cache)
		if cached then
			cached = trim(cached)
			return cached ~= "" and cached or nil
		end
	end

	local v = pkgVersionUncached(name)
	fs.writefile(cache, (v or "") .. "\n")
	return v
end




local function dnsMappingState(domainsPath)
	local mtime = fs.stat(DNSCHECK_FILE, "mtime")
	if mtime and (os.time() - mtime) < 30 then
		local cached = fs.readfile(DNSCHECK_FILE)
		if cached then
			return (cached:gsub("%s+$", ""))
		end
	end

	local out = runCmd(
		"f=" .. util.shellquote(domainsPath) .. "; " ..
		"[ -f \"$f\" ] || f=" .. DEFAULT_DOMAINS .. "; " ..
		"ip=$(awk '$2==\"github.com\"{print $1; exit}' \"$f\" 2>/dev/null); " ..
		"dom=github.com; " ..
		"if [ -z \"$ip\" ]; then echo none; " ..
		"elif ! command -v nslookup >/dev/null 2>&1; then echo skip; " ..
		"elif nslookup \"$dom\" 127.0.0.1 2>/dev/null | grep -qF \"$ip\"; then echo ok; " ..
		"else echo fail; fi", 6)

	local v = (out or ""):match("(%a+)") or "fail"
	fs.writefile(DNSCHECK_FILE, v .. "\n")
	return v
end

function act_status()
	local e = {}

	local out = runCmd(
		"echo pid=$(pidof ghboost 2>/dev/null); " ..
		"echo binary=$(test -x /usr/bin/ghboost && echo present || echo missing); " ..
		"echo fw=$(nft list table ip ghboost >/dev/null 2>&1 && echo nft || " ..
		"{ iptables -t nat -S GH_BOOST >/dev/null 2>&1 && echo iptables || echo none; }); " ..
		"echo dnsmasq=$(n=$(uci -q get dhcp.@dnsmasq[0].address 2>/dev/null | tr ' ' '\\n' | grep -c .); " ..
		"[ \"${n:-0}\" -gt 0 ] && echo present || echo missing); " ..
		"echo enabled=$(uci -q get ghboost.main.enabled 2>/dev/null); " ..
		"echo domains=$(uci -q get ghboost.main.domains_file)", 8)

	local st = {}
	for line in out:gmatch("[^\r\n]+") do
		local k, v = line:match("^(%w+)=(.*)$")
		if k then
			st[k] = (v:gsub("%s+$", ""))
		end
	end

	e.pid = st.pid or ""
	e.running = (e.pid ~= "")
	e.binary = st.binary or "missing"
	e.fw = st.fw or "none"
	e.tproxy = (e.fw ~= "none")
	e.dnsmasq = st.dnsmasq or "missing"
	e.enabled = (st.enabled == "1")

	local rt = readRuntime()
	e.runtime = rt
	e.domains_file = rt.domains
		or ((st.domains and st.domains ~= "") and st.domains or DEFAULT_DOMAINS)

	e.dnsmap = "skip"
	if e.running then
		e.dnsmap = dnsMappingState(e.domains_file)
	end

	local caPath = luci.sys.exec("uci -q get ghboost.main.ca_cert 2>/dev/null"):gsub("%s+$", "")
	if caPath == "" then
		caPath = "/etc/ghboost/ghboost-ca.crt"
	end
	e.ca_file = fs.access(caPath) and true or false

	e.plain = {}
	local rawDomains = fs.readfile(e.domains_file)
	if rawDomains then
		for line in rawDomains:gmatch("[^\r\n]+") do
			local ip, dom, rest = line:match("^%s*(%d+%.%d+%.%d+%.%d+)%s+(%S+)%s*(.*)$")
			if dom and not rest:match("#sni") and not rest:match("#skip%-verify") then
				e.plain[dom] = true
			end
		end
	end

	local rawStats = fs.readfile(STATS_FILE)
	if rawStats then
		local ok, parsed = pcall(jsonc.parse, rawStats)
		if ok and type(parsed) == "table" then
			e.stats = parsed
			local mtime = fs.stat(STATS_FILE, "mtime")
			if mtime then
				e.stats_age = os.time() - mtime
			end
		end
	end

	e.version_core = nil
	if e.stats and type(e.stats.version) == "string" and e.stats.version ~= "" and e.stats.version ~= "dev" then
		e.version_core = e.stats.version
	end
	if not e.version_core then
		e.version_core = pkgVersion("ghboost")
	end
	e.version_ui = pkgVersion("luci-app-ghboost")

	http.prepare_content("application/json")
	http.write_json(e)
end

function act_toggle()
	local on = (http.formvalue("on") == "1")

	luci.sys.call("uci -q set ghboost.main.enabled=" ..
		(on and "1" or "0") .. " && uci -q commit ghboost >/dev/null 2>&1")
	luci.sys.call("/etc/init.d/ghboost " .. (on and "start" or "stop") ..
		" >/dev/null 2>&1")

	http.redirect(luci.dispatcher.build_url("admin/services/ghboost/base"))
end

function act_log()
	http.prepare_content("text/plain; charset=utf-8")
	local n = tonumber(http.formvalue("n")) or 100
	if n < 1 or n > 2000 then
		n = 100
	end

	local logPath = readRuntime().log
	local cmd
	if logPath and logPath ~= "" then
		cmd = "if [ -f " .. util.shellquote(logPath) .. " ]; then tail -n " .. n .. " " ..
			util.shellquote(logPath) .. "; else logread -e ghboost 2>/dev/null | tail -n " .. n .. "; fi"
	else
		cmd = "f=$(uci -q get ghboost.main.log_file); " ..
			"if [ -n \"$f\" ] && [ -f \"$f\" ]; then tail -n " .. n .. " \"$f\"; " ..
			"else logread -e ghboost 2>/dev/null | tail -n " .. n .. "; fi"
	end
	http.write(runCmd(cmd, 8))
end

function act_ca_cert()
	local certPath = luci.sys.exec("uci -q get ghboost.main.ca_cert 2>/dev/null"):gsub("%s+$", "")
	if certPath == "" then
		certPath = "/etc/ghboost/ghboost-ca.crt"
	end

	local raw = fs.readfile(certPath)
	if raw == nil then
		http.status(404, "Not Found")
		http.prepare_content("text/plain; charset=utf-8")
		http.write("CA 证书不存在: " .. certPath .. "\n请先启动 ghboost 服务，它会自动生成 CA 证书。\n")
		return
	end

	http.prepare_content("application/x-x509-ca-cert")
	http.header("Content-Disposition", "attachment; filename=ghboost-ca.crt")
	http.write(raw)
end
