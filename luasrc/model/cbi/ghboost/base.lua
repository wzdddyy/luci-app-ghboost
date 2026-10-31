local m, s

m = Map("ghboost", translate("黑猫加速"))

s = m:section(SimpleSection)
s:append(Template("ghboost/style"))
s:append(Template("ghboost/status_overview"))

return m
