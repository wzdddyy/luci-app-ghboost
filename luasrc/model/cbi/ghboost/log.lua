local m, s

m = Map("ghboost", translate("运行日志"))

s = m:section(SimpleSection)
s:append(Template("ghboost/style"))
s:append(Template("ghboost/log"))

return m
