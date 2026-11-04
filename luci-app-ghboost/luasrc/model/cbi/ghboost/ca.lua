local m, s

m = Map("ghboost", translate("CA 证书"))

s = m:section(SimpleSection)
s:append(Template("ghboost/style"))
s:append(Template("ghboost/ca_cert"))

return m
