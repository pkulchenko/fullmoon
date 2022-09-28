--
-- ultralight webframework for [Redbean web server](https://redbean.dev/)
-- Copyright 2021 Paul Kulchenko
--

local NAME, VERSION = "fullmoon", "0.34"

--[[-- support functions --]]--

local unpack = table.unpack or unpack
local load = load or loadstring
if not setfenv then -- Lua 5.2+; this assumes f is a function
  -- based on http://lua-users.org/lists/lua-l/2010-06/msg00314.html
  -- and https://leafo.net/guides/setfenv-in-lua52-and-above.html
  local function findenv(f)
    local idx = 1
    repeat
      local name, value = debug.getupvalue(f, idx)
      if name == '_ENV' then return idx, value end
      idx = idx + 1
    until not name
  end
  getfenv = function (f) return(select(2, findenv(f)) or _G) end
  setfenv = function (f, t)
    local level = findenv(f)
    if level then debug.upvaluejoin(f, level, function() return t end, 1) end
    return f
  end
end
local function loadsafe(data)
  local f, err = load(data)
  if not f then return f, err end
  local c = -2
  local hf, hm, hc = debug.gethook()
  debug.sethook(function() c=c+1; if c>0 then error("failed safety check") end end, "c")
  local ok, res = pcall(f)
  c = -1
  debug.sethook(hf, hm, hc)
  return ok, res
end
local function argerror(cond, narg, extramsg, name)
  name = name or debug.getinfo(2, "n").name or "?"
  local msg = ("bad argument #%d to %s%s"):format(narg, name, extramsg and " "..extramsg or  "")
  if not cond then error(msg, 3) end
  return cond, msg
end
local function logFormat(fmt, ...)
  argerror(type(fmt) == "string", 1, "(string expected)")
  return "(fm) "..(select('#', ...) == 0 and fmt or (fmt or ""):format(...))
end
local function getRBVersion()
  local v = GetRedbeanVersion()
  local major = math.floor(v / 2^16)
  local minor = math.floor((v / 2^16 - major) * 2^8)
  return ("%d.%d.%d"):format(major, minor, v % 2^8)
end
local LogDebug = function(...) return Log(kLogDebug, logFormat(...)) end
local LogVerbose = function(...) return Log(kLogVerbose, logFormat(...)) end
local LogInfo = function(...) return Log(kLogInfo, logFormat(...)) end
local LogWarn = function(...) return Log(kLogWarn, logFormat(...)) end
local istype = function(b)
  return function(mode) return math.floor((mode % (2*b)) / b) == 1 end end
local isregfile = unix and unix.S_ISREG or istype(2^15)
-- headers that are not allowed to be set, as Redbean may
-- also set them, leading to conflicts and improper handling
local noHeaderMap = {
  ["content-length"] = true,
  ["transfer-encoding"] = true,
  ["content-encoding"] = true,
  date = true,
  connection = "close",  -- the only value that is allowed
}

-- request headers based on https://datatracker.ietf.org/doc/html/rfc7231#section-5
-- response headers based on https://datatracker.ietf.org/doc/html/rfc7231#section-7
-- this allows the user to use `.ContentType` instead of `["Content-Type"]`
-- Host is listed to allow retrieving Host header even in the presence of host attribute
local headerMap = {}
(function(s) for h in s:gmatch("[%w%-]+") do headerMap[h:gsub("-","")] = h end end)([[
  Cache-Control Host Max-Forwards Proxy-Authorization User-Agent
  Accept-Charset Accept-Encoding Accept-Language Content-Disposition
  If-Match If-None-Match If-Modified-Since If-Unmodified-Since If-Range
  Content-Type Content-Encoding Content-Language Content-Location
  Retry-After Last-Modified WWW-Authenticate Proxy-Authenticate Accept-Ranges
  Content-Length Transfer-Encoding
]])
local htmlVoidTags = {} -- from https://html.spec.whatwg.org/#void-elements
(function(s) for h in s:gmatch("%w+") do htmlVoidTags[h] = true end end)([[
  area base br col embed hr img input link meta param source track wbr
]])
local default500 = [[<!doctype html><title>{%& status %} {%& reason %}</title>
<h1>{%& status %} {%& reason %}</h1>
{% if message then %}<pre>{%& message %}</pre>{% end %}]]

--[[-- route path generation --]]--

local PARAM = "([:*])([%w_]*)"
local routes = {}
local function makePath(name, params)
  argerror(type(name) == "string", 1, "(string expected)")
  params = params or {}
  -- name can be the name or the route itself (even not registered)
  local pos = routes[name]
  local route = pos and routes[pos].route or name
  -- replace :foo and *splat with provided parameters
  route = route:gsub(PARAM.."([^(*:]*)", function(sigil, param, rest)
      if sigil == "*" and param == "" then param = "splat" end
      -- ignore everything that doesn't match `:%w` pattern
      if sigil == ":" and param == "" then return sigil..param..rest end
      -- if the parameter value is `false`, replace it with an empty string
      return ((params[param] or (params[param] == false and "" or sigil..param))
        ..rest:gsub("^%b[]",""))
    end)
  -- remove all optional groups
  local function findopt(route)
    return route:gsub("(%b())", function(optroute)
        optroute = optroute:sub(2, -2)
        local s = optroute:find("[:*]")
        if s then
          local p = optroute:find("%b()")
          if not p or s < p then return "" end
        end
        return findopt(optroute)
      end)
  end
  route = findopt(route)
  local param = route:match(":(%a[%w_]*)") or route:match("*([%w_]*)")
  argerror(not param, 2, "(missing required parameter "
    ..(param and #param > 0 and param or "splat")..")")
  return route
end
local function makeUrl(url, opts)
  if type(url) == "table" and opts == nil then url, opts = nil, url end
  if not url then url = GetUrl() end
  if not opts then opts = {} end
  argerror(type(url) == "string", 1, "(string expected)")
  argerror(type(opts) == "table", 2, "(table expected)")
  -- check if params are in the hash table format and
  -- convert to the array format that Redbean expects
  if opts.params and not opts.params[1] and next(opts.params) then
    local tbl = {}
    for k, v in pairs(opts.params) do
      table.insert(tbl, v == true and {k} or {k, v})
    end
    table.sort(tbl, function(a, b) return a[1] < b[1] end)
    opts.params = tbl
  end
  local parts = ParseUrl(url)
  -- copy options, but remove those that have `false` values
  for k, v in pairs(opts) do parts[k] = v or nil end
  return EncodeUrl(parts)
end

local ref = {} -- some unique key value
-- request functions (`request.write()`)
local reqenv = {
  escapeHtml = EscapeHtml, escapePath = EscapePath,
  formatIp = FormatIp, formatHttpDateTime = FormatHttpDateTime,
  makePath = makePath, makeUrl = makeUrl, }
-- request properties (`request.authority`)
local reqapi = { authority = function()
    local parts = ParseUrl(GetUrl())
    return EncodeUrl({scheme = parts.scheme, host = parts.host, port = parts.port})
  end, }
local function genEnv(opt)
  opt = opt or {}
  return function(t, key)
    local val = reqenv[key] or rawget(t, ref) and rawget(t, ref)[key]
    -- can cache the value, since it's not passed as a parameter
    local cancache = val == nil
    if not opt.request and val == nil then val = _G[key] end
    if opt.request and val == nil and type(key) == "string" then
      local func = reqapi[key] or _G["Get"..key:sub(1,1):upper()..key:sub(2)]
      -- map a property (like `.host`) to a function call (`GetHost()`)
      if type(func) == "function" then val = func() else val = func end
    end
    -- allow pseudo-tags, but only if used in a template environment;
    -- provide fallback for `table` to make `table{}` and `table.concat` work
    local istable = key == "table"
    if opt.autotag and (val == nil or istable) then
      -- nothing was resolved; this is either undefined value or
      -- a pseudo-tag (like `div{}` or `span{}`), so add support for them
      val = setmetatable({key}, {
          -- support the case of printing/concatenating undefined values
          -- tostring handles conversion to a string
          __tostring = function() return "" end,
          -- concat handles contatenation with a string
          __concat = function(a, _) return a end,
          __index = (istable and table or nil),
          __call = function(t, v, ...)
            if type(v) == "table" then
              table.insert(v, 1, key)
              return v
            end
            return {t[1], v, ...}
          end})
    elseif cancache then
      t[key] = val -- cache the calculated value for future use
    end
    return val
  end
end
local tmplTagHandlerEnv = {__index = genEnv({autotag = true}) }
local tmplRegHandlerEnv = {__index = genEnv() }
local tmplReqHandlerEnv = {__index = genEnv({request = true}) }
local req
local function getRequest() return req end
local function detectType(s)
  local ch = s:match("^%s*(%S)")
  return ch and (ch == "<" and "text/html" or ch == "{" and "application/json") or "text/plain"
end

local function serveResponse(status, headers, body)
  -- since headers is optional, handle the case when headers are not present
  if type(headers) == "string" and body == nil then
    body, headers = headers, nil
  end
  if type(status) == "string" and body == nil and headers == nil then
    body, status = status, 200
  end
  argerror(type(status) == "number", 1, "(number expected)")
  argerror(not headers or type(headers) == "table", 2, "(table expected)")
  argerror(not body or type(body) == "string", 3, "(string expected)")
  return function()
    SetStatus(status)
    if headers then
      -- make sure that the metatable gets transferred as well
      local r = getRequest()
      r.headers = setmetatable(headers, getmetatable(r.headers))
    end
    if body then Write(body) end
    return true
  end
end

--[[-- template engine --]]--

local templates, vars = {}, {}
local function render(name, opt)
  argerror(type(name) == "string", 1, "(string expected)")
  argerror(templates[name], 1, "(unknown template name '"..tostring(name).."')")
  argerror(not opt or type(opt) == "table", 2, "(table expected)")
  local params = {vars = vars}  -- assign by default, but allow to overwrite
  local env = getfenv(templates[name].handler)
  -- add "original" template parameters
  for k, v in pairs(rawget(env, ref) or {}) do params[k] = v end
  -- add "passed" template parameters
  for k, v in pairs(opt or {}) do params[k] = v end
  LogDebug("render template '%s'", name)
  local refcopy = env[ref]
  env[ref] = params
  local res, more = templates[name].handler(opt)
  env[ref] = refcopy
  -- return template results or an empty string to indicate completion
  -- this is useful when the template does direct write to the output buffer
  return res or "", more or templates[name].ContentType
end

local function setTemplate(name, code, opt)
  -- name as a table designates a list of prefixes for assets paths
  -- to load templates from;
  -- its hash values provide mapping from extensions to template types
  if type(name) == "table" then
    local tmpls = {}
    for _, prefix in ipairs(name) do
      local paths = GetZipPaths(prefix)
      for _, path in ipairs(paths) do
        local tmplname, ext = path:gsub("^"..prefix.."/?",""):match("(.+)%.(%w+)$")
        if ext and name[ext] then
          setTemplate(tmplname, {type = name[ext], path  = path,
              LoadAsset(path) or error("Can't load asset: "..path)})
          tmpls[tmplname] = true
        end
      end
    end
    return tmpls
  end
  argerror(type(name) == "string", 1, "(string or table expected)")
  local params = {}
  if type(code) == "table" then params, code = code, table.remove(code, 1) end
  local ctype = type(code)
  argerror(ctype == "string" or ctype == "function", 2, "(string, table or function expected)")
  LogVerbose("set template '%s'", name)
  local tmpl = templates[params.type or "fmt"]
  if ctype == "string" then
    argerror(tmpl ~= nil, 2, "(unknown template type/name)")
    argerror(tmpl.parser ~= nil, 2, "(referenced template doesn't have a parser)")
    code = assert(load(tmpl.parser(code), "@".. (params.path or name)))
  end
  local env = setmetatable({render = render, [ref] = opt},
    -- get the metatable from the template that this one is based on,
    -- to make sure the correct environment is being served
    tmpl and getmetatable(getfenv(tmpl.handler)) or
    (opt or {}).autotag and tmplTagHandlerEnv or tmplRegHandlerEnv)
  params.handler = setfenv(code, env)
  templates[name] = params
  return {name = true}
end

local function setTemplateVar(name, value) vars[name] = value end

--[[-- routing engine --]]--

local setmap = {}
(function(s) for pat, reg in s:gmatch("(%S+)=([^%s,]+),?") do setmap[pat] = reg end end)([[
  d=0-9, ]=[.].], -=[.-.], a=[:alpha:], l=[:lower:], u=[:upper:], w=[:alnum:], x=[:xdigit:],
]])
local function findset(s)
  return setmap[s] or s:match("%p") and s or error("Invalid escape sequence %"..s)
end
local function route2regex(route)
  -- foo/bar, foo/*, foo/:bar, foo/:bar[%d], foo(/:bar(/:more))(.:ext)
  local params = {}
  local regex = route:gsub("%)", "%1?") -- update optional groups from () to ()?
    :gsub("%.", "\\.") -- escape dots (.)
    :gsub(PARAM, function(sigil, param)
        if sigil == "*" and param == "" then param = "splat" end
        -- ignore everything that doesn't match `:%w` pattern
        if sigil == ":" and param == "" then return sigil..param end
        table.insert(params, param)
        return sigil == "*" and "(.*)" or "([^/]+)"
      end)
    :gsub("%b[](%+%))(%b[])([^/:*%[]*)", function(sep, pat, rest)
        local leftover, more = rest:match("(.-])(.*)")
        if leftover then pat = pat..leftover; rest = more end
        -- replace Lua character classes with regex ones
        return pat:gsub("%%(.)", findset)..sep..rest end)
  -- mark optional captures, as they are going to be returned during match
  local subnum = 1
  local s, _, capture = 0
  while true do
    s, _, capture = regex:find("%b()([?]?)", s+1)
    if not s then break end
    if capture > "" then table.insert(params, subnum, false) end
    subnum = subnum + 1
  end
  return "^"..regex.."$", params
end

local function findRoute(route, opts)
  for i, r in ipairs(routes) do
    local ometh = opts.method
    local rmeth = (r.options or {}).method
    if route == r.route and
      (type(ometh) == "table" and table.concat(ometh, ",") or ometh) ==
      (type(rmeth) == "table" and table.concat(rmeth, ",") or rmeth) then
      return i
    end
  end
end
local function setRoute(opts, handler)
  local ot = type(opts)
  if ot == "string" then
    opts = {opts}
  elseif ot == "table" then
    if #opts == 0 then argerror(false, 1, "(one or more routes expected)") end
  else
    argerror(false, 1, "(string or table expected)")
  end
  -- as the handler is optional, allow it to be skipped
  local ht = type(handler)
  argerror(ht == "function" or ht == "string" or ht == "nil", 2, "(function or string expected)")
  if ht == "string" then
    -- if `handler` is a string, then turn it into a handler that does
    -- internal redirect (to an existing path), but not a directory.
    -- This is to avoid failing on a missing directory index.
    -- If directory index is still desired, then use `serveIndex()`.
    local newroute = handler
    handler = function(r)
      local path = r.makePath(newroute, r.params)
      local mode = GetAssetMode(path)
      return mode and isregfile(mode) and RoutePath(path)
    end
  end
  if ot == "table" then
    -- remap filters to hash if presented as an (array) table
    for k, v in pairs(opts) do
      if type(v) == "table" then
        -- {"POST", "PUT"} => {"POST", "PUT", PUT = true, POST = true}
        for i = 1, #v do v[v[i]] = true end
        -- if GET is allowed, then also allow HEAD, unless `HEAD=false` exists
        if k == "method" and v.GET and v.HEAD == nil then
          table.insert(v, "HEAD") -- add to the list to generate a proper list of methods
          v.HEAD = v.GET
        end
        if v.regex then v.regex = re.compile(v.regex) or argerror(false, 3, "(valid regex expected)") end
      elseif headerMap[k] then
        opts[k] = {pattern = "%f[%w]"..v.."%f[%W]"}
      end
    end
  end
  -- process 1+ routes as specified
  while true do
    local route = table.remove(opts, 1)
    if not route then break end
    argerror(type(route) == "string", 1, "(route string expected)")
    local pos = findRoute(route, opts) or #routes+1
    if opts.routeName then
      if routes[opts.routeName] then LogWarn("route '%s' already registered", opts.routeName) end
      routes[opts.routeName], opts.routeName = pos, nil
    end
    local regex, params = route2regex(route)
    local tmethod = type(opts.method)
    local methods = tmethod == "table" and opts.method or tmethod == "string" and {opts.method} or {'ANY'}
    LogVerbose("set route '%s' (%s) at index %d", route, table.concat(methods,','), pos)
    routes[pos] = {route = route, handler = handler, options = opts, comp = re.compile(regex), params = params}
    routes[route] = pos
  end
end

local function matchCondition(value, cond)
  if type(cond) == "function" then return cond(value) end
  if type(cond) ~= "table" then return value == cond end
  -- allow `{function() end, otherwise = ...}` as well
  if type(cond[1]) == "function" then return cond[1](value) end
  if value == nil or cond[value] then return true end
  if cond.regex then return cond.regex:search(value) ~= nil end
  if cond.pattern then return value:match(cond.pattern) ~= nil end
  return false
end

local function getAllowedMethod(matchedRoutes)
  local methods = {}
  for _, idx in ipairs(matchedRoutes) do
    local routeMethod = routes[idx].options and routes[idx].options.method
    if routeMethod then
      for _, method in ipairs(type(routeMethod) == "table" and routeMethod or {routeMethod}) do
        if not methods[method] then
          methods[method] = true
          table.insert(methods, method)
        end
      end
    end
  end
  table.sort(methods)
  return (#methods > 0
    and table.concat(methods, ", ")..(methods.OPTIONS == nil and ", OPTIONS" or "")
    or "GET, HEAD, POST, PUT, DELETE, OPTIONS")
end

local function matchRoute(path, req)
  assert(type(req) == "table", "bad argument #2 to match (table expected)")
  LogDebug("match %d route(s) against '%s'", #routes, path)
  local matchedRoutes = {}
  for idx, route in ipairs(routes) do
    -- skip static routes that are only used for path generation
    local opts = route.options
    if route.handler or opts and opts.otherwise then
      local res = {route.comp:search(path)}
      local matched = table.remove(res, 1)
      LogDebug("route '%s' %smatched", route.route, matched and "" or "not ")
      if matched then -- path matched
        table.insert(matchedRoutes, idx)
        for ind, val in ipairs(route.params) do
          if val and res[ind] then req.params[val] = res[ind] > "" and res[ind] or false end
        end
        -- check if there are any additional options to filter by
        local otherwise
        matched = true
        if opts and next(opts) then
          for filter, cond in pairs(opts) do
            if filter ~= "otherwise" then
              local header = headerMap[filter]
              -- check "dashed" headers, params, properties (method, port, host, etc.), and then headers again
              local value = (filter == "r" and req  -- special request value
                or header and req.headers[header]  -- an existing header
                or req.params[filter] or req[filter] or req.headers[filter])
              -- condition can be a value (to compare with) or a table/hash with multiple values
              local resCond, err = matchCondition(value, cond)
              if not resCond then
                otherwise = type(cond) == "table" and cond.otherwise or opts.otherwise
                LogDebug("route '%s' filter '%s%s' didn't match value '%s'%s",
                  route.route, filter, type(cond) == "string" and "="..cond or "",
                  value, tonumber(otherwise) and " and returned "..otherwise or "")
                if otherwise then
                  if type(otherwise) == "function" then
                    return otherwise(err, value)
                  else
                    if otherwise == 405 and not req.headers.Allow then
                      req.headers.Allow = getAllowedMethod(matchedRoutes)
                    end
                    return serveResponse(otherwise)
                  end
                end
                matched = false
                break
              end
            end
          end
        end
        if matched and route.handler then
          local res, more = route.handler(req)
          if res then return res, more end
        end
      end
    end
  end
end

--[[-- storage engine --]]--

local function makeStorage(dbname, sqlsetup)
  local sqlite3 = require "lsqlite3"
  local dbm = {prepcache = {}, name = dbname, sql = sqlsetup}
  local msgdelete = "use delete option to force"
  function dbm:init()
    local db = self.db
    if not db then
      local code, msg
      db, code, msg = sqlite3.open(self.name)
      if not db then error(("%s (code: %d)"):format(msg, code)) end
      if db:exec(self.sql) > 0 then error("can't setup db: "..db:errmsg()) end
      self.db = db
    end
    -- simple __index = db doesn't work, as it gets `dbm` passed instead of `db`,
    -- so remapping is needed to proxy this to `t.db` instead
    return setmetatable(self, {__index = function(t,k)
          return function(self,...) return t.db[k](db,...) end
        end})
  end
  local function norm(sql)
    return (sql:gsub("%-%-[^\n]*\n?",""):gsub("^%s+",""):gsub("%s+$",""):gsub("%s+"," ")
      :gsub("%s*([(),])%s*","%1"):gsub('"(%w+)"',"%1"))
  end
  function dbm:upgrade(opts)
    opts = opts or {}
    local actual = self.db or error("can't ungrade non initialized db")
    local pristine = makeStorage(":memory:", self.sql).db
    local sqltbl = [[SELECT name, sql FROM sqlite_master
      WHERE type = "table" AND name not like "sqlite_%"]]
    -- this PRAGMA is automatically disabled when the db is committed
    local changes = {}
    local actbl, prtbl = {}, {}
    for r in pristine:nrows(sqltbl) do prtbl[r.name] = r.sql end
    for r in actual:nrows(sqltbl) do
      actbl[r.name] = true
      if prtbl[r.name] then
        if norm(r.sql) ~= norm(prtbl[r.name]) then
          local namepatt = '%f[^%s"]'..r.name:gsub("%p","%%%1")..'%f[%s"]'
          local tmpname = r.name.."__new"
          local createtbl = prtbl[r.name]:gsub(namepatt, tmpname, 1)
          table.insert(changes, createtbl)

          local sqlcol = ("PRAGMA table_info(%s)"):format(r.name)
          local common, prcol = {}, {}
          for c in pristine:nrows(sqlcol) do prcol[c.name] = true end
          for c in actual:nrows(sqlcol) do
            if prcol[c.name] then
              table.insert(common, c.name)
            elseif not opts.delete then
              return nil, ("Not allowed to remove '%s' from '%s'; %s"
                ):format(c.name, r.name, msgdelete)
            end
          end
          local cols = table.concat(common, ",")
          table.insert(changes, ("INSERT INTO %s (%s) SELECT %s FROM %s")
            :format(tmpname, cols, cols, r.name))
          table.insert(changes, ("DROP TABLE %s"):format(r.name))
          table.insert(changes, ("ALTER TABLE %s RENAME TO %s"):format(tmpname, r.name))
        end
      else
        if not opts.delete then
          return nil, ("Not allowed to drop table '%s'; %s"
            ):format(r.name, msgdelete)
        end
        table.insert(changes, ("DROP table %s"):format(r.name))
      end
    end
    for k in pairs(prtbl) do
      if not actbl[k] then table.insert(changes, prtbl[k]) end
    end

    local sqlidx = [[SELECT name, sql FROM sqlite_master
      WHERE type = "index" AND name not like "sqlite_%"]]
    actbl, prtbl = {}, {}
    for r in pristine:nrows(sqlidx) do prtbl[r.name] = r.sql end
    for r in actual:nrows(sqlidx) do
      actbl[r.name] = true
      if prtbl[r.name] then
        if r.sql ~= prtbl[r.name] then
          table.insert(changes, ("DROP INDEX IF EXISTS %s"):format(r.name))
          table.insert(changes, prtbl[r.name])
        end
      else
        table.insert(changes, ("DROP INDEX IF EXISTS %s"):format(r.name))
      end
    end
    for k in pairs(prtbl) do
      if not actbl[k] then table.insert(changes, prtbl[k]) end
    end

    local acpfk, prpfk = "0", "0"
    -- get the current value of `PRAGMA foreign_keys` to restore if needed
    actual:exec("PRAGMA foreign_keys", function (u,c,v,n) acpfk = v[1] return 0 end)
    -- get the pristine value of `PRAGMA foreign_keys` to set later
    pristine:exec("PRAGMA foreign_keys", function (u,c,v,n) prpfk = v[1] return 0 end)

    if opts.integritycheck ~= false then
      local row = self:fetchone("PRAGMA integrity_check(1)")
      if row and row.integrity_check ~= "ok" then return nil, row.integrity_check end
      -- check foreign key violations if the foreign key setting is enabled
      row = prpfk ~= "0" and self:fetchone("PRAGMA foreign_key_check")
      if row then return nil, "foreign key check failed" end
    end
    if opts.dryrun then return changes end
    if #changes == 0 then return changes end

    -- disable `pragma foreign_keys`, to avoid triggerring cascading deletes
    local ok, err = self:exec("PRAGMA foreign_keys = OFF")
    if not ok then return ok, err end

    -- execute the changes
    ok, err = self:execall(changes)
    -- restore `PRAGMA foreign_keys` value:
    -- (1) to the original value after failure
    -- (2) to the "pristine" value after normal execution
    local pfk = "PRAGMA foreign_keys="..(ok and prpfk or acpfk)
    if self:exec(pfk) and ok then table.insert(changes, pfk) end
    if not ok then return ok, err end

    -- clean up the database
    ok, err = self:exec("VACUUM")
    if not ok then return ok, err end
    return changes
  end
  function dbm:prepstmt(stmt)
    if not self.prepcache[stmt] then
      self.prepcache[stmt] = self.db:prepare(stmt)
    end
    return self.prepcache[stmt]
  end
  function dbm:close()
    if not self.db then return end
    local db = self.db
    for code, stmt in pairs(self.prepcache) do
      if stmt:finalize() > 0 then
        error("can't finalize '"..code.."': "..db:errmsg())
      end
    end
    return db:close()
  end
  function dbm:exec(stmt, ...)
    if not self.db then self:init() end
    local db = self.db
    if type(stmt) == "string" then stmt = self:prepstmt(stmt) end
    if not stmt then return nil, "can't prepare: "..db:errmsg() end
    if stmt:bind_values(...) > 0 then return nil, "can't bind values"..db:errmsg() end
    if stmt:step() ~= sqlite3.DONE then
      return nil, "can't execute prepared statement: "..db:errmsg()
    end
    stmt:reset()
    return db:changes()
  end
  local function fetch(self, stmt, one, ...)
    if not self.db then self:init() end
    local db = self.db
    if type(stmt) == "string" then stmt = self:prepstmt(stmt) end
    if not stmt then error("can't prepare: "..db:errmsg()) end
    if stmt:bind_values(...) > 0 then error("can't bind values: "..db:errmsg()) end
    local rows = {}
    for row in stmt:nrows() do
      table.insert(rows, row)
      if one then break end
    end
    stmt:reset()
    return not one and rows or rows[1]
  end
  function dbm:fetchall(stmt, ...) return fetch(dbm, stmt, false, ...) end
  function dbm:fetchone(stmt, ...) return fetch(dbm, stmt, true, ...) end
  function dbm:execall(list)
    if not self.db then self:init() end
    local db = self.db
    db:exec("begin")
    for _, sql in ipairs(list) do
      if type(sql) ~= "table" then sql = {sql} end
      local ok, err = self:exec(unpack(sql))
      if not ok then
        db:exec("rollback")
        return nil, err
      end
    end
    db:exec("commit")
    return true
  end
  return dbm:init()
end

--[[-- hook management --]]--

local hooks = {}
local function onHook(hookName, ...)
  for _, v in ipairs(hooks[hookName]) do
    local res = v[1](...)
    if res ~= nil then return res end
  end
end
local function findHook(hookName, suffix)
  for i, v in ipairs(hooks[hookName]) do
    if v[2] == suffix then return i, v end
  end
end
local function setHook(name, func)
  -- name: OnWorkerStart[.suffix]
  argerror(type(name) == "string", 1, "(string expected)")
  local main, suffix = name:match("([^.]+)%.?(.*)")
  -- register redbean hook even without handler;
  -- this is needed to set up a handler later, as for some
  -- hooks redbean only checks before the main loop is started
  if not hooks[main] then
    hooks[main] = {}
    local orig = _G[main]
    _G[main] = function(...)
      if orig then orig() end
      return onHook(main, ...)
    end
  end
  local idx, val = findHook(main, suffix)
  local res = val and val[1]
  local isQualified = #suffix > 0
  if not func then
    -- remove the current hook if it's a fully qualified hook
    if isQualified then table.remove(hooks[main], idx) end
  else  -- set the new function
    local hook = {func, suffix}
    if idx and isQualified then  -- update existing qualified hook
      hooks[main][idx] = hook
    else  -- add a new one
      table.insert(hooks[main], hook)
    end
  end
  return res  -- return the old hook value (if any)
end

--[[-- scheduling engine --]]--

local function expand(min, max, vals)
  local tbl = {MIN = min, MAX = max, ['*'] = min.."-"..max}
  for i = min, max do
    tbl[i] = vals and vals[i] or ("%02d"):format(i)
  end
  for k, v in pairs(vals or {}) do tbl[v] = k end
  return tbl
end
local expressions = { expand(0,59), expand(0,23), expand(1,31),
  expand(1,12, {"jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec"}),
  expand(0,7, {[0]="sun","mon","tue","wed","thu","fri","sat","sun"}),
}
local function cron2hash(rec)
  local cronrec = {rec:lower():match("%s*(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s*")}
  local tbl = {{},{},{},{},{}}
  if #cronrec ~= #tbl then return nil, "invalid format" end
  for exppos, exps in ipairs(cronrec) do
    local map = expressions[exppos]
    for e in exps:gmatch("([^,]+)") do
      local exp = e:gsub("[^%d%-/]+", map)
      local min, rng, max, step = exp:match("^(%d+)(%-?)(%d*)/?(%d*)$")
      if not min then max, step = exp:match("^%-(%d+)/?(%d*)$") end
      if not min and not max then return nil, "invalid expression: "..e end
      min = math.max(map.MIN, tonumber(min) or map.MIN)
      max = math.min(map.MAX, tonumber(max) or #rng==0 and min or map.MAX)
      step = tonumber(step) or 1
      for i = min, max, step do tbl[exppos][map[i]] = true end
    end
  end
  return tbl
end

local schedules, lasttime = {}, 0
local scheduleHook = "OnServerHeartbeat.fm-setSchedule"
local function checkSchedule(time)
  local times = FormatHttpDateTime(time)
  local dow, dom, mon, h, m = times:lower():match("^(%S+), (%S+) (%S+) %S+ (%S+):(%S+):")
  for _, v in pairs(schedules) do
    local cront, func, sameproc = v[1], v[2], v[3]
    if cront[1][m] and cront[2][h] and cront[3][dom] and cront[4][mon] and cront[5][dow] then
      if sameproc or assert(unix.fork()) == 0 then
        local ok, err = pcall(func)
        if not ok then LogWarn("scheduled task failed: "..err) end
        if not sameproc then unix.exit(0) end
      end
    end
  end
end
local function scheduler()
  local time = math.floor(GetTime()/60)*60
  if time == lasttime then return else lasttime = time end
  checkSchedule(time)
end
local function setSchedule(exp, func, opts)
  if type(exp) == "table" then opts, exp, func = exp, unpack(exp) end
  opts = opts or {}
  argerror(type(opts) == "table", 3, "(table expected)")
  local res, err = cron2hash(exp)
  argerror(res ~= nil, 1, err)
  schedules[exp] = {res, func, opts.sameProc}
  if not setHook(scheduleHook, scheduler) then  -- first schedule hook
    if ProgramHeartbeatInterval then
      local min = 60*1000
      if ProgramHeartbeatInterval() > min then ProgramHeartbeatInterval(min) end
    else
      LogWarn("OnServerHeartbeat is required for setSchedule to work,"..
        " but may not be available; you need redbean v2.0.16+.")
    end
  end
end

--[[-- filters --]]--

local function makeLastModified(asset)
  argerror(type(asset) == "string", 1, "(string expected)")
  local lastModified = GetLastModifiedTime(asset)
  return {
    function(ifModifiedSince)
      local isModified = (not ifModifiedSince or
        ParseHttpDateTime(ifModifiedSince) < lastModified)
      if isModified then
        getRequest().headers.LastModified = FormatHttpDateTime(lastModified)
      end
      return isModified
    end,
    otherwise = 304,  -- serve 304 if not modified
  }
end

local trueval = function() return true end
local validators = { msg = trueval, optional = trueval,
  minlen = function(s, num) return #tostring(s or "") >= num, "%s is shorter than "..num.." chars" end,
  maxlen = function(s, num) return #tostring(s or "") <= num, "%s is longer than "..num.." chars" end,
  pattern = function(s, pat) return tostring(s or ""):match(pat), "invalid %s format" end,
  test = function(s, fun) return fun(s) end,
  oneof = function(s, list)
    if type(list) ~= "table" then list = {list} end
    for _, v in ipairs(list) do if s == v then return true end end
    return nil, "%s must be one of: "..table.concat(list, ", ")
  end,
}
local function makeValidator(rules)
  argerror(type(rules) == "table", 1, "(table expected)")
  for i, rule in ipairs(rules) do
    argerror(type(rule) == "table", 1, "(table expected at position "..i..")")
    argerror(type(rule[1]) == "string", 1, "(rule with name expected at position "..i..")")
    argerror(not rule.test or type(rule.test) == "function", 1, "(rule with test as function expected at position "..i..")")
  end
  return setmetatable({
      function(val)
        -- validator can be called in three ways:
        -- (1) directly with a params-like table passed
        -- (2) as a filter on an existing (scalar) field
        -- (3) as a filter on an non-existing field (to get request.params table)
        if val == nil then val = getRequest().params end  -- case (3)
        if type(val) ~= "table" and #rules > 0 then  -- case (2)
          -- convert the passed value into a hash based on the name in the first rule
          val = {[rules[1][1]] = val}
        end
        local errors = {}
        for _, rule in ipairs(rules) do repeat
          local param, err = rule[1], rule.msg
          local value = val[param]
          if value == nil and rule.optional == true then break end  -- continue
          for checkname, checkval in pairs(rule) do
            if type(checkname) == "string" then
              local validator = validators[checkname]
              if not validator then argerror(false, 1, "unknown validator "..checkname) end
              local success, msg = validator(value, checkval)
              if not success then
                local key = rules.key and param or #errors+1
                local errmsg = (err or msg or "%s check failed"):format(param)
                errors[key] = errors[key] or errmsg
                if not rules.all then
                  -- report an error as a single message, unless key is asked for
                  return nil, rules.key and errors or errmsg
                end
              end
            end
          end
        until true end
        if #errors > 0 or next(errors) then return nil, errors end
        return true
      end,
      otherwise = rules.otherwise,
      }, {__call = function(t, r) return t[1](r) end})
  end

--[[-- security --]]--

local function makeBasicAuth(authtable, opts)
  argerror(type(authtable) == "table", 1, "(table expected)")
  argerror(opts == nil or type(opts) == "table", 2, "(table expected)")
  opts = opts or {}
  local realm = opts.realm and (" Realm=%q"):format(opts.realm) or ""
  local hash, key = opts.hash, opts.key
  return {
    function(authorization)
      if not authorization then return false end
      local pass, user = GetPass(), GetUser()
      if not pass or not user or not authtable[user] then return false end
      if hash:upper() == "ARGON2" then return argon2.verify(authtable[user], pass) end
      return authtable[user] == (hash and GetCryptoHash(hash:upper(), pass, key) or pass)
    end,
    -- if authentication is not present or fails, return 401
    otherwise = serveResponse(401, {WWWAuthenticate = "Basic" .. realm}),
  }
end

local function makeIpMatcher(list)
  if type(list) == "string" then list = {list} end
  argerror(type(list) == "table", 1, "(table or string expected)")
  local subnets = {}
  for _, ip in ipairs(list) do
    local v, neg = ip:gsub("^!","")
    local addr, mask = v:match("^(%d+%.%d+%.%d+%.%d+)/(%d+)$")
    if not addr then addr, mask = v, 32 end
    addr = ParseIp(addr)
    argerror(addr ~= -1, 1, ("(invalid IP address %s)"):format(ip))
    mask = tonumber(mask)
    argerror(mask and mask >= 0 and mask <=32, 1, ("invalid mask in %s"):format(ip))
    mask = ~0 << (32 - mask)
    -- apply mask to addr in case addr/subnet is not properly aligned
    table.insert(subnets, {addr & mask, mask, neg > 0})
  end
  return function(ip)
    if ip == -1 then return false end -- fail the check on invalid IP
    for _, v in ipairs(subnets) do
      local match = v[1] == (ip & v[2])
      if match then return not v[3] end
    end
    return false
  end
end

--[[-- core engine --]]--

local function error2tmpl(status, reason, message)
  if not reason then reason = GetHttpReason(status) end
  SetStatus(status, reason) -- set status, but allow template handlers to overwrite it
  local ok, res = pcall(render, tostring(status),
    {status = status, reason = reason, message = message})
  if not ok and status ~= 500 and not res:find("unknown template name") then
    error(res)
  end
  return ok and res or ServeError(status, reason) or true
end
local function checkPath(path) return type(path) == "string" and path or GetPath() end
local fm = setmetatable({ _VERSION = VERSION, _NAME = NAME, _COPYRIGHT = "Paul Kulchenko",
  getBrand = function() return ("%s/%s %s/%s"):format("redbean", getRBVersion(), NAME, VERSION) end,
  setTemplate = setTemplate, setTemplateVar = setTemplateVar,
  setRoute = setRoute, setSchedule = setSchedule, setHook = setHook,
  makeStorage = makeStorage,
  makePath = makePath, makeUrl = makeUrl,
  makeBasicAuth = makeBasicAuth, makeIpMatcher = makeIpMatcher,
  makeLastModified = makeLastModified, makeValidator = makeValidator,
  getAsset = LoadAsset, getRequest = getRequest,
  render = render,
  -- options
  cookieOptions = {HttpOnly = true, SameSite = "Strict"},
  sessionOptions = {name = "fullmoon_session", hash = "SHA256", secret = true, format = "lua"},
  -- serve* methods that take path can be served as a route handler (with request passed)
  -- or as a method called from a route handler (with the path passed);
  -- serve index.lua or index.html if available; continue if not
  serveIndex = function(path) return function() return ServeIndex(checkPath(path)) end end,
  -- handle and serve existing path, including asset, Lua, folder/index, and pre-configured redirect
  servePath = function(path) return function() return RoutePath(checkPath(path)) end end,
  -- return asset (de/compressed) along with checking for asset range and last/not-modified
  serveAsset = function(path) return function() return ServeAsset(checkPath(path)) end end,
  serveError = function(status, reason, msg)
    return function() return error2tmpl(status, reason, msg) end
  end,
  serveContent = function(tmpl, params) return function() return render(tmpl, params) end end,
  serveRedirect = function(loc, status) return function()
      -- if no status or location is specified, then redirect to the original URL with 303
      -- this is useful for switching to GET after POST/PUT to an endpoint
      -- in all other cases, use the specified status or 307 (temp redirect)
      return ServeRedirect(status or loc and 307 or 303, loc or GetPath()) end end,
  serveResponse = serveResponse,
}, {__index =
  function(t, key)
    local function cache(f) t[key] = f return f end
    local method = key:match("^[A-Z][A-Z][A-Z]+$")
    if method then return cache(function(route)
        if type(route) == "string" then return {route, method = method} end
        argerror(type(route) == "table", 1, "(string or table expected)")
        route.method = method
        return route
      end)
    end
    -- handle serve204 and similar calls
    local serveStatus = key:match("^serve(%d%d%d)$")
    if serveStatus then return cache(t.serveError(tonumber(serveStatus))) end
    -- handle logVerbose and other log calls
    local kVal = not _G[key] and _G[key:gsub("^l(og%w*)$", function(name) return "kL"..name end)]
    if kVal then return cache(function(...) return Log(kVal, logFormat(...)) end) end
    -- return upper camel case version if exists
    return cache(_G[key] or _G[key:sub(1,1):upper()..key:sub(2)])
  end})

local isfresh = {} -- some unique key value
local function deleteCookie(name, copts)
  local maxage, MaxAge = copts.maxage, copts.MaxAge
  copts.maxage, copts.MaxAge = 0, nil
  SetCookie(name, "", copts)
  copts.maxage, copts.MaxAge = maxage, MaxAge
end
local function getSessionOptions()
  local sopts = fm.sessionOptions or {}
  if not sopts.name then error("missing session name") end
  if not sopts.hash then error("missing session hash") end
  if not sopts.format then error("missing session format") end
  -- check for session secret and hash
  if sopts.secret and type(sopts.secret) ~= "string" then
    error("sessionOptions.secret is expected to be a string")
  end
  return sopts
end
local function setSession(session)
  -- if the session hasn't been touched (read or updated), do nothing
  if session and session[isfresh] then return end
  local sopts = getSessionOptions()
  local cookie
  if session and next(session) then
    local msg = EncodeBase64(EncodeLua(session))
    local sig = EncodeBase64(
      GetCryptoHash(sopts.hash, msg, sopts.secret or ""))
    cookie = msg.."."..sopts.format.."."..sopts.hash.."."..sig
  end
  local copts = fm.cookieOptions or {}
  if cookie then
    SetCookie(sopts.name, cookie, copts)
  else
    fm.logDebug("delete session cookie")
    deleteCookie(sopts.name, copts)
  end
end
local function getSession()
  local sopts = getSessionOptions()
  local session = GetCookie(sopts.name)
  if not session then return {} end
  local msg, format, hash, sig = session:match("(.-)%.(.-)%.(.-)%.(.+)")
  if not msg then return {} end
  if not pcall(GetCryptoHash, hash, "") then
    LogWarn("invalid session crypto hash: "..hash)
    return {}
  end
  if DecodeBase64(sig) ~= GetCryptoHash(hash, msg, sopts.secret) then
    LogWarn("invalid session signature: "..sig)
    return {}
  end
  if format ~= "lua" then
    LogWarn("invalid session format: "..format)
    return {}
  end
  local ok, val = loadsafe("return "..DecodeBase64(msg))
  if not ok then LogWarn("invalid session content: "..val) end
  return ok and val or {}
end
local function setHeaders(headers)
  for name, value in pairs(headers or {}) do
    local val = tostring(value)
    if type(value) ~= "string" and type(value) ~= "number" then
      LogWarn("header '%s' is assigned non-string value '%s'", name, val)
    end
    local hname = headerMap[name] or name
    local noheader = noHeaderMap[hname:lower()]
    if not noheader or val:lower() == noheader then
      SetHeader(hname, val)
    else
      LogDebug("header '%s' with value '%s' is skipped to avoid conflict", name, val)
    end
  end
end
local function setCookies(cookies)
  local copts = fm.cookieOptions or {}
  for cname, cvalue in pairs(cookies or {}) do
    local value, opts = cvalue, copts
    if type(cvalue) == "table" then
      value, opts = cvalue[1], cvalue
    end
    if value == false then
      deleteCookie(cname, opts)
    else
      SetCookie(cname, value, opts)
    end
  end
end

-- call the handler and handle any Lua error by returning Server Error
local function hcall(func, ...)
  local co = type(func) == "thread" and func or coroutine.create(func)
  local ok, res, more = coroutine.resume(co, ...)
  if ok then
    return coroutine.status(co) == "suspended" and co or false, res, more
  end
  local err = debug.traceback(co, res)
  Log(kLogError, logFormat("Lua error: %s", err))
  return false, error2tmpl(500, nil, IsLoopbackIp(GetRemoteAddr()) and err or nil)
end
local function handleRequest(path)
  path = path or GetPath()
  req = setmetatable({
      params = setmetatable({}, {__index = function(_, k)
            if not HasParam(k) then return end
            -- GetParam may return `nil` for empty parameters,
            -- like `foo` in `foo&bar=1`, but need to return `false` instead
            if not string.find(k, "%[%]$") then return GetParam(k) or false end
            local array={}
            for _, v in ipairs(GetParams()) do
              if v[1] == k then table.insert(array, v[2] or false) end
            end
            return array
          end}),
      -- check headers table first to allow using `.ContentType` instead of `["Content-Type"]`
      headers = setmetatable({}, {__index = function(_, k) return GetHeader(headerMap[k] or k) end}),
      cookies = setmetatable({}, {__index = function(_, k) return GetCookie(k) end}),
      session = setmetatable({[isfresh] = true}, {
          __index = function(t, k)
            if t[isfresh] == true then t[isfresh] = getSession() end
            return t[isfresh] and t[isfresh][k]
          end,
          __newindex = function(t, k, v)
            if t[isfresh] then
              -- copy the already processed table if available
              req.session = type(t[isfresh]) == "table" and t[isfresh] or getSession()
            end
            req.session[k] = v
          end,
        }),
    }, tmplReqHandlerEnv)
  SetStatus(200) -- set default status; can be reset later
  -- find a match and handle any Lua errors in handlers
  local co, res, conttype = hcall(matchRoute, path, req)
  -- execute the (deferred) function and handle any errors
  while type(res) == "function" do co, res, conttype = hcall(res) end
  local tres = type(res)
  if res == true then
    -- do nothing, as this request was already handled
  elseif not res and not co then
    -- this request wasn't handled, so report 404
    return error2tmpl(404) -- use 404 template if available
  elseif tres == "string" then
    if #res > 0 then
      if not conttype then conttype = detectType(res) end
      Write(res) -- output content as is
    end
  elseif not co then
    LogWarn("unexpected result from action handler: '%s' (%s)", tostring(res), tres)
  end
  -- set the content type returned by the render
  if (type(conttype) == "string"
    and not rawget(req.headers or {}, "ContentType")) then
    req.headers.ContentType = conttype
  end
  -- set the headers as returned by the render
  if type(conttype) == "table" then
    if not req.headers then req.headers = {} end
    for name, value in pairs(conttype) do req.headers[name] = value end
  end
  setHeaders(req.headers) -- output specified headers
  setCookies(req.cookies) -- output specified cookies
  setSession(req.session) -- add a session cookie if needed
  while co do
    coroutine.yield()
    co, res = hcall(co)
    -- if the function is returned, which may happen if serve* is used
    -- as the last call, then process it to get its result
    while type(res) == "function" do co, res = hcall(res) end
    if type(res) == "string" then Write(res) end
  end
end

local function streamWrap(func)
  return function(...) return coroutine.yield(func(...)()) or true end
end
fm.streamResponse = streamWrap(fm.serveResponse)
fm.streamContent = streamWrap(fm.serveContent)

local tests -- forward declaration
local function run(opts)
  opts = opts or {}
  if opts.tests and tests then tests(); os.exit() end
  ProgramBrand(fm.getBrand())
  -- configure logPath first to capture all subsequent messages
  -- in the log file, as the order is randomized otherwise
  local logpath = opts.logPath or opts.LogPath
  if logpath then ProgramLogPath(logpath) end
  for key, v in pairs(opts) do
    if key == "headers" and type(v) == "table" then
      for h, val in pairs(v) do ProgramHeader(headerMap[h] or h, val) end
    elseif key:find("Options$") and type(v) == "table" then
      -- if *Options is assigned, then overwrite the provided default
      if fm[key] then
        fm[key] = opts[key]
      else -- if there is no default, it's some wrong option
        argerror(false, 1, ("(unknown option '%s')"):format(key))
      end
    else
      local name = "Program"..key:sub(1,1):upper()..key:sub(2)
      if name ~= "ProgramLogPath" then  -- this is already handled earlier
        local func = _G[name]
        argerror(type(func) == "function", 1,
          ("(unknown option '%s' with value '%s')"):format(key, v))
        for _, val in pairs(type(v) == "table" and v or {v}) do func(val) end
      end
    end
  end
  if GetLogLevel then
    local level, none = GetLogLevel(), function() end
    if level < kLogWarn then LogWarn = none end
    if level < kLogInfo then LogInfo = none end
    if level < kLogVerbose then LogVerbose = none end
    if level < kLogDebug then LogDebug = none end
  end
  LogInfo("started "..fm.getBrand())
  local sopts = fm.sessionOptions
  if sopts.secret == true then
    sopts.secret = GetRandomBytes(32)
    LogVerbose("applied random session secret; set `fm.sessionOptions.secret`"
      ..(" to `fm.decodeBase64('%s')` to continue using this value")
        :format(EncodeBase64(sopts.secret))
      .." or to `false` to disable")
  end
  -- assign Redbean handler to execute on each request
  OnHttpRequest = function() handleRequest(GetPath()) end

  collectgarbage() -- clean up no longer used memory to reduce image size
end

-- assign the rest of the methods
fm.run = run

Log = Log or function() end

fm.setTemplate("fmt", {
    parser = function (tmpl)
      local EOT = "\0"
      local function writer(s) return #s > 0 and ("Write(%q)"):format(s) or "" end
      local tupd = (tmpl.."{%"..EOT.."%}"):gsub("(.-){%%([=&]*)%s*(.-)%s*%%}", function(htm, pref, val)
          return writer(htm)
          ..(val ~= EOT -- this is not the suffix
            and (pref == "" -- this is a code fragment
              and val.." "
              or ("Write(%s(tostring(%s or '')))")
                :format(pref == "&" and "escapeHtml" or "", val))
            or "")
        end)
      return tupd
    end,
    function() end,
  })
fm.setTemplate("500", default500) -- register default 500 status template
fm.setTemplate("json", {ContentType = "application/json",
    function(val) return EncodeJson(val, {useoutput = true}) end})
fm.setTemplate("sse", function(val)
    argerror(type(val) == "table", 1, "(table expected)")
    if #val == 0 then val = {val} end
    for _, event in ipairs(val) do
      for etype, eval in pairs(event) do
        Write(("%s: %s\n"):format(
            etype == "comment" and "" or etype,
            etype == "data" and eval:gsub("\n", "\ndata: ") or eval
          ))
      end
      Write("\n")
    end
    return "", {
      ContentType = "text/event-stream",
      CacheControl = "no-store",
      ["X-Accel-Buffering"] = "no",
    }
  end)
fm.setTemplate("html", {
    parser = function(s)
      return ([[return render("html", %s)]]):format(s)
    end,
    function(val)
      argerror(type(val) == "table", 1, "(table expected)")
      local function writeAttrs(opt)
        for attrname, attrval in pairs(opt) do
          if type(attrname) == "string" then
            local valtype = type(attrval)
            local escape = not(valtype == "table" and attrval[1] == "raw")
            if valtype == "table" then
              -- this handles `_=raw"some<tag>"`
              if #attrval > 1 then
                attrval = attrval[2]
              else
                -- the following turns `tx={post="x", get="y"}`
                -- into `["tx-post"]="x", ["tx-get"]="y"`
                for k, v in pairs(attrval) do
                  if type(k) == "string" then
                    if escape then v = EscapeHtml(v) end
                    Write((' %s="%s"'):format(attrname.."-"..k, v))
                  end
                end
              end
            elseif attrval == true then
              -- this turns `checked=true` into `checked="checked"`
              attrval = attrname
            elseif attrval == false then
              -- write nothing here
            end
            if type(attrval) == "string" or type(attrval) == "number" then
              if escape then attrval = EscapeHtml(attrval) end
              Write((' %s="%s"'):format(attrname, attrval))
            end
          end
        end
      end
      local function writeVal(opt, escape)
        if type(opt) == "function" then opt = opt() end
        if type(opt) == "table" then
          local tag = opt[1]
          argerror(tag ~= nil, 1, "(tag name expected)")
          if tag == "include" then return(fm.render(opt[2], opt[3])) end
          if tag == "raw" then
            for i = 2, #opt do writeVal(opt[i], false) end
            return
          end
          if tag == "each" then
            -- rewrite messages to point to `each` function
            argerror(type(opt[2]) == "function", 1, "(function expected)", "each")
            argerror(type(opt[3]) == "table", 2, "(table expected)", "each")
            for _, v in ipairs(opt[3]) do writeVal(opt[2](v), false) end
            return
          end
          if tag:lower() == "doctype" then
            Write("<!"..tag.." "..(opt[2] or "html")..">")
            return
          end
          if getmetatable(opt) and not htmlVoidTags[tag:lower()] then
            LogWarn("rendering '%s' with `nil` value", tag)
            return
          end
          Write("<"..tag)
          writeAttrs(opt)
          if htmlVoidTags[tag:lower()] then Write("/>") return end
          Write(">")
          local escape = tag ~= "script"
          for i = 2, #opt do writeVal(opt[i], escape) end
          Write("</"..tag..">")
        else
          local val = tostring(opt or "")
          -- escape by default if not requested not to
          if escape ~= false then val = EscapeHtml(val) end
          Write(val)
        end
      end
      for _, v in pairs(val) do writeVal(v) end
    end,
  }, {autotag = true})

--[[-- various tests --]]--

tests = function()
  local out = ""
  reqenv.write = function(s) out = out..s end
  Write = reqenv.write

  local isRedbean = ProgramBrand ~= nil
  if not isRedbean then
    re = {compile = function(exp) return {search = function(self, path)
          local res = {path:match(exp)}
          if #res > 0 then table.insert(res, 1, path) end
          return unpack(res)
        end}
      end}
    EscapeHtml = function(s)
      return (string.gsub(s, "&", "&amp;"):gsub('"', "&quot;"):gsub("<","&lt;"):gsub(">","&gt;"):gsub("'","&#39;"))
    end
    FormatHttpDateTime = function(s) return os.date("%a, %d %b %Y %X GMT", s) end
    ParseIp = function(str)
      local v1, v2, v3, v4 = str:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
      return (v1 and (tonumber(v1) << 24) + (tonumber(v2) << 16) + (tonumber(v3) << 8) + tonumber(v4)
        or -1) -- match ParseIp logic in redbean
    end
    reqenv.escapeHtml = EscapeHtml
  end

  -- provide methods not available outside of Redbean or outside of request handling
  SetStatus = function() end
  SetHeader = function() end
  ServeError = function() end
  IsLoopbackIp = function() return true end
  GetRemoteAddr = function() end
  GetHttpReason = function(status) return tostring(status).." reason" end
  Log = function(_, ...) print("#", ...) end

  local num, success = 0, 0
  local section = ""
  local function outformat(s) return type(s) == "string" and ("%q"):format(s):gsub("\n","n") or tostring(s) end
  local function is(result, expected, message)
    local ok = result == expected
    num = num + 1
    success = success + (ok and 1 or 0)
    local msg = ("%s %d\t%s%s%s"):format((ok and "ok" or "not ok"), num,
      (section > "" and section.." " or ""), message or "",
      ok and "" or " at line "..debug.getinfo(2).currentline
    )
    if not ok then
      msg = msg .. ("\n\treceived: %s\n\texpected: %s"):format(outformat(result), outformat(expected))
    end
    print(msg)
    out = ""
  end
  local function rt(opt)
    local saved = {}
    for f, v in pairs(opt) do
      if type(f) == "string" then saved[f], _G[f] = _G[f], v end
    end
    for _, test in ipairs(opt) do test() end
    for f, v in pairs(saved) do _G[f] = v end
  end
  local function done() print(("1..%d # Passed %d/%d"):format(num, success, num)) end

  --[[-- template engine tests --]]--

  section = "(template)"
  local tmpl1 = "tmpl1"
  fm.setTemplate(tmpl1, "Hello, World!")
  fm.render(tmpl1)
  is(out, "Hello, World!", "text rendering")

  fm.setTemplate(tmpl1, "Hello, {%& title %}!")
  fm.render(tmpl1, {title = "World"})
  is(out, "Hello, World!", "text with parameter")

  fm.render(tmpl1, {title = "World&"})
  is(out, "Hello, World&amp;!", "text with encoded parameter")

  fm.render(tmpl1, {})
  is(out, "Hello, !", "text with missing enscaped parameter")

  fm.setTemplate(tmpl1, "Hello, {% for i, v in ipairs({3,2,1}) do %}-{%= v %}{% end %}")
  fm.render(tmpl1)
  is(out, "Hello, -3-2-1", "Lua code")

  local tmpl2 = "tmpl2"
  fm.setTemplate(tmpl2, [[{a: "{%= title %}"}]])
  fm.render(tmpl2)
  is(out, '{a: ""}', "JSON with missing non-escaped parameter")

  do
    fm.setTemplate(tmpl2, [[{a: "{%= title %}"}]], {title = "set when adding template"})
    fm.render(tmpl2)
    is(out, '{a: "set when adding template"}', "JSON with value set when adding template")

    fm.render(tmpl2, {title = "set from render"})
    is(out, '{a: "set from render"}', "JSON with a passed value set at rendering")

    fm.render(tmpl2)
    is(out, '{a: "set when adding template"}',
      "JSON with value set when adding template (after another assignment)")

    fm.setTemplate(tmpl2, [[{% local title = "set from template" %}{a: "{%= title %}"}]])
    fm.render(tmpl2)
    is(out, '{a: "set from template"}', "JSON with value set from template")

    fm.setTemplateVar("num", 123)
    fm.setTemplateVar("fun", function() return "abc" end)
    fm.setTemplate(tmpl2, "{%= vars.num %}{%= vars.fun() %}")
    fm.render(tmpl2)
    is(out, '123abc', "templates vars are set with numbers and functions")
  end

  fm.setTemplate(tmpl2, [[{a: "{%= title %}"}]], {title = "set when adding"})
  fm.setTemplate(tmpl1, "Hello, {% render('tmpl2') %}")
  fm.render(tmpl1)
  is(out, [[Hello, {a: "set when adding"}]], "`include` other template with a local value")

  fm.setTemplate(tmpl1, [[Hello, {% render('tmpl2', {title = "value"}) %}]])
  fm.render(tmpl1)
  is(out, [[Hello, {a: "value"}]], "`include` other template with passed value set at rendering")

  fm.setTemplate(tmpl1, "Hello, World!\n{% something.missing() %}")
  local ok, err = pcall(render, tmpl1)
  is(err ~= nil, true, "report Lua error in template")
  is(err:match('tmpl1:'), 'tmpl1:', "error references original template name")
  is(err:match(':2: '), ':2: ', "error references expected line number")

  fm.setTemplate(tmpl1, "{%if title then%}full{%else%}empty{%end%}")
  fm.render(tmpl1)
  is(out, "empty", "`if` checks for an empty parameter")

  fm.render(tmpl1, {title = ""})
  is(out, "full", "`if` checks for a non-empty parameter")

  fm.setTemplate(tmpl1, "Hello, {% main() %}World!", {main = function() end})
  fm.render(tmpl1)
  is(out, [[Hello, World!]], "used function can be passed when adding template")

  rt({
      GetZipPaths = function() return {"/views/hello1.fmt", "/views/hello2.fmg"} end,
      LoadAsset = function(s) return ({
          ["/views/hello1.fmt"] = "Hello, {%& title %}",
          ["/views/hello2.fmg"] = [[{ h1{"Hello, ", title} }]],
          ["/views/hello3.aaa"] = "Hello",
        })[s] end,
      function()
        local tmpls = fm.setTemplate({"/views/", fmt = "fmt", fmg = "html"})
        is(tmpls["hello1"], true, "setTemplate for a folder returns list of templates 1/2")
        is(tmpls["hello2"], true, "setTemplate for a folder returns list of templates 2/2")
        fm.render("hello1", {title = "value 1"})
        is(out, [[Hello, value 1]], "rendered default template loaded from an asset")
        fm.render("hello2", {title = "value 2"})
        is(out, [[<h1>Hello, value 2</h1>]], "rendered html generator template loaded from an asset")
        local _, err = pcall(render, "hello3")
        is(err:match("unknown template name"), "unknown template name", "only specified extensions loaded from an asset")

        fm.setTemplate({"/", fmt = "fmt", fmg = "html"})
        fm.render("views/hello1", {title = "value 1"})
        is(out, [[Hello, value 1]], "rendered default template loaded from an asset with folder name")
        fm.render("views/hello2", {title = "value 2"})
        is(out, [[<h1>Hello, value 2</h1>]], "rendered html generator template loaded from an asset with folder name")
      end,
    })

  --[[-- routing engine tests --]]--

  section = "(routing)"
  is(route2regex("/foo/bar"), "^/foo/bar$", "simple route")
  is(route2regex("/foo/:bar"), "^/foo/([^/]+)$", "route with a named parameter")
  is(route2regex("/foo/:bar_none/"), "^/foo/([^/]+)/$", "route with a named parameter with underscore")
  is(route2regex("/foo(/:bar)"), "^/foo(/([^/]+))?$", "route with a named optional parameter")
  is(route2regex("/foo/:bar[%d]"), "^/foo/([0-9]+)$", "route with a named parameter and a customer set")
  is(route2regex("/foo/:bar[^%d]"), "^/foo/([^0-9]+)$", "route with a named parameter and not-in-set")
  is(route2regex("/foo/:bar[]5]"), "^/foo/([]5]+)$", "route with a starting closing bracket in a set")
  is(route2regex("/foo/:bar[]5].:some"), "^/foo/([]5]+)\\.([^/]+)$", "route with a closing bracket in a set followed by another parameter")
  is(route2regex("/foo/:bar[^]5]"), "^/foo/([^]5]+)$", "route with a starting closing bracket in not-in-set")
  is(route2regex("/foo/:bar[1%]2%-%+]"), "^/foo/([1[.].]2[.-.]+]+)$", "route with a closed bracked")
  is(route2regex("/foo(/:bar(/:more))"), "^/foo(/([^/]+)(/([^/]+))?)?$", "route with two named optional parameters")
  is(route2regex("/foo(/:bar)/*.zip"), "^/foo(/([^/]+))?/(.*)\\.zip$", "route with an optional parameter and a splat")
  is(route2regex("/foo(/:bar)/*splat.zip"), "^/foo(/([^/]+))?/(.*)\\.zip$", "route with an optional parameter and a named splat")
  is(select(2, pcall(route2regex, "/foo/:bar[%o]")):match(": (.+)"), "Invalid escape sequence %o",
    "route with invalid sequence is reported")
  local _, params = route2regex("foo(/:bar)/*.zip")
  is(params[1], false, "'foo(/:bar)/*.zip' - parameter 1 is optional")
  is(params[2], "bar", "'foo(/:bar)/*.zip' - parameter 2 is 'bar'")
  is(params[3], "splat", "'foo(/:bar)/*.zip' - parameter 3 is 'splat'")

  local handler = function() end
  fm.setRoute("/foo/bar", handler)
  local index = routes["/foo/bar"]
  is(routes[index].handler, handler, "assign handler to a regular route")
  fm.setRoute("/foo/bar")
  is(routes["/foo/bar"], index, "route with the same name is not added")
  is(routes[routes["/foo/bar"]].handler, nil, "assign no handler to a static route")
  fm.setRoute(fm.PUT"/foo/bar")
  is(routes["/foo/bar"], index+1, "route with the same name and different method is added")

  local route = "/foo(/:bar(/:more[%d]))(.:ext)/*.zip"
  fm.setRoute(route, function(r)
      is(r.params.bar, "some", "[1/4] default optional parameter matches")
      is(r.params.more, "123", "[2/4] customer set matches")
      is(r.params.ext, "myext", "[3/4] optional extension matches")
      is(r.params.splat, "mo/re", "[4/4] splat matches path separators")
    end)
  matchRoute("/foo/some/123.myext/mo/re.zip", {params = {}})
  fm.setRoute(route, function(r)
      is(r.params.bar, "some.myext", "[1/4] default optional parameter matches dots")
      is(not r.params.more, true, "[2/4] missing optional parameter gets `false` value")
      is(not r.params.ext, true, "[3/4] missing optional parameter gets `false` value")
      is(r.params.splat, "more", "[4/4] splat matches")
    end)
  matchRoute("/foo/some.myext/more.zip", {params = {}})
  if isRedbean then
    local called = false
    fm.setRoute(route, function() called = true end)
    matchRoute("/foo/some.myext/more", {params = {}})
    is(called, false, "non-matching route handler is not called")
  end

  do
    local rp = RoutePath
    local gm = GetAssetMode

    GetAssetMode = function() return nil end

    local status
    SetStatus = function(s) status = s end
    fm.setRoute("/*path", "/asset/*path")
    handleRequest("/nofail") -- GetAssetMode returns `nil`
    is(status, 404, "Hanler doesn't fail on missing resource")

    GetAssetMode = function(m) return m:find("/$") and 2^14 or 2^15 end

    local path
    RoutePath = function(s) path = s; return s ~= nil end
    fm.setRoute("/*path", "/asset/*path")
    handleRequest("/")
    is(path, nil, "Directory is not returned for empty parameter with internal routing")

    fm.setRoute("/*path", "/*path.lua")
    -- confirm that forwarded existing path is returned
    RoutePath = function(s) path = s; return s ~= nil end
    handleRequest("/foo/some.myext/more")
    is(path, "/foo/some.myext/more.lua", "Forwarded path is returned for internal routing")

    -- confirm that 404 is returned if nothing is matched
    RoutePath = function() return false end
    handleRequest("/foo/some.myext/more")
    is(status, 404, "No match in forwarded path sets 404")

    fm.setRoute("/*path") -- remove the path from subsequent matching
    GetAssetMode = gm
    RoutePath = rp
  end

  is(headerMap.CacheControl, "Cache-Control", "Cache-Control header is mapped")
  is(headerMap.IfRange, "If-Range", "If-Range header is mapped")
  is(headerMap.Host, "Host", "Host header is mapped")
  is(headerMap.RetryAfter, "Retry-After", "Retry-After header is mapped")

  is(detectType("  <"), "text/html", "auto-detect html content")
  is(detectType("{"), "application/json", "auto-detect json content")
  is(detectType("abc"), "text/plain", "auto-detect text content")

  section = "(matchAttr)"

  is(matchCondition("GET", "GET"), true, "attribute matches based on simple value")
  is(matchCondition("GET", {GET = true}), true, "attribute matches based on simple value in condition table")
  is(matchCondition("GET", {}), false, "non-existing attribute doesn't match")
  is(matchCondition(nil, "GET"), false, "`nil` value doesn't match a simple value")
  is(matchCondition(nil, {GET = true}), true, "`nil` value matches a value in condition table")
  is(matchCondition("GET", {GET = true, POST = true}), true,
    "attribute matches based on simple value in condition table (among other values)")
  is(matchCondition("text/html; charset=utf-8", {regex = re.compile("text/")}), true, "attribute matches based on regex")
  is(matchCondition("text/html; charset=utf-8", {pattern = "%f[%w]text/html%f[%W]"}), true, "attribute matches based on Lua pattern")
  is(matchCondition("GET", "POST"), false, "attribute doesn't match another simple value")
  is(matchCondition("GET", {POST = true}), false, "attribute doesn't match if not present in condition table")
  is(matchCondition("text/html; charset=utf-8", {regex = re.compile("text/plain")}), false, "attribute doesn't match another regex")
  is(matchCondition(nil, function() return true end), true, "`nil` value matches function that return `true`")
  is(matchCondition(nil, function() return false end), false, "`nil` value doesn't match function that return `false`")
  is(matchCondition("GET", function() return true end), true, "attribute matches function that return `true`")
  is(matchCondition("GET", function() return false end), false, "attribute doesn't match function that return `false`")
  is(matchCondition("GET", {function() return true end}), true,
    "attribute matches function in condition table that return `true`")
  is(matchCondition("GET", {function() return false end}), false,
    "attribute doesn't match function in condition table that return `false`")

  fm.setRoute({"acceptencoding", AcceptEncoding = "gzip"})
  is(routes[routes.acceptencoding].options.AcceptEncoding.pattern, "%f[%w]gzip%f[%W]", "known header generates pattern-based match")

  is(rawget(fm, "GET"), nil, "GET doesn't exist before first use")
  local groute = fm.GET"route"
  is(rawget(fm, "GET"), fm.GET, "GET is cached after first use")
  is(type(groute), "table", "GET method returns condition table")
  is(groute.method, "GET", "GET method sets method")
  is(groute[1], "route", "GET method sets route")

  local proute = fm.POST{"route", more = "parameters"}
  is(type(proute), "table", "POST method on a table returns condition table")
  is(proute.method, "POST", "POST method on a table sets method")
  is(proute.more, "parameters", "POST method on a table preserves existing conditions")

  --[[-- schedule engine tests --]]--

  section = "(schedule)"
  do local res={}
    OnServerHeartbeat = function() res.hook = true end
    fm.setSchedule("* * * * *", function() res.everymin = true end, {sameProc = true})
    fm.setSchedule{"*/2 * * * *", function() res.everyothermin = true end, sameProc = true}
    fm.setHook("OnServerHeartbeat.testhook", function() res.hookcalls = true end)
    GetTime = function() return 1*60 end
    OnServerHeartbeat()
    is(res.everymin, true, "* is called on minute 1")
    is(res.everyothermin, nil, "*/2 is not called on minute 1")
    is(res.hook, true, "'original' hook is called as well")
    is(res.hookcalls, true, "setHook sets hook that is then called")
    res={}
    GetTime = function() return 2*60 end
    fm.setHook("OnServerHeartbeat.testhook")  -- remove hook
    OnServerHeartbeat()
    is(res.everymin, true, "* is called on minute 2")
    is(res.everyothermin, true, "*/2 is called on minute 2")
    is(res.hookcalls, nil, "setHook removes hook that is then not called")
  end

  --[[-- request tests --]]--

  -- headers processing (retrieve and set)
  GetHeader = function() return "text/plain" end
  GetPath = function() return "/" end
  EncodeJson = function() return "" end
  handleRequest("")
  local r = getRequest()
  is(r.headers.ContentType, "text/plain", "ContentType header retrieved")
  do local header, value
    SetHeader = function(h,v) header, value = h, v end

    fm.setRoute("/", function(r) r.headers.ContentLength = 42; return true end)
    handleRequest()
    is(value, nil, "Content-Length header is not allowed to be set")

    fm.setRoute("/", function(r) r.headers.ContentType = "text/plain"; return true end)
    handleRequest()
    is(header, "Content-Type", "Header is remaped to its full name")
    is(value, "text/plain", "Header is set to its correct value")

    fm.setRoute("/", function(r) r.headers.RetryAfter = 5; return true end)
    handleRequest()
    is(value, "5", "Header with numeric value is allowed to be set")

    fm.setTemplate(tmpl2, function() return "text", {foo = "bar"} end)
    fm.setRoute("/", fm.serveContent(tmpl2))
    handleRequest()
    is(out, 'text', "template returns text directly")
    is(header, 'foo', "template returns set of headers (name)")
    is(value, 'bar', "template returns set of headers (value)")

    fm.setRoute("/", fm.serveContent("sse", {data = "Line 1\nLine 2"}))
    handleRequest()
    is(out, "data: Line 1\ndata: Line 2\n\n", "SSE template with data element")

    fm.setTemplate(tmpl2, {[[{a: "{%= title %}"}]], ContentType = "application/json"})
    fm.setRoute("/", fm.serveContent(tmpl2))
    handleRequest()
    is(out, '{a: ""}', "JSON template with options and empty local value")
    is(header, 'Content-Type', "custom template with options sets Content-Type")
    is(value, 'application/json', "custom template with options sets expected Content-Type")

    fm.setRoute("/", function() return fm.serveContent("json", {}) end)
    handleRequest()
    is(header, 'Content-Type', "preset template with options sets Content-Type")
    is(value, 'application/json', "preset template with options sets expected Content-Type")

    fm.setRoute("/", fm.serveContent("html",
        {{"h1", "Title"}, {"div", a = 1, {"p", checked = true, "text"}}}))
    handleRequest()
    is(out, [[<h1>Title</h1><div a="1"><p checked="checked">text</p></div>]],
      "preset template with html generation")

    fm.setTemplate(tmpl1, {type = "html", [[{
            doctype, body{h1{title}, "<!>", raw"<!-- -->"},
            div{hx={post="url"}},
            {"script", "a<b"}, p"text",
            table{style=raw"b<a", tr{td"3", td"4", td{table.concat({1,2}, "")}}},
            table{"more"}, p{"1"..notitle}, br,
            each{function(v) return p{v} end, {3,2,1}},
            {"div", a = "\"1'", p{"text+", include{"tmpl2", {title = "T"}}}},
            {"iframe", function() return raw{p{1},p{2},p{3}} end},
          }]]})
    fm.setRoute("/", fm.serveContent(tmpl1, {title = "post title"}))
    handleRequest()
    is(out, "<!doctype html><body><h1>post title</h1>&lt;!&gt;<!-- --></body>"
      .."<div hx-post=\"url\"></div><script>a<b</script><p>text</p>"
      .."<table style=\"b<a\"><tr><td>3</td><td>4</td><td>12</td></tr></table>"
      .."<table>more</table><p>1</p><br/><p>3</p><p>2</p><p>1</p>"
      .."<div a=\"&quot;1&#39;\"><p>text+{a: \"T\"}</p></div>"
      .."<iframe><p>1</p><p>2</p><p>3</p></iframe>",
      "preset template with html generation")

    fm.setTemplate(tmpl1, fm.serveContent("html", {{"h1", "Title"}}))
    fm.setRoute("/", fm.serveContent(tmpl1))
    handleRequest()
    is(out, "<h1>Title</h1>")

    fm.setTemplate(tmpl1, {type = "html", [[{{"h1", title}}]]})
    fm.setRoute("/", fm.serveContent(tmpl1, {title = "post title"}))
    handleRequest()
    is(out, "<h1>post title</h1>")

    for k,v in pairs{text = "text/plain", ["{}"] = "application/json", ["<br>"] = "text/html"} do
      fm.setRoute("/", function() return k end)
      handleRequest()
      is(value, v, v.." value is auto-detected after being returned")

      fm.setRoute("/", fm.serveResponse(200, k))
      handleRequest()
      is(value, v, v.." value is auto-detected after serveResponse")
    end

    fm.setRoute("/", fm.serveResponse(200, {ContentType = "text/html"}, "text"))
    handleRequest()
    is(value, "text/html", "explicitly set content-type takes precedence over auto-detected one")

    fm.setRoute("/", fm.serveResponse("response text"))
    handleRequest()
    is(out, "response text", "serve response with text only")

    fm.setTemplate(tmpl2, {[[no content-type]]})
    fm.setRoute("/", fm.serveContent(tmpl2))
    value = nil
    handleRequest()
    is(value, nil, "template with no content-type doesn't set content type")

    local routeNum = #routes
    fm.setRoute({"/route1", "/route2", method = "GET", routeName = "routeOne"}, fm.serve404)
    is(routes["/route1"], routeNum+1, "mutiple routes can be added 1/2")
    is(routes["/route2"], routeNum+2, "mutiple routes can be added 2/2")
    is(routes.routeOne, routes["/route1"], "first route (our of several) gets name assigned")
  end

  -- cookie processing (retrieve and set)
  GetCookie = function() return "cookie value" end
  is(r.cookies.MyCookie, "cookie value", "Cookie value retrieved")
  do local cookie, value, options
    SetCookie = function(c,v,o)
      cookie, value, options = c, v, {}
      for k,v in pairs(o) do options[k] = v end
    end
    fm.setRoute("/", function(r) r.cookies.MyCookie = "new value"; return true end)
    handleRequest()
    is(cookie, "MyCookie", "Cookie is processed when set")
    is(value, "new value", "Cookie value is set")

    fm.setRoute("/", function(r) r.cookies.MyCookie = {"new value", secure = true}; return true end)
    handleRequest()
    is(value, "new value", "Cookie value is set (even with options)")
    is(options.secure, true, "Cookie option is set")

    fm.setRoute("/", function(r) r.cookies.MyCookie = false; return true end)
    handleRequest()
    is(cookie, "MyCookie", "Deleted cookie is processed when set to `false` (value)")
    is(value, "", "Deleted cookie gets empty value (value)")
    is(options.maxage, 0, "Deleted cookie gets MaxAge set to 0 (value)")

    fm.setRoute("/", function(r) r.cookies.MyCookie = {false, secure = true}; return true end)
    handleRequest()
    is(value, "", "Deleted cookie gets empty value (table)")
    is(options.maxage, 0, "Deleted cookie gets MaxAge set to 0 (table)")
    is(options.secure, true, "Deleted cookie gets option set (table)")

    if isRedbean then
      fm.sessionOptions.secret = ""
      setSession({a=""})
      is(cookie, "fullmoon_session")
      is(value, "e2E9IiJ9.lua.SHA256.AYDGTB6O7W4ohlbpRtgvY2NiDFUdS1efkd0ZpROoL+Q=")
    end
  end

  fm.setRoute("/", function(r)
      is(type(r.escapeHtml), "function", "escapeHtml function is available")
      is(type(r.escapePath), "function", "escapePath function is available")
      is(type(r.formatIp), "function", "formatIp function is available")
      is(type(r.formatHttpDateTime), "function", "formatHttpDateTime function is available")
    end)
  if isRedbean then handleRequest() end

  --[[-- makePath tests --]]--

  section = "(makePath)"
  route = "/foo(/:bar(/:more[%d]))(.:ext)/*.zip"
  do local rname
    LogWarn = function(_, n) rname = n end
    fm.setRoute({"/something/else", routeName = "foobar"})
    fm.setRoute({route, routeName = "foobar"})
    is(rname, "foobar", "duplicate route with the same routeName triggers warning")
  end
  is(routes.foobar, routes[route], "route name can be used as alias")
  is(routes[routes.foobar].routeName, nil, "route name is removed from conditions")

  _, err = pcall(fm.makePath, route)
  is(err:match("missing required parameter splat"), "missing required parameter splat", "required splat is checked")
  _, err = pcall(fm.makePath, "/foo/:bar")
  is(err:match("missing required parameter bar"), "missing required parameter bar", "required parameter is checked")
  is(fm.makePath(route, {splat = "name"}), "/foo/name.zip", "required splat is filled in")
  is(fm.makePath("/assets/*asset", {asset = false}), "/assets/", "empty splat is filled in")
  is(fm.makePath("/foo/*more/*splat.zip", {more = "some", splat = "name"}), "/foo/some/name.zip",
    "multiple required splats are filled in when specified")
  is(fm.makePath("/foo/*more/*.zip", {more = "some", splat = "name"}), "/foo/some/name.zip",
    "multiple required splats are filled in when under-specified")
  is(fm.makePath("foobar", {splat = "name"}), makePath(route, {splat = "name"}),
    "`makePath` by name and route produce same results")
  is(fm.makePath(route, {splat = "name", more = "foo"}), "/foo/name.zip",
    "missing optional parameter inside another missing parameter is removed")
  is(fm.makePath(route, {splat = "name", bar = "some"}), "/foo/some/name.zip", "single optional parameter is filled in")
  is(fm.makePath(route, {splat = "name", bar = "some", more = 12, ext = "json"}), "/foo/some/12.json/name.zip",
    "multiple optional parameters are filled in")
  is(fm.makePath("/foo/:bar", {bar = "more"}), "/foo/more", "unregistered route is handled")
  is(fm.makePath("/foo(/*.zip)"), "/foo", "optional splat is not required")
  is(fm.makePath("/foo(/*.zip)", {splat = "more"}), "/foo/more.zip", "optional splat is filled in")
  is(fm.makePath("/foo"), "/foo", "relative route generates absolute path")
  is(fm.makePath("/foo"), "/foo", "absolute route generates absolute path")

  is(fm.makePath("http://some.website.com:8080/:foo?param=:bar", {foo = "some", bar = 123}),
    "http://some.website.com:8080/some?param=123", "external/static path")

  -- test using makePath from a template
  fm.setTemplate(tmpl1, "Hello, {%= makePath('foobar', {splat = 'name'}) %}")
  fm.render(tmpl1)
  is(out, [[Hello, /foo/name.zip]], "`makePath` inside template")

  --[[-- makeUrl tests --]]--

  section = "(makeUrl)"
  if isRedbean then
    local url = "http://domain.com/path/more/name.ext?param1=val1&param2=val2#frag"
    GetUrl = function() return url end
    is(makeUrl(), url, "makeUrl produces original url")
    is(makeUrl({path = "/short"}), url:gsub("/path/more/name.ext", "/short"), "makeUrl uses path")
    is(makeUrl({scheme = "https"}), url:gsub("http:", "https:"), "makeUrl uses scheme")
    is(makeUrl({fragment = "newfrag"}), url:gsub("#frag", "#newfrag"), "makeUrl uses fragment")
    is(makeUrl({fragment = false}), url:gsub("#frag", ""), "makeUrl removes fragment")
    is(makeUrl("", {path = "/path", params = {{"a", 1}, {"b", 2}, {"c"}}}), "/path?a=1&b=2&c",
      "makeUrl generates path and query string")
    is(makeUrl("", {params = {a = 1, b = "", c = true, ["d[1][name]"] = "file" }}),
      "?a=1&b=&c&d%5B1%5D%5Bname%5D=file", "makeUrl generates query string from hash table")

    -- test using makeUrl from a template
    -- confirm that the URL is both url (%xx) and html (&...) escaped
    fm.setTemplate(tmpl1, "Hello, {%& makeUrl({path = '<some&/path>'}) %}")
    fm.render(tmpl1)
    is(out, [[Hello, http://domain.com/%3Csome&amp;/path%3E?param1=val1&amp;param2=val2#frag]],
      "`makeUrl` inside template")
  end

  --[[-- serve* tests --]]--

  local status
  SetStatus = function(s) status = s end
  local url = "/status"
  GetPath = function() return url end

  section = "(serveError)"
  fm.setRoute("/status", fm.serveError(403, "Access forbidden"))
  fm.setTemplate("403", "Server Error: {%& reason %}")
  local error403 = routes[routes["/status"]].handler()
  is(out, "Server Error: Access forbidden", "serveError used as a route handler")
  is(error403, "", "serveError finds registered template")

  fm.setRoute("/status", fm.serveError(405))
  handleRequest()
  is(status, 405, "direct serveError(405) sets expected status")

  fm.setRoute("/status", function() return fm.serveError(402) end)
  handleRequest()
  is(status, 402, "handler calling serveError(402) sets expected status")

  section = "(serveResponse)"
  is(rawget(fm, "serve401"), nil, "serve401 doesn't exist before first use")
  fm.setRoute("/status", fm.serve401)
  handleRequest()
  is(status, 401, "direct serve401 sets expected status")
  is(rawget(fm, "serve401"), fm.serve401, "serve401 is cached after first use")

  GetParam = function(key) return ({foo=123, bar=456})[key] end
  HasParam = function() return true end
  GetHeader = function() end
  GetMethod = function() return "GET" end

  fm.setRoute({"/statuserr", method = {"SOME", otherwise = 404}}, fm.serve402)
  handleRequest("/statuserr")
  is(status, 404, "not matched condition triggers configured otherwise processing")

  fm.setRoute({"/statuserr", method = {"SOME", otherwise = fm.serveResponse(405)}}, fm.serve402)
  handleRequest("/statuserr")
  is(status, 405, "not matched condition triggers dynamic otherwise processing")

  fm.setRoute({"/statusoth", method = "GET", otherwise = 404}, fm.serve402)
  handleRequest("/statusoth")
  is(status, 402, "`otherwise` value is not checked as filter value")

  GetMethod = function() return "HEAD" end
  fm.setRoute({"/statusget", method = {"GET", otherwise = 405}}, fm.serve402)
  handleRequest("/statusget")
  is(status, 402, "HEAD is accepted when GET is allowed")

  fm.setRoute({"/statusnohead", method = {"GET", HEAD = false, otherwise = 405}}, fm.serve402)
  handleRequest("/statusnohead")
  is(status, 405, "HEAD is not accepted when is explicitly disallowed")
  is(getRequest().headers.Allow, "GET, OPTIONS", "Allow header is returned along with 405 status")

  GetMethod = function() return "PUT" end
  fm.setRoute({"/statusput", method = "DELETE"}, fm.serve402)
  fm.setRoute({"/statusput", method = {"GET", "POST", otherwise = 405}}, fm.serve402)
  handleRequest("/statusput")
  is(getRequest().headers.Allow, "DELETE, GET, HEAD, POST, OPTIONS",
    "Allow header includes methods from all matched routes")

  GetMethod = function() return "PUT" end
  fm.setRoute({"/statusput", method = "DELETE"}) -- disable this route
  fm.setRoute({"/statusput", method = {"GET", "POST", otherwise = 405}}, fm.serve402)
  handleRequest("/statusput")
  is(getRequest().headers.Allow, "GET, HEAD, POST, OPTIONS", "Allow header includes HEAD when 405 status is returned")

  section = "(serveContent)"
  fm.setTemplate(tmpl1, "Hello, {%& title %}!")
  fm.setRoute("/content", fm.serveContent(tmpl1, {title = "World"}))
  routes[routes["/content"]].handler()
  is(out, "Hello, World!", "serveContent used as a route handler")

  do local status, loc
    section = "(serveRedirect)"
    ServeRedirect = function(s, l) status, loc = s, l end
    fm.setRoute("/content", fm.serveRedirect())
    routes[routes["/content"]].handler()
    is(status, 303, "serveRedirect without parameters sets 303 status")
    is(loc, GetPath(), "serveRedirect without parameters uses current path as location")
  end

  section = "(params)"
  url = "/params/789"

  fm.setTemplate(tmpl1, "{%= foo %}-{%= bar %}")
  fm.setRoute("/params/:bar", function(r)
      return fm.render(tmpl1, {foo = r.params.foo, bar = r.params.bar})
    end)
  handleRequest()
  is(out, "123-789", "route parameter takes precedence over URL parameter with the same name")

  fm.setTemplate(tmpl1, "-{%= baz %}-")
  fm.setRoute("/params/:bar", function(r)
      return fm.render(tmpl1, {baz = tostring(r.params.baz)})
    end)
  handleRequest()
  is(out, "-false-", "empty existing parameter returns `false`")

  HasParam = function() return true end
  GetParams = function()
    return {
      {"a[]", "10"},
      {"a[]"},
      {"a[]", "12"},
      {"a[]", ""},
    } end
  fm.setTemplate(tmpl1, "-{%= a[1]..(a[2] or 'false')..a[3]..a[4] %}-")
  fm.setRoute("/params/:bar", function(r)
      return fm.render(tmpl1, {a = r.params["a[]"]})
    end)
  handleRequest()
  is(out, "-10false12-", "parameters with [] are returned as array")

  --[[-- validator tests --]]--

  section = "(validator)"
  local validator = makeValidator{
    {"name", minlen=5, maxlen=64, },
    otherwise = function() end,
  }
  is(validator{name = "abcdef"}, true, "valid name is allowed")
  local res, msg = validator{params = {name = "a"}}
  is(res, nil, "minlen is checked")
  is(msg, "name is shorter than 5 chars", "minlen message is reported")
  is(validator{params = {name = ("a"):rep(100)}}, nil, "maxlen is checked")
  is(type(validator[1]), "function", "makeValidator returns table with a filter handler")
  is(type(validator.otherwise), "function", "makeValidator return table with an 'otherwise' handler")

  validator = fm.makeValidator{
    {"name", msg = "Invalid name format", minlen=5, maxlen=64, },
    {"pass", minlen=5, maxlen=64, },
    key = true,
    all = true,
  }
  res, msg = validator{params = {name = "a"}}
  is(type(msg), "table", "error messages reported in a table")
  is(msg.name, "Invalid name format", "error message is keyed on parameter name")
  is(msg.pass, "pass is shorter than 5 chars", "multiple error message are provided when `all=true` is set")

  validator = fm.makeValidator{
    {"name", msg="Invalid name format", minlen=5, maxlen=64, optional=true, },
    {"pass", msg="Invalid pass format", minlen=5, maxlen=64, optional=true, },
    key = true,
  }
  res = validator{name = "a"}
  is(res, nil, "validation fails for invalid optional parameters")
  res = validator{}
  is(res, true, "validation passes for missing optional parameters")
  res, err = validator"a"
  is(res, nil, "validation fails for invalid scalar parameters")
  is(err.name, "Invalid name format", "scalar parameters get their name from the first rule")

  res = {notcalled = true}
  fm.setRoute({"/params/:bar",
      _ = fm.makeValidator({{"bar", minlen = 5}, all = true,
          otherwise = function(errors) res.errors = errors end}),
    }, function() res.notcalled = false end)
  handleRequest()
  is(res.notcalled, true, "route action not executed after a failed validator check")
  is(type(res.errors), "table", "failed validator check triggers `otherwise` processing")
  is(res.errors[1], "bar is shorter than 5 chars", "`otherwise` processing gets the list of errors")

  --[[-- security tests --]]--

  section = "(security)"
  res = makeBasicAuth({user = "pass"})
  is(type(res[1]), "function", "makeBasicAuth returns table with a filter handler")
  is(type(res.otherwise), "function", "makeBasicAuth returns table with an 'otherwise' handler")

  local matcherTests = {
    {"0.0.0.0/0", "1.2.3.4", true},
    {"192.168.2.1", "192.168.2.1", true},
    {{"!192.168.2.1", "192.168.2.0/30"}, "192.168.2.1", false},
    {{"!192.168.2.1", "192.168.2.0/30"}, "192.168.3.1", false},
    {{"!192.168.2.1", "192.168.2.0/30"}, "192.168.2.2", true},
    {"192.168.2.0/32", "192.168.2.a", false},
    {"192.168.2.0/32", "192.168.2.1", false},
    {"192.168.2.0/24", "192.168.2.5", true},
    {"192.168.2.4/24", "192.168.2.5", true},
    {"10.10.20.0/30", "10.10.20.3", true},
    {"10.10.20.0/30", "10.10.20.5", false},
    {"10.10.20.4/30", "10.10.20.5", true},
  }
  for n, test in ipairs(matcherTests) do
    local mask, ip, res = unpack(test)
    is(makeIpMatcher(mask)(ParseIp(ip)), res,
      ("makeIpMatcher %s (%d/%d)"):format(ip, n, #matcherTests))
  end

  local privateMatcher = makeIpMatcher(
    {"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"})
  for val, res in pairs(
    {["192.168.0.1"] = true, ["172.16.0.1"] = true,
      ["10.0.0.1"] = true, ["100.1.1.1"] = false}) do
    local ip = ParseIp(val)
    is(privateMatcher(ip), res,
      ("makeIpMatcher for private ip %s"):format(val))
  end

  --[[-- redbean tests --]]--

  if isRedbean then
    section = "(log)"
    is(type(fm.logVerbose), "function", "logVerbose is a (dynamic) method")
    is(type(fm.logInfo), "function", "logInfo is a (dynamic) method")
    is(type(fm.kLogVerbose), "number", "kLogVerbose is a valid number")

    section = "(redbean)"
    is(type(fm.fetch), "function", "fetch function is available")
    is(type(fm.isLoopbackIp), "function", "isLoopbackIp function is available")
    is(type(fm.formatIp), "function", "formatIp function is available")
    is(type(fm.formatHttpDateTime), "function", "formatHttpDateTime function is available")
  end

  --[[-- DB management tests --]]--

  if isRedbean then
    section = "(makeStorage)"
    local script = [[
      create table test(key integer primary key, value text)
    ]]
    local dbm = fm.makeStorage(":memory:", script)
    local changes = dbm:upgrade()
    is(#changes, 0, "no changes from initial upgrade")
    changes = dbm:exec("insert into test values(1, 'abc')")
    is(changes, 1, "insert is successful")
    local row = dbm:fetchone("select key, value from test where key = 1")
    is(row.key, 1, "select fetches expected value 1/2")
    is(row.value, "abc", "select fetches expected value 2/2")
  end

  --[[-- run tests --]]--

  section = "(run)"
  local addr, brand, port, header, value = ""
  GetRedbeanVersion = function() return 0x020103 end
  ProgramBrand = function(b) brand = b end
  ProgramPort = function(p) port = p end
  ProgramAddr = function(a) addr = addr.."-"..a end
  ProgramHeader = function(h,v) header, value = h, v end
  fm.sessionOptions.secret = false -- disable secret message warning
  run{port = 8081, addr = {"abc", "def"}, headers = {RetryAfter = "bar"}}
  is(brand:match("redbean/[.%d]+"), "redbean/2.1.3", "brand captured server version")
  is(port, 8081, "port is set when passed")
  is(addr, "-abc-def", "multiple values are set from a table")
  is(header..":"..value, "Retry-After:bar", "default headers set when passed")

  ok, err = pcall(run, {cookieOptions = {}}) -- reset cookie options
  is(ok, true, "run accepts valid options")

  ok, err = pcall(run, {invalidOptions = {}}) -- some invalid option
  is(ok, false, "run fails on invalid options")
  is(err:match("unknown option"), "unknown option", "run reports unknown option")

  done()
end

-- run tests if launched as a script
if not pcall(debug.getlocal, 4, 1) then run{tests = true} end

-- return library if called with `require`
return fm
