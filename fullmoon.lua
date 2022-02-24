--
-- ultralight webframework for [Redbean web server](https://redbean.dev/)
-- Copyright 2021 Paul Kulchenko
-- 

local NAME, VERSION = "fullmoon", "0.21"

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
local function argerror(cond, narg, extramsg, name)
  name = name or debug.getinfo(2, "n").name or "?"
  local msg = ("bad argument #%d to %s%s"):format(narg, name, extramsg and " "..extramsg or  "")
  if not cond then error(msg, 3) end
  return cond, msg
end
local function logFormat(fmt, ...)
  return "(fm) "..(select('#', ...) == 0 and fmt or (fmt or ""):format(...))
end
local function getRBVersion()
  local v = GetRedbeanVersion()
  local major = math.floor(v / 2^16)
  return ("%d.%d"):format(major, math.floor((v / 2^16 - major) * 2^8))
end
local LogVerbose = function(...) return Log(kLogVerbose, logFormat(...)) end
local LogInfo = function(...) return Log(kLogInfo, logFormat(...)) end
local LogWarn = function(...) return Log(kLogWarn, logFormat(...)) end
local istype = function(b)
  return function(mode) return math.floor((mode % (2*b)) / b) == 1 end end
local isdirectory = istype(2^14)
local isregfile = istype(2^15)

-- request headers based on https://datatracker.ietf.org/doc/html/rfc7231#section-5
-- response headers based on https://datatracker.ietf.org/doc/html/rfc7231#section-7
-- this allows the user to use `.ContentType` instead of `["Content-Type"]`
-- Host is listed to allow retrieving Host header even in the presence of host attribute
local headers = {}
(function(s) for h in s:gmatch("[%w%-]+") do headers[h:gsub("-","")] = h end end)([[
  Cache-Control Host Max-Forwards Proxy-Authorization User-Agent
  Accept-Charset Accept-Encoding Accept-Language
  If-Match If-None-Match If-Modified-Since If-Unmodified-Since If-Range
  Content-Type Content-Encoding Content-Language Content-Location
  Retry-After Last-Modified WWW-Authenticate Proxy-Authenticate Accept-Ranges
]])
local htmlvoid = {} -- from https://html.spec.whatwg.org/#void-elements
(function(s) for h in s:gmatch("%w+") do htmlvoid[h] = true end end)([[
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
local reqenv = { write = Write,
  escapeHtml = EscapeHtml, escapePath = EscapePath,
  formatIp = FormatIp, formatHttpDateTime = FormatHttpDateTime,
  makePath = makePath, makeUrl = makeUrl, }
-- request properties (`request.authority`)
local reqapi = { authority = function()
    local parts = ParseUrl(GetUrl())
    return EncodeUrl({scheme = parts.scheme, host = parts.host, port = parts.port})
  end, }
local function genEnv(isTmplEnv)
  return function(t, key)
    local val = reqenv[key] or rawget(t, ref) and rawget(t, ref)[key]
    -- can cache the value, since it's not passed as a parameter
    local cancache = val == nil
    if val == nil then val = _G[key] end
    if not isTmplEnv and val == nil and type(key) == "string" then
      local func = reqapi[key] or _G["Get"..key:sub(1,1):upper()..key:sub(2)]
      -- map a property (like `.host`) to a function call (`.GetHost()`)
      if type(func) == "function" then val = func() else val = func end
    end
    -- allow pseudo-tags, but only if used in a template environment;
    -- provide fallback for `table` to make `table{}` and `table.concat` work
    local istable = key == "table"
    if isTmplEnv and (val == nil or istable) then
      -- nothing was resolved; this is either undefined value or
      -- a pseudo-tag (like `div{}` or `span{}`), so add support for them
      val = setmetatable({key}, {
          -- support the case of printing/concatenating undefined values
          __concat = function(a, b) return a end,
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
local templateHandlerEnv = {__index = genEnv(true) }
local requestHandlerEnv = {__index = genEnv(false) }
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
    return true, body and #body > 0 and detectType(body)
  end
end

--[[-- template engine --]]--

local templates = {}
local function render(name, opt)
  argerror(type(name) == "string", 1, "(string expected)")
  argerror(templates[name], 1, "(unknown template name '"..tostring(name).."')")
  argerror(not opt or type(opt) == "table", 2, "(table expected)")
  local params = {}
  local env = getfenv(templates[name].handler)
  -- add "original" template parameters
  for k, v in pairs(rawget(env, ref) or {}) do params[k] = v end
  -- add "passed" template parameters
  for k, v in pairs(opt or {}) do params[k] = v end
  Log(kLogInfo, logFormat("render template '%s'", name))
  -- return template results or an empty string to indicate completion
  -- this is useful when the template does direct write to the output buffer
  local refcopy = env[ref]
  env[ref] = params
  local res = templates[name].handler(opt) or ""
  env[ref] = refcopy
  return res, templates[name].ContentType
end

local function setTemplate(name, code, opt)
  -- name as a table designates a list of prefixes for assets paths
  -- to load templates from;
  -- its hash values provide mapping from extensions to template types
  if type(name) == "table" then
    for _, prefix in ipairs(name) do
      local paths = GetZipPaths(prefix)
      for _, path in ipairs(paths) do
        local tmplname, ext = path:gsub("^"..prefix.."/?",""):match("(.+)%.(%w+)$")
        if ext and name[ext] then
          setTemplate(tmplname, {type = name[ext], LoadAsset(path)})
        end
      end
    end
    return
  end
  argerror(type(name) == "string", 1, "(string or table expected)")
  local params = {}
  if type(code) == "table" then params, code = code, table.remove(code, 1) end
  local ctype = type(code)
  argerror(ctype == "string" or ctype == "function", 2, "(string, table or function expected)")
  LogVerbose("set template '%s'", name)
  if ctype == "string" then
    local tmpl = templates[params.type or "fmt"]
    argerror(tmpl ~= nil, 2, "(unknown template type/name)")
    argerror(tmpl.parser ~= nil, 2, "(referenced template doesn't have a parser)")
    code = assert(load(tmpl.parser(code), code))
  end
  local env = setmetatable({render = render, [ref] = opt}, templateHandlerEnv)
  params.handler = setfenv(code, env)
  templates[name] = params
end

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
  local s, e, capture = 0
  while true do
    s, e, capture = regex:find("%b()([?]?)", s+1)
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
      elseif headers[k] then
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
  LogVerbose("match %d route(s) against '%s'", #routes, path)
  local matchedRoutes = {}
  for idx, route in ipairs(routes) do
    -- skip static routes that are only used for path generation
    local opts = route.options
    if route.handler or opts and opts.otherwise then
      local res = {route.comp:search(path)}
      local matched = table.remove(res, 1)
      ;(matched and LogInfo or LogVerbose)
        ("route '%s' %smatched", route.route, matched and "" or "not ")
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
              local header = headers[filter]
              -- check "dashed" headers, params, properties (method, port, host, etc.), and then headers again
              local value = (header and req.headers[header]
                or req.params[filter] or req[filter] or req.headers[filter])
              -- condition can be a value (to compare with) or a table/hash with multiple values
              if not matchCondition(value, cond) then
                otherwise = type(cond) == "table" and cond.otherwise or opts.otherwise
                matched = false
                Log(kLogInfo, logFormat("route '%s' filter '%s' didn't match value '%s'%s",
                    route.route, filter, value, tonumber(otherwise) and " and returned "..otherwise or ""))
                break
              end
            end
          end
        end
        if matched and route.handler then
          local res, more = route.handler(req)
          if res then return res, more end
        else
          if otherwise then
            if type(otherwise) == "function" then
              return otherwise()
            else
              if otherwise == 405 and not req.headers.Allow then
                req.headers.Allow = getAllowedMethod(matchedRoutes)
              end
              return serveResponse(otherwise)
            end
          end
        end
      end
    end
  end
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
      return pass and user and authtable[user] == (
        hash and GetCryptoHash(hash:upper(), pass, key) or pass)
    end,
    -- if authentication is not present or fails, return 401
    otherwise = serveResponse(401, {WWWAuthenticate = "Basic" .. realm}),
  }
end

--[[-- core engine --]]--

local function error2tmpl(status, reason, message)
  if not reason then reason = GetHttpReason(status) end
  SetStatus(status, reason) -- set status, but allow template handlers to overwrite it
  local ok, res = pcall(render, tostring(status),
    {status = status, reason = reason, message = message})
  return ok and res or ServeError(status, reason) or true
end
-- call the handler and handle any Lua error by returning Server Error
local function hcall(func, ...)
  local ok, res, more = xpcall(func, debug.traceback, ...)
  if ok then return res, more end
  local err = res:gsub("\n[^\n]*in function 'xpcall'\n", "\n")
  Log(kLogError, logFormat("Lua error: %s", err))
  return error2tmpl(500, nil, IsLoopbackIp(GetRemoteAddr()) and err or nil)
end

local function handleRequest(path)
  path = path or GetPath()
  req = setmetatable({
      params = setmetatable({}, {__index = function(_, k)
            if not HasParam(k) then return end
            -- GetParam may return `nil` for empty parameters,
            -- like `foo` in `foo&bar=1`, but need to return `false` instead
            return GetParam(k) or false
          end}),
      -- check headers table first to allow using `.ContentType` instead of `["Content-Type"]`
      headers = setmetatable({}, {__index = function(_, k) return GetHeader(headers[k] or k) end}),
      cookies = setmetatable({}, {__index = function(_, k) return GetCookie(k) end}),
    }, requestHandlerEnv)
  SetStatus(200) -- set default status; can be reset later
  -- find a match and handle any Lua errors in handlers
  local res, conttype = hcall(matchRoute, path, req)
  -- execute the (deferred) function and handle any errors
  while type(res) == "function" do res, conttype = hcall(res) end
  local tres = type(res)
  if res == true then
    -- do nothing, as this request was already handled
  elseif not res then
    -- this request wasn't handled, so report 404
    return error2tmpl(404) -- use 404 template if available
  elseif tres == "string" then
    if #res > 0 then
      if not conttype then conttype = detectType(res) end
      Write(res) -- output content as is
    end
  else
    LogWarn("unexpected result from action handler: `%s` (%s)", tostring(res), tres)
  end
  -- set the content type returned by the render
  if conttype and not rawget(req.headers or {}, "ContentType") then
    req.headers.ContentType = conttype
  end
  -- output any headers and cookies that have been specified
  for name, value in pairs(req.headers or {}) do
    if type(value) ~= "string" then
      LogWarn("header '%s' is assigned non-string value '%s'", name, tostring(value))
    end
    SetHeader(headers[name] or name, tostring(value))
  end
  for name, value in pairs(req.cookies or {}) do
    if type(value) == "table" then
      SetCookie(name, value[1], value)
    else
      SetCookie(name, value)
    end
  end
end

local tests -- forward declaration
local function run(opt)
  opt = opt or {}
  if opt.tests and tests then tests(); os.exit() end
  ProgramBrand(("%s/%s %s/%s"):format("redbean", getRBVersion(), NAME, VERSION))
  for key, v in pairs(opt) do
    if key == "headers" and type(v) == "table" then
      for h, val in pairs(v) do ProgramHeader(headers[h] or h, val) end
    else
      local func = _G["Program"..key:sub(1,1):upper()..key:sub(2)]
      argerror(type(func) == "function", 1, ("(unknown option '%s' with value '%s')"):format(key, v))
      for _, val in pairs(type(v) == "table" and v or {v}) do func(val) end
    end
  end
  if GetLogLevel then
    local level, none = GetLogLevel(), function() end
    if level < kLogWarn then LogWarn = none end
    if level < kLogVerbose then LogVerbose = none end
    if level < kLogInfo then LogInfo = none end
  end
  -- assign Redbean handler to execute on each request
  OnHttpRequest = function() return handleRequest(GetPath()) end
end

local function checkPath(path) return type(path) == "string" and path or GetPath() end
local fm = setmetatable({ _VERSION = VERSION, _NAME = NAME, _COPYRIGHT = "Paul Kulchenko",
  setTemplate = setTemplate, setRoute = setRoute,
  makePath = makePath, makeUrl = makeUrl, makeBasicAuth = makeBasicAuth,
  getAsset = LoadAsset,
  run = run, render = render,
  -- serve* methods that take path can be served as a route handler (with request passed)
  -- or as a method called from a route handler (with the path passed);
  -- serve index.lua or index.html if available; continue if not
  serveIndex = function(path) return function() return ServeIndex(checkPath(path)) end end,
  -- handle and serve existing path, including asset, Lua, folder/index, and pre-configured redirect
  servePath = function(path) return function() return RoutePath(checkPath(path)) end end,
  -- return asset (de/compressed) along with checking for asset range and last/not-modified
  serveAsset = function(path) return function() return ServeAsset(checkPath(path)) end end,
  serveError = function(status, reason) return function() return error2tmpl(status, reason) end end,
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
    if serveStatus then return cache(t.serveResponse(tonumber(serveStatus))) end
    -- handle logVerbose and other log calls
    local kVal = _G[key:gsub("^l(og%w*)$", function(name) return "kL"..name end)]
    if kVal then return cache(function(...) return Log(kVal, logFormat(...)) end) end
    -- return upper camel case version if exists
    return cache(_G[key:sub(1,1):upper()..key:sub(2)])
  end})

Log = Log or function() end

fm.setTemplate("fmt", {
    parser = function (tmpl)
      local EOT = "\0"
      local function writer(s) return #s > 0 and ("write(%q)"):format(s) or "" end
      local tupd = (tmpl.."{%"..EOT.."%}"):gsub("(.-){%%([=&]*)%s*(.-)%s*%%}", function(htm, pref, val)
          return writer(htm)
          ..(val ~= EOT -- this is not the suffix
            and (pref == "" -- this is a code fragment
              and val.." "
              or ("write(%s(%s or ''))"):format(pref == "&" and "escapeHtml" or "", val))
            or "")
        end)
      return tupd
    end,
    function() end,
  })
fm.setTemplate("500", default500) -- register default 500 status template
fm.setTemplate("json", {ContentType = "application/json",
    function(val) return EncodeJson(val, {useoutput = true}) end})
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
          if tag == nil then argerror(false, 1, "(tag name expected)") end
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
          if getmetatable(opt) and not htmlvoid[tag:lower()] then
            LogWarn("rendering '%s' with `nil` value", tag)
            return
          end
          Write("<"..tag)
          writeAttrs(opt)
          if htmlvoid[tag:lower()] then Write("/>") return end
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
  })

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
    EscapeHtml = function(s) return (string.gsub(s, "&", "&amp;"):gsub('"', "&quot;"):gsub("<","&lt;"):gsub(">","&gt;"):gsub("'","&#39;")) end
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

  fm.setTemplate(tmpl1, "Hello, {% for i, v in ipairs({3,2,1}) do %}-{%= v %}{% end %}")
  fm.render(tmpl1)
  is(out, "Hello, -3-2-1", "Lua code")

  local tmpl2 = "tmpl2"
  fm.setTemplate(tmpl2, [[{a: "{%= title %}"}]])
  fm.render(tmpl2)
  is(out, '{a: ""}', "JSON with empty local value")

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
  end

  fm.setTemplate(tmpl2, [[{a: "{%= title %}"}]], {title = "set when adding"})
  fm.setTemplate(tmpl1, "Hello, {% render('tmpl2') %}")
  fm.render(tmpl1)
  is(out, [[Hello, {a: "set when adding"}]], "`include` other template with a local value")

  fm.setTemplate(tmpl1, [[Hello, {% render('tmpl2', {title = "value"}) %}]])
  fm.render(tmpl1)
  is(out, [[Hello, {a: "value"}]], "`include` other template with passed value set at rendering")

  fm.setTemplate(tmpl1, "Hello, World!\n{% something.missing() %}")
  local _, err = pcall(render, tmpl1)
  is(err ~= nil, true, "report Lua error in template")
  is(err:match('string "Hello, World!'), 'string "Hello, World!', "error references original template code")
  is(err:match(':2: '), ':2: ', "error references expected line number")

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
        fm.setTemplate({"/views/", fmt = "fmt", fmg = "html"})
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

    GetAssetMode = function(m) return nil end

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

  is(headers.CacheControl, "Cache-Control", "Cache-Control header is mapped")
  is(headers.IfRange, "If-Range", "If-Range header is mapped")
  is(headers.Host, "Host", "Host header is mapped")
  is(headers.RetryAfter, "Retry-After", "Retry-After header is mapped")

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
    fm.setRoute("/", function(r) r.headers.ContentType = "text/plain"; return true end)
    handleRequest()
    is(header, "Content-Type", "Header is remaped to its full name")
    is(value, "text/plain", "Header is set to its correct value")

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
            table{"more"}, p{notitle.noval}, br,
            each{function(v) return p{v} end, {3,2,1}},
            {"div", a = "\"1'", p{"text+", include{"tmpl2", {title = "T"}}}},
            {"iframe", function() return raw{p{1},p{2},p{3}} end},
          }]]})
    fm.setRoute("/", fm.serveContent(tmpl1, {title = "post title"}))
    handleRequest()
    is(out, "<!doctype html><body><h1>post title</h1>&lt;!&gt;<!-- --></body>"
      .."<div hx-post=\"url\"></div><script>a<b</script><p>text</p>"
      .."<table style=\"b<a\"><tr><td>3</td><td>4</td><td>12</td></tr></table>"
      .."<table>more</table><p></p><br/><p>3</p><p>2</p><p>1</p>"
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
    SetCookie = function(c,v,o) cookie, value, options = c, v, o end
    fm.setRoute("/", function(r) r.cookies.MyCookie = "new value"; return true end)
    handleRequest()
    is(cookie, "MyCookie", "Cookie is processed when set")
    is(value, "new value", "Cookie value is set")

    fm.setRoute("/", function(r) r.cookies.MyCookie = {"new value", secure = true}; return true end)
    handleRequest()
    is(value, "new value", "Cookie value is set (even with options)")
    is(options.secure, true, "Cookie option is set")
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
    is(makeUrl("", {params = {a = 1, b = 2, c = true, ["d[1][name]"] = "file" }}),
      "?a=1&b=2&c&d%5B1%5D%5Bname%5D=file", "makeUrl generates query string from hash table")

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

  --[[-- security tests --]]--

  section = "(security)"
  local res = makeBasicAuth({user = "pass"})
  is(type(res[1]), "function", "makeBasicAuth returns table with a filter handler")
  is(type(res.otherwise), "function", "makeBasicAuth returns table with a 'otherwise' handler")

  --[[-- redbean tests --]]--

  if isRedbean then
    section = "(log)"
    is(type(fm.logVerbose), "function", "logVerbose is a (dynamic) method")
    is(type(fm.logInfo), "function", "logInfo is a (dynamic) method")

    section = "(redbean)"
    is(type(fm.fetch), "function", "fetch function is available")
    is(type(fm.isLoopbackIp), "function", "isLoopbackIp function is available")
    is(type(fm.formatIp), "function", "formatIp function is available")
    is(type(fm.formatHttpDateTime), "function", "formatHttpDateTime function is available")
  end

  --[[-- run tests --]]--

  section = "(run)"
  local addr, brand, port, header, value = ""
  GetRedbeanVersion = function() return 0x010000 end
  ProgramBrand = function(b) brand = b end
  ProgramPort = function(p) port = p end
  ProgramAddr = function(a) addr = addr.."-"..a end
  ProgramHeader = function(h,v) header, value = h, v end
  run({port = 8081, addr = {"abc", "def"}, headers = {RetryAfter = "bar"}})
  is(brand:match("redbean/[.%d]+"), "redbean/1.0", "brand captured server version")
  is(port, 8081, "port is set when passed")
  is(addr, "-abc-def", "multiple values are set from a table")
  is(header..":"..value, "Retry-After:bar", "default headers set when passed")

  done()
end

-- run tests if launched as a script
if not pcall(debug.getlocal, 4, 1) then run{tests = true} end

-- return library if called with `require`
return fm
