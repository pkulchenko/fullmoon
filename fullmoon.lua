--
-- ultralight webframework for [Redbean web server](https://redbean.dev/)
-- Copyright 2021-23 Paul Kulchenko
--

local NAME, VERSION = "fullmoon", "0.377"

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
  getfenv = function (f)
    -- if the function is not provided, use the caller
    return(select(2, findenv(f or debug.getinfo(2,"f").func)) or _G)
  end
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
  if cond then return cond end
  name = name or debug.getinfo(2, "n").name or "?"
  local msg = ("bad argument #%d to %s%s"):format(narg, name, extramsg and " "..extramsg or  "")
  return error(msg, 3)
end
local function logFormat(fmt, ...)
  argerror(type(fmt) == "string", 1, "(string expected)")
  return "(fm) "..(select('#', ...) == 0 and fmt or (fmt or ""):format(...))
end
local function quote(s) return s:gsub('([%(%)%.%%%+%-%*%?%[%^%$%]])','%%%1') end
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
local function reg(func, v)
  local t = {n = 1,
    x2 = function(t, v) t[v] = t.n; t.n = t.n * 2 end,
    p1 = function(t, v) t[v] = t.n; t.n = t.n + 1 end,
  }
  for _, p in ipairs(v) do t[func](t, p) end
  return t
end
local function reg2x(v) return reg("x2", v) end
local function reg1p(v) return reg("p1", v) end
local getTimeNano = (unix
  and function() return {unix.clock_gettime()} end
  or function() return {GetTime(), 0} end)
local function getTimeDiff(st, et)
  if not et then et = getTimeNano() end
  return et[1] - st[1] + (et[2] - st[2]) * 1e-9
end
local function obsolete(obj, old, new, ver)
  obj[old] = VERSION < ver and function(...)
    LogWarn(("method %s has been replaced by %s and will be removed in v%s.")
      :format(old, new, ver))
    obj[old] = obj[new]
    return obj[new](...)
  end or nil
end

-- headers that are not allowed to be set, as Redbean may
-- also set them, leading to conflicts and improper handling
local noHeaderMap = {
  ["content-length"] = true,
  ["transfer-encoding"] = true,
  ["content-encoding"] = true,
  date = true,
  -- "close" is the only value that is allowed for "Connection",
  -- but only in Redbean before v2.2
  connection = GetRedbeanVersion() < 0x20200 and "close" or nil,
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

local org, ref = {}, {} -- some unique key values to index template parameters
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

--[[-- multipart parsing --]]--

local patts = {}
local function getParameter(header, name)
  local function optignorecase(s)
    if not patts[s] then
      patts[s] = (";%s*"
        ..s:gsub("%w", function(s) return ("[%s%s]"):format(s:upper(), s:lower()) end)
        ..[[=["']?([^;"']*)["']?]])
    end
    return patts[s]
  end
  return header:match(optignorecase(name))
end
local CRLF, TAIL = "\r\n", "--"
local CRLFlen = #CRLF
local MULTIVAL = "%[%]$"
local function parseMultipart(body, ctype)
  argerror(type(ctype) == "string", 2, "(string expected)")
  local parts = {
    boundary = getParameter(ctype, "boundary"),
    start = getParameter(ctype, "start"),
  }
  local boundary = "--"..argerror(parts.boundary, 2, "(boundary expected in Content-Type)")
  local bol, eol, eob = 1
  while true do
    repeat
      eol, eob = string.find(body, boundary, bol, true)
      if not eol then return nil, "missing expected boundary at position "..bol end
    until eol == 1 or eol > CRLFlen and body:sub(eol-CRLFlen, eol-1) == CRLF
    if eol > CRLFlen then eol = eol - CRLFlen end
    local headers, name, filename = {}
    if bol > 1 then
      -- find the header (if any)
      if string.sub(body, bol, bol+CRLFlen-1) == CRLF then -- no headers
        bol = bol + CRLFlen
      else -- headers
        -- find the end of headers (CRLF+CRLF)
        local boh, eoh = 1, string.find(body, CRLF..CRLF, bol, true)
        if not eoh then return nil, "missing expected end of headers at position "..bol end
        -- join multi-line header values back if present
        local head = string.sub(body, bol, eoh+1):gsub(CRLF.."%s+", " ")
        while (string.find(head, CRLF, boh, true) or 0) > boh do
          local p, e, header, value = head:find("([^:]+)%s*:%s*(.-)%s*\r\n", boh)
          if p ~= boh then return nil, "invalid header syntax at position "..bol+boh end
          header = header:lower()
          if header == "content-disposition" then
            name = getParameter(value, "name")
            filename = getParameter(value, "filename")
          end
          headers[header] = value
          boh = e + 1
        end
        bol = eoh + CRLFlen*2
      end
      -- epilogue is processed, but not returned
      local ct = headers["content-type"]
      local b, err = string.sub(body, bol, eol-1)
      if ct and ct:lower():find("^multipart/") then
        b, err = parseMultipart(b, ct) -- handle multipart/* recursively
        if not b then return b, err end
      end
      local first = parts.start and parts.start == headers["content-id"] and 1
      local v = {name = name, headers = headers, filename = filename, data = b}
      table.insert(parts, first or #parts+1, v)
      if name then
        if string.find(name, MULTIVAL) then
          parts[name] = parts[name] or {}
          table.insert(parts[name], first or #parts[name]+1, v)
        else
          parts[name] = parts[name] or v
        end
      end
    end
    local tail = body:sub(eob+1, eob+#TAIL)
    -- check if the encapsulation or regular boundary is present
    if tail == TAIL then break end
    if tail ~= CRLF then return nil, "missing closing boundary at position "..eol end
    bol = eob + #tail + 1
  end
  return parts
end

--[[-- template engine --]]--

local templates, vars = {}, {}
local stack, blocks = {}, {}
-- `blocks` is a table behind proxy tables indexed by actual `block` tables in each template
-- where the values are defined blocks and their functions
-- blocks are retrieved in the order in which templates are rendered
-- (first called is first used), as stored in `stack` during rendering.
-- the `stack` table also includes mapping from template names to their proxy tables
local metablock = {
  __newindex = function(t, k, v)
    if not blocks[t] then
      blocks[t] = {}
      stack[t[blocks]] = blocks[t]
    end
    blocks[t][k] = v
  end,
  __index = function(t, k)
    if not blocks[t] then
      blocks[t] = {}
      stack[t[blocks]] = blocks[t]
    end
    -- use the "earliest" template after the one signified with `t`
    for _, name in ipairs(stack) do
      -- if a template name is requested, then return its table
      -- this is needed for direct access to template blocks to simulate `super()`
      local tbl = stack[name]
      -- don't look beyond the template that made this call
      if name == k then return tbl end
      local blk = name and tbl and tbl[k]
      if blk then return blk end
    end
  end,
}
local function render(name, opt)
  argerror(type(name) == "string", 1, "(string expected)")
  argerror(templates[name], 1, "(unknown template name '"..tostring(name).."')")
  argerror(not opt or type(opt) == "table", 2, "(table expected)")
  -- assign default parameters, but allow to overwrite
  local params = {vars = vars, block = setmetatable({[blocks] = name}, metablock)}
  local env = getfenv(templates[name].handler)
  -- add "original" template parameters
  for k, v in pairs(rawget(env, org) or {}) do params[k] = v end
  -- add "passed" template parameters
  for k, v in pairs(opt or {}) do params[k] = v end
  LogDebug("render template '%s'", name)
  env[ref] = params
  table.insert(stack, name)
  local res, more = templates[name].handler(opt)
  table.remove(stack)
  -- reset block cache when the render stack becomes empty
  if #stack == 0 then stack, blocks = {}, {} end
  -- return template results or an empty string to indicate completion
  -- this is useful when the template does direct write to the output buffer
  return res or "", more or {ContentType = templates[name].ContentType}
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
          local asset = LoadAsset(path) or error("Can't load asset: "..path)
          setTemplate(tmplname, {asset, type = name[ext], path = path}, opt)
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
  local env = setmetatable({render = render, [org] = opt},
    -- get the metatable from the template that this one is based on,
    -- to make sure the correct environment is being served
    tmpl and getmetatable(getfenv(tmpl.handler)) or
    params.autotag and tmplTagHandlerEnv or tmplRegHandlerEnv)
  if ctype == "string" then
    argerror(tmpl ~= nil, 2, "(unknown template type/name)")
    argerror(tmpl.parser ~= nil, 2, "(referenced template doesn't have a parser)")
    local path = "@" .. (params.path or name)
    -- assign proper environment in case parser needs it
    if tmpl.autotag then tmpl.parser = setfenv(tmpl.parser, env) end
    local func = tmpl.parser(code, path)
    -- if the parser returns function, use it as is
    -- if it returns some code, then load and use it
    code = type(func) == "function" and func or assert(load(func, path))
  end
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
        opts[k] = {pattern = "%f[%w]"..quote(v).."%f[%W]"}
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
          path = rawget(req, "path") or path  -- assign path for subsequent checks
        end
      end
    end
  end
end

--[[-- storage engine --]]--

local NONE = {}
local function makeStorage(dbname, sqlsetup, opts)
  local sqlite3 = require "lsqlite3"
  if type(sqlsetup) == "table" and opts == nil then
    sqlsetup, opts = nil, sqlsetup
  end
  local flags = 0
  for flagname, val in pairs(opts or {}) do
    local flagcode = flagname:find("^OPEN_") and (
      sqlite3[flagname] or error("unknown option "..flagname))
    flags = flags | (val and flagcode or 0)
  end
  argerror(not opts or not opts.trace or type(opts.trace) == "function",
    3 , "(function expected as trace option value)")
  -- check if any of the required flags are set; set defaults if not
  if flags & (sqlite3.OPEN_READWRITE + sqlite3.OPEN_READONLY) == 0 then
    flags = flags | (sqlite3.OPEN_READWRITE + sqlite3.OPEN_CREATE)
  end
  local dbm = {NONE = NONE, prepcache = {}, pragmas = {},
    name = dbname, sql = sqlsetup, opts = opts or {}}
  local msgdelete = "use delete option to force"

  function dbm:init()
    local db = self.db
    if not db then
      local code, msg
      db, code, msg = sqlite3.open(self.name, flags)
      if not db then error(("%s (code: %d)"):format(msg, code)) end
      if self.sql and db:exec(self.sql) > 0 then error("can't setup db: "..db:errmsg()) end
      self.db = db
    end
    -- simple __index = db doesn't work, as it gets `dbm` passed instead of `db`,
    -- so remapping is needed to proxy this to `t.db` instead
    return setmetatable(self, {
      __index = function(t,k)
          if sqlite3[k] then return sqlite3[k] end
          local db = rawget(t, "db")
          return db and db[k] and function(self,...) return db[k](db,...) end or nil
      end,
      __close = function(t) return t:close() end
    })
  end
  local function norm(sql)
    return (sql:gsub("%-%-[^\n]*\n?",""):gsub("^%s+",""):gsub("%s+$",""):gsub("%s+"," ")
      :gsub("%s*([(),])%s*","%1"):gsub('"(%w+)"',"%1"))
  end
  local function prepstmt(dbm, stmt)
    if not dbm.prepcache[stmt] then
      assert(dbm.db)
      local st, tail = dbm.db:prepare(stmt)
      -- if there is tail, then return as is, don't cache
      if st and tail and #tail > 0 then return st, tail end
      dbm.prepcache[stmt] = st
    end
    return dbm.prepcache[stmt]
  end
  function dbm:close()
    if self.db then return self.db:close() end
  end
  local function fetch(self, query, one, ...)
    if not self.db then self:init() end
    local trace = self.opts.trace
    local start = trace and getTimeNano()
    local rows = {}
    local stmt, tail = query, nil
    repeat
      if type(stmt) == "string" then
        stmt, tail = prepstmt(self, stmt)
      end
      if not stmt then return nil, "can't prepare: "..self.db:errmsg() end
      -- if the last statement is incomplete
      if not stmt:isopen() then break end
      if stmt:bind_values(...) > 0 then
        return nil, "can't bind values: "..self.db:errmsg()
      end
      for row in stmt:nrows() do
        table.insert(rows, row)
        if one then break end
      end
      stmt:reset()
      stmt = tail  -- get multi-statement ready for processing
    until (one or not tail)
    if trace then trace(self, query, {...}, getTimeDiff(start)) end
    if one == nil then return self.db:changes() end  -- return execute results
    -- return self.NONE instead of an empty table to indicate no rows
    return not one and (rows[1] and rows or self.NONE) or rows[1] or self.NONE
  end
  local function exec(self, stmt, ...) return fetch(self, stmt, nil, ...) end
  local function dberr(db) return nil, db:errmsg() end
  function dbm:execute(list, ...)
    -- if the first parameter is not table, use regular exec
    if type(list) ~= "table" then return exec(self, list, ...) end
    if not self.db then self:init() end
    local db = self.db
    local changes = 0
    if db:exec("savepoint execute") ~= sqlite3.OK then return dberr(db) end
    for _, sql in ipairs(list) do
      if type(sql) ~= "table" then sql = {sql} end
      local ok, err = exec(self, unpack(sql))
      if not ok then
        if db:exec("rollback to execute") ~= sqlite3.OK then return dberr(db) end
        return nil, err
      end
      changes = changes + ok
    end
    if db:exec("release execute") ~= sqlite3.OK then return dberr(db) end
    return changes
  end
  function dbm:fetchAll(stmt, ...) return fetch(dbm, stmt, false, ...) end
  function dbm:fetchOne(stmt, ...) return fetch(dbm, stmt, true, ...) end
  function dbm:pragma(stmt)
    local pragma = stmt:match("[_%w]+")
    if not self.pragmas[pragma] then
      if self:fetchOne("select * from pragma_pragma_list() where name = ?",
        pragma or "") == self.NONE then return nil, "missing or invalid pragma name" end
      self.pragmas[pragma] = true
    end
    local row = self:fetchOne("PRAGMA "..stmt)
    if not row then return nil, self.db:errmsg() end
    return select(2, next(row)) or self.NONE
  end
  obsolete(dbm, "fetchone", "fetchOne", "0.40")
  obsolete(dbm, "fetchall", "fetchAll", "0.40")

  --[[-- dbm upgrade --]]--

  function dbm:upgrade(opts)
    opts = opts or {}
    local actual = self.db and self or error("can't ungrade non initialized db")
    local pristine = makeStorage(":memory:", self.sql)
    local sqltbl = [[SELECT name, sql FROM sqlite_schema
      WHERE type = 'table' AND name not like 'sqlite_%']]
    local ok, err
    local changes, legacyalter = {}, false
    local actbl, prtbl = {}, {}
    for r in pristine:nrows(sqltbl) do prtbl[r.name] = r.sql end
    for r in actual:nrows(sqltbl) do
      actbl[r.name] = true
      if prtbl[r.name] then
        if norm(r.sql) ~= norm(prtbl[r.name]) then
          local namepatt = '%f[^%s"]'..r.name:gsub("%p","%%%1")..'%f[%s"(]'
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
              err = err or ("Not allowed to remove '%s' from '%s'; %s"
                ):format(c.name, r.name, msgdelete)
            end
          end
          local cols = table.concat(common, ",")
          table.insert(changes, ("INSERT INTO %s (%s) SELECT %s FROM %s")
            :format(tmpname, cols, cols, r.name))
          table.insert(changes, ("DROP TABLE %s"):format(r.name))
          table.insert(changes, ("ALTER TABLE %s RENAME TO %s"):format(tmpname, r.name))
          legacyalter = true
        end
      else
        if opts.delete == nil then
          err = err or ("Not allowed to drop table '%s'; %s"
            ):format(r.name, msgdelete)
        end
        if opts.delete == true then
          table.insert(changes, ("DROP table %s"):format(r.name))
        end
      end
    end
    if err then return nil, err end
    -- `alter table` may require legacy_alter_table pragma
    -- if depending triggers/views exist
    -- see https://sqlite.org/forum/forumpost/0e2390093fbb8fd6
    -- and https://www.sqlite.org/pragma.html#pragma_legacy_alter_table
    if legacyalter then
      table.insert(changes, 1, "PRAGMA legacy_alter_table=1")
      table.insert(changes, "PRAGMA legacy_alter_table=0")
    end
    for k in pairs(prtbl) do
      if not actbl[k] then table.insert(changes, prtbl[k]) end
    end

    local sqlidx = [[SELECT name, sql, type FROM sqlite_schema
      WHERE type in ('index', 'trigger', 'view')
        AND name not like 'sqlite_%']]
    actbl, prtbl = {}, {}
    for r in pristine:nrows(sqlidx) do
      prtbl[r.type..r.name] = r.sql end
    for r in actual:nrows(sqlidx) do
      actbl[r.type..r.name] = true
      if prtbl[r.type..r.name] then
        if r.sql ~= prtbl[r.type..r.name] then
          table.insert(changes, ("DROP %s IF EXISTS %s"):format(r.type, r.name))
          table.insert(changes, prtbl[r.type..r.name])
        end
      else
        table.insert(changes, ("DROP %s IF EXISTS %s"):format(r.type, r.name))
      end
    end
    for k in pairs(prtbl) do
      if not actbl[k] then table.insert(changes, prtbl[k]) end
    end

    -- get the current value of `PRAGMA foreign_keys` to restore if needed
    local acpfk = assert(actual:pragma"foreign_keys")
    -- get the pristine value of `PRAGMA foreign_keys` to set later
    local prpfk = assert(pristine:pragma"foreign_keys")

    if opts.integritycheck ~= false then
      local ic = self:pragma"integrity_check(1)"
      if ic ~= "ok" then return nil, ic end
      -- check existing foreign key violations if the foreign key setting is enabled
      local fkc = prpfk ~= "0" and self:pragma"foreign_key_check"
      if fkc and fkc ~= self.NONE then return nil, "foreign key check failed" end
    end
    if opts.dryrun then return changes end
    if #changes == 0 then return changes end

    -- disable `pragma foreign_keys`, to avoid triggerring cascading deletes
    ok, err = self:pragma"foreign_keys=0"
    if not ok then return ok, err end

    -- execute the changes (within a savepoint)
    ok, err = self:execute(changes)
    -- restore `PRAGMA foreign_keys` value:
    -- (1) to the original value after failure
    -- (2) to the "pristine" value after normal execution
    local pfk = "foreign_keys="..(ok and prpfk or acpfk)
    if self:pragma(pfk) and ok then table.insert(changes, "PRAGMA "..pfk) end
    if not ok then return ok, err end

    -- clean up the database
    ok, err = self:execute("VACUUM")
    if not ok then return ok, err end
    return changes
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
    if idx and isQualified then table.remove(hooks[main], idx) end
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
    return nil, "%s must be one of: "..EncodeLua(list):sub(2, -2)
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
  reg2x = reg2x, reg1p = reg1p,
  getBrand = function() return ("%s/%s %s/%s"):format("redbean", getRBVersion(), NAME, VERSION) end,
  setTemplate = setTemplate, setTemplateVar = setTemplateVar,
  setRoute = setRoute, setSchedule = setSchedule, setHook = setHook,
  parseMultipart = parseMultipart,
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
  serveRedirect = function(status, loc) return function()
      -- if no status or location is specified, then redirect to the original URL with 303
      -- this is useful for switching to GET after POST/PUT to an endpoint
      -- in all other cases, use the specified status or 307 (temp redirect)
      local ts, tl = type(status), type(loc)
      -- swap parameters if needed (as they used to be in a different order before 0.368)
      -- and also allow both status and location be optional
      if (ts == "string" or ts == "nil") and (tl == "nil" or tl == "number") then
        status, loc = loc, status
      end
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
  -- return normally on successful execution or an unsuccessful one
  -- that returns a function (to allow calling `error(fm.serve404)`)
  if ok or type(res) == "function" then
    return coroutine.status(co) == "suspended" and co or false, res, more
  end
  local err = debug.traceback(co, res)
  Log(kLogError, logFormat("Lua error: %s", err))
  return false, error2tmpl(500, nil, IsLoopbackIp(GetRemoteAddr()) and err or nil)
end
local MPKEY = "multipart"
local function handleRequest(path)
  path = path or GetPath()
  req = setmetatable({
      params = setmetatable({}, {__index = function(t, k)
            local mk = k.."[]" -- if the multi-key exists, then use it instead
            if not HasParam(k) and HasParam(mk) then k = mk end
            if not HasParam(k) and not rawget(t, MPKEY) then
              local ct = GetHeader("Content-Type")
              if not ct or not string.find(ct, "^multipart/") then return end
              -- check the multipart body for the requested parameter
              t[MPKEY] = parseMultipart(GetBody(), ct)
              -- return pseudo parameter with the parsed multipart message;
              -- subsequent calls will retrieve it from the table directly
              if k == MPKEY then return t[MPKEY] end
            end
            local mp = rawget(t, MPKEY)
            if mp then
              local m = mp[k] or mp[mk]
              -- if a multipart parameter, then return individual value or list of elements
              if m then return m.data or m end
            end
            -- GetParam may return `nil` for empty parameters (`foo` in `foo&bar=1`),
            -- but `params` needs to return `false` instead
            if not string.find(k, MULTIVAL) then return GetParam(k) or false end
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
  local co, res, headers = hcall(matchRoute, path, req)
  -- execute the (deferred) function and handle any errors
  while type(res) == "function" do co, res, headers = hcall(res) end
  local tres = type(res)
  if res == true then
    -- do nothing, as this request was already handled
  elseif not res and not co then
    -- this request wasn't handled, so report 404
    return error2tmpl(404) -- use 404 template if available
  elseif tres == "string" then
    if #res > 0 then
      if not headers then headers = {ContentType = detectType(res)} end
      Write(res) -- output content as is
    end
  elseif not co then
    LogWarn("unexpected result from action handler: '%s' (%s)", tostring(res), tres)
  end
  -- set the headers as returned by the render
  if type(headers) == "table" then
    if not req.headers then req.headers = {} end
    for name, value in pairs(headers) do req.headers[name] = value end
  elseif headers then
    LogWarn("non-table headers returned from action handler (%s)", tostring(headers))
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

-- add internal functions for test support
fm.test = {
  reqenv = reqenv, route2regex = route2regex, routes = routes,
  matchRoute = matchRoute, handleRequest = handleRequest, getRequest = getRequest,
  headerMap = headerMap, detectType = detectType, matchCondition = matchCondition,
  setSession = setSession,
}

function fm.run(opts)
  opts = opts or {}
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
        for _, val in pairs(type(v) == "table" and v or {v}) do
          -- accept a table to pass multiple values and unpack it
          func(unpack(type(val) ~= "table" and {val} or val))
        end
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

-- setTemplate will do some logging, so provide the log function
-- if this is executed outside of redbean
Log = Log or function() end

fm.setTemplate("fmt", {
    parser = function (tmpl)
      local EOT = "\0"
      local function writer(s) return #s > 0 and ("Write(%q)"):format(s) or "" end
      local function decomment(s) return s:match("%[=*%[") and "--"..s or "" end
      local tupd = (tmpl.."{%"..EOT.."%}"):gsub("(.-){%%([=&]*)%s*(.-)%s*%%}", function(htm, pref, val)
          return writer(htm)
          ..(val ~= EOT -- this is not the suffix
            and (pref == "" -- this is a code fragment
              and val:gsub("%-%-(.*)", decomment).." "
              or ("Write(%s(tostring(%s or '')))")
                :format(pref == "&" and "escapeHtml" or "",
                        val:gsub("%-%-(.*)", decomment)))
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
local function fmgRender(val)
      argerror(type(val) == "table", 1, "(table expected)")
      local function writeAttrs(opt)
        local doneattr = false
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
            doneattr = true
          end
        end
        return doneattr
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
          -- the following allows both `{"elem", attr = 1, {"sub-elem"}}`
          -- and `{"elem", {attr = 1}, {"sub-elem"}}` to be handled;
          -- It allows Lua-base languages that don't mix arrays and hashes
          -- (like fennel) to use the latter syntax and
          -- requires no attributes to be present and the table in the second
          -- index to only have attributes and no array values
          local validx = (not writeAttrs(opt) -- if there are no attributes
            and type(opt[2]) == "table" -- and the second element is a table
            and #opt[2] == 0 -- with no values
            and writeAttrs(opt[2]) -- that has attributes
            and 3 or 2) -- then shift sub-element processing by one
          if htmlVoidTags[tag:lower()] then Write("/>") return end
          Write(">")
          local escape = tag ~= "script"
          for i = validx, #opt do writeVal(opt[i], escape) end
          Write("</"..tag..">")
        else
          local val = tostring(opt or "")
          -- escape by default if not requested not to
          if escape ~= false then val = EscapeHtml(val) end
          Write(val)
        end
      end
      for _, v in pairs(val) do writeVal(v) end
    end
fm.setTemplate("fmg", {
    autotag = true,
    parser = function(s, path)
      local code = setfenv(assert(load("return "..s, path, "t")), getfenv())
      return function() fmgRender(assert(code())) end
    end,
    fmgRender,
  })
fm.setTemplate("cgi", function(cmd)
  if not cmd or not cmd[1] then error('missing command') end
  local nph = cmd.nph
  local maxtime = cmd.maxtime or 5
  local env = {}
  local envu = cmd.env or {}
  local envd = #envu > 0 and envu or {
    SERVER_ADDR = FormatIp(GetServerAddr()),
    SERVER_PORT = select(2, GetServerAddr()),
    SERVER_SOFTWARE = fm.getBrand(),
    REMOTE_HOST = GetHost(),
    REMOTE_ADDR = FormatIp(GetRemoteAddr()),
    REMOTE_INDENT = ParseUrl(GetUrl()).user,
    REQUEST_SCHEME = GetScheme(),
    REQUEST_METHOD = GetMethod(),
    GATEWAY_INTERFACE = "CGI/1.1",
    SERVER_PROTOCOL = ("HTTP/%01.1f"):format(GetHttpVersion()/10),
    QUERY_STRING = EncodeUrl({params = ParseUrl(GetUrl()).params}):sub(2),
    REQUEST_URI = (
      function(u) return EncodeUrl({params = u.params, path = u.path})end)(
      ParseUrl(GetUrl())),
    HTTPS = GetSslIdentity() and "on" or nil,
    PATH_INFO = GetPath(),
    PATH_TRANSLATED = GetEffectivePath(),
    CONTENT_TYPE = GetHeader("Content-Type"),
    CONTENT_LENGTH = GetHeader("Content-Length"),
  }
  if #envu == 0 then
    -- provide all the headers
    for k, v in pairs(GetHeaders()) do envd["HTTP_"..k:upper()] = v end
    -- overwrite all defaults
    for k, v in pairs(envu) do envd[k] = v end
    -- convert to strings unless the value is false
    for k, v in pairs(envd) do if v then table.insert(env, k.."="..v) end end
  end
  local rfd1, wfd1 = unix.pipe(unix.O_CLOEXEC)
  local rfd2, wfd2 = unix.pipe(unix.O_CLOEXEC)
  local pid = unix.fork()
  if pid == 0 then  -- forked child
    assert(unix.close(GetClientFd()))  -- close client fd to not send anything
    assert(unix.dup(rfd2, 0))  -- redirect stdin
    assert(unix.dup(wfd1, 1))  -- redirect stdout
    assert(unix.dup(wfd1, 2))  -- redirect stderr
    assert(unix.close(wfd1))
    assert(unix.close(rfd1))
    assert(unix.close(wfd2))
    assert(unix.close(rfd2))
    assert(unix.sigaction(unix.SIGQUIT, unix.exit))
    unix.execve(cmd[1], cmd, env)
    unix.exit(127)
  else
    unix.write(wfd2, GetBody())
    local isactive = true
    local header = true
    local done = false
    assert(unix.sigaction(unix.SIGALRM, function() isactive = false end))
    assert(unix.setitimer(unix.ITIMER_REAL, 0, 0, maxtime, 0))
    local cfd = GetClientFd()
    while true do
      -- block for a bit until there is output from the launched process
      local se = (unix.poll({[rfd1] = unix.POLLIN}, maxtime*1000/10) or {})[rfd1] or 0
      if se & (unix.POLLHUP + unix.POLLERR) > 0 then break end

      -- check if the client is (still) writable
      local re = (unix.poll({[cfd] = unix.POLLOUT}) or {})[cfd] or 0
      if re & (unix.POLLHUP + unix.POLLERR) > 0 then break end

      -- check if the process took too long to respond
      if not isactive then break end

      local data, errno
      if se & unix.POLLIN > 0 then data, errno = unix.read(rfd1) end
      -- check for end of file or any descriptor errors
      if data == "" or errno and errno:errno() == unix.EBADF then break end

      if data then
        if header then
          local pos = 1
          while true do
            -- allow both CRLF and LF to be handled
            local spos, epos = data:find("\r?\n", pos, false)
            if not spos then break end
            -- found an empty string, which signals the end of headers
            if spos == pos then header = false; pos = epos + 1; break end
            local status, reason
            if pos == 1 then
              status, reason = data:sub(pos, spos-1):match("^HTTP/%d%.%d%s+(%d%d%d)%s+(.+)")
            end
            if status then
              -- found the status line
              SetStatus(status, reason)
            else
              -- found something that may be a header
              local name, value = data:sub(pos, spos-1):match("^(%a[%w_-]+):%s*(.+)")
              -- check if the header has a valid syntax
              -- if not, skip it and handle it as part of the data;
              -- this may happen if an error is thrown instead of a valid context
              local ok, err = pcall(SetHeader, name, value)
              if not name or not value or not ok then
                header = false
                break
              end
            end
            pos = epos + 1
          end
          -- finished parsing headers, so remove them from the data
          if not header then
            -- if nph is requested, then close the connection when done
            if nph then SetHeader("Connection", "close") end
            if pos > 1 then data = data:sub(pos) end
          end
        end
        -- if the headers are set, write the response
        if not header then
          Write(data)
          if nph then coroutine.yield() end
        end
      -- check if reading was interrupted or wasn't done
      elseif not data and (not errno or errno:errno() == unix.EINTR) then
        -- closing connection will fail on send
        -- if it doesn't fail, then redo the interrupted read
      else  -- report an error and stop
        -- TODO: log error
        break
      end
      -- stop reading if the process is already done
      done = not unix.wait(pid, unix.WNOHANG)
      if done then break end
    end
    unix.close(rfd1)
    unix.close(wfd1)
    unix.close(rfd2)
    unix.close(wfd2)
    -- kill launched process if it's still running, as it's been running for too long
    if not done then assert(unix.kill(pid, unix.SIGTERM)) end
  end
end)

return fm
