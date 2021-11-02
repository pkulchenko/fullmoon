--
-- ultra-light webframework for Redbean web server (https://redbean.dev/)
-- Copyright 2021 Paul Kulchenko
-- 

--[[-- support functions --]]--

local isRedbean = ProgramBrand ~= nil
local Write = isRedbean and Write or io.write
local EscapeHtml = isRedbean and EscapeHtml or function(s)
  return (string.gsub(s, "&", "&amp;"):gsub('"', "&quot;"):gsub("<","&lt;"):gsub(">","&gt;")) end
local re = isRedbean and re or {compile = function() return {search = function(path) return path end} end}
local logf = (isRedbean and Log
  and function(lvl, fmt, ...)
    return Log(lvl, "(fm) "..(select('#', ...) == 0 and fmt or (fmt or ""):format(...)))
  end or function() end)

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

local function argerror(cond, narg, extramsg)
  local name = debug.getinfo(2, "n").name or "?"
  local msg = ("bad argument #%d to %s%s"):format(narg, name, extramsg and " "..extramsg or  "")
  if not cond then error(msg, 3) end
  return cond, msg
end

local ref = {} -- some unique key value
-- request functions (`request.write()`)
local reqenv -- forward declaration
-- request properties (`request.authority`)
local reqapi = { authority = function()
    local url = ParseUrl(GetUrl())
    return EncodeUrl({scheme = url.scheme, host = url.host, port = url.port})
  end, }
local envmt = {__index = function(t, key)
    local val = reqenv[key] or rawget(t, ref) and t[ref][key] or _G[key]
    if not val and type(key) == "string" then
      local func = reqapi[key] or _G["Get"..key:sub(1,1):upper()..key:sub(2)]
      -- map a property (like `.host`) to a function call (`.GetHost()`)
      if type(func) == "function" then val = func() else val = func end
      t[key] = val
    end
    return val
  end}

--[[-- template engine --]]--

local function addlocals(params)
  local i = 1
  while true do
    local name, value = debug.getlocal(3, i)
    if not name then break end
    if string.sub(name, 1, 1) ~= '(' then
      params[name] = value
    end
    i = i + 1
  end
  return params
end

local templates = {}
local function render(name, opt)
  argerror(type(name) == "string", 1, "(string expected)")
  argerror(templates[name], 1, "(unknown template name)")
  -- add local variables from the current environment
  local params = addlocals(getfenv(templates[name])[ref] or {})
  -- add explicitly passed parameters
  for k, v in pairs(type(opt) == "table" and opt or {}) do params[k] = v end
  -- set the calculated parameters to the current template
  getfenv(templates[name])[ref] = params
  logf(kLogInfo, "render template: %s", name)
  -- return template results or an empty string to indicate completion
  -- this is useful when the template does direct write to the output buffer
  return templates[name]() or ""
end

local function parse(tmpl)
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
end

local function addTemplate(name, code, opt)
  argerror(type(name) == "string", 1, "(string expected)")
  argerror(type(code) == "string" or type(code) == "function", 2, "(string or function expected)")
  logf(kLogVerbose, "add template: %s", name)
  local env = setmetatable({include = render, [ref] = opt}, envmt)
  templates[name] = setfenv(type(code) == "function" and code or assert((loadstring or load)(parse(code), code)), env)
end

--[[-- routing engine --]]--

local routes = {}
local setmap = {["%d"] = "0-9", ["%w"] = "a-zA-Z0-9", ["\\d"] = "0-9", ["\\w"] = "a-zA-Z0-9"}
local function route2regex(route)
  -- foo/bar, foo/*, foo/:bar, foo/:bar[%d], foo(/:bar(/:more))(.:ext)
  local params = {}
  local regex, subnum = string.gsub(route, "%)", "%1?") -- update optional groups from () to ()?
    :gsub("%.", "\\.") -- escape dots (.)
    :gsub(":(%w+)", function(param) table.insert(params, param); return "([^/]+)" end)
    :gsub("(%b[])(%+%))(%b[])", "%3%2") -- handle custom sets
    :gsub("%b[]", function(s) return s:gsub("[%%\\][wd]", setmap) end)
    :gsub("%*", "(.*)") -- add splat
  argerror(subnum <= 1, 1, "more than one splat ('*') found")
  if subnum > 0 then table.insert(params, "splat") end
  -- mark optional captures, as they are going to be returned during match
  subnum = 1
  local s, e, capture = 0
  while true do
    s, e, capture = regex:find("%b()([?]?)", s+1)
    if not s then break end
    if capture > "" then table.insert(params, subnum, false) end
    subnum = subnum + 1
  end
  return "^"..regex.."$", params
end

local function addRoute(route, handler, opt)
  argerror(type(route) == "string", 1, "(string expected)")
  local pos = routes[route] or #routes+1
  local regex, params = route2regex(route)
  logf(kLogVerbose, "add route: %s", route)
  if type(handler) == "string" then
    -- if `handler` is a string, then turn it into a handler
    local newroute = handler
    handler = function(r) return RoutePath(r.makePath(newroute, r.params)) end
  end
  routes[pos] = {route = route, handler = handler, options = opt, comp = re.compile(regex), params = params}
  routes[route] = pos
  if opt and opt.name then routes[opt.name] = pos end
end

local function match(path, req)
  logf(kLogVerbose, "matching %d route(s) against %s", #routes, path)
  if not req then req = {params = {}} end
  for _, route in ipairs(routes) do
    -- skip static routes that are only used for path generation
    if type(route.handler) == "function" then
      local res = {route.comp:search(path)}
      local matched = #res > 0
      logf(matched and kLogInfo or kLogVerbose, "route %s %smatched",
        route.route, matched and "" or "not ")
      if table.remove(res, 1) then -- path matched
        for ind, val in ipairs(route.params) do
          if val and res[ind] then req.params[val] = res[ind] > "" and res[ind] or false end
        end
        local res = route.handler(req)
        if res then return res end
      end
    end
  end
end

--[[-- route path generation --]]--

local function makePath(name, params)
  argerror(type(name) == "string", 1, "(string expected)")
  params = params or {}
  -- name can be the name or the route itself (even not registered)
  local pos = routes[name]
  local route = pos and routes[pos].route or name
  -- replace :foo with provided parameters
  route = route:gsub(":(%w+)([^(*:]*)", function(param, rest)
      return (params[param] or ":"..param)..rest:gsub("^%b[]","")
    end)
  -- replace splat with provided parameter, if any
  -- more than one splat is not expected, since it's already checked
  route = route:gsub("*", function() return params.splat or "*" end)
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
  local param = route:match(":(%w+)")
  argerror(not param, 2, "(missing required parameter "..(param or "?")..")")
  argerror(not route:find("*", 1, true), 2, "(missing required splat parameter)")
  return route
end

--[[-- core engine --]]--

local tests -- forward declaration
local function error2tmpl(status, reason, message)
  if not reason then reason = GetHttpReason(status) end
  SetStatus(status, reason) -- set status, but allow template handlers to overwrite it
  local ok, res = pcall(render, tostring(status),
    {status = status, reason = reason, message = message})
  return ok and res or ServeError(status, reason) or true
end
-- call the handler and handle any Lua error by returning Server Error
local function hcall(func, ...)
  local ok, res = xpcall(func, debug.traceback, ...)
  if ok then return res end
  local err = res:gsub("\n[^\n]*in function 'xpcall'\n", "\n")
  logf(kLogError, "Lua error: %s", err)
  return error2tmpl(500, nil, IsLoopbackIp(GetRemoteAddr()) and err or nil)
end

local req
local function getRequest() return req end
local function handleRequest()
  req = setmetatable({params = {}, headers = {}}, envmt)
  -- find a match and handle any Lua errors in handlers
  local res = hcall(match, GetPath(), req)
  local tres = type(res)
  if res == true then
    -- do nothing, as this request was already handled
  elseif not res then
    -- this request wasn't handled, so report 404
    return error2tmpl(404) -- use 404 template if available
  elseif tres == "function" then
    hcall(res) -- execute the (deferred) function and handle any errors
  elseif tres == "string" then
    Write(res) -- output content as is
  end
  -- also output any headers that have been specified
  for name, value in pairs(req.headers or {}) do SetHeader(name, value) end
end
local function run(opt)
  opt = opt or {}
  if opt.tests then tests(); os.exit() end
  OnHttpRequest = handleRequest
end

local function checkpath(path) return type(path) == "string" and path or GetPath() end

reqenv = { write = Write, escapeHtml = EscapeHtml, makePath = makePath }
local fm = setmetatable({
  addTemplate = addTemplate, render = render,
  addRoute = addRoute, makePath = makePath,
  getAsset = LoadAsset, run = run,
  -- serve index.lua or index.html if available; continue if not
  -- this handles being served as the route handler (with request passed)
  -- or as a method called from a route handler (with an optional path passed)
  serveIndex = function(path) return ServeIndex(checkpath(path)) end,
  -- return existing static/other assets if available
  serveDefault = function() return RoutePath() end,
  serveError = function(status, reason) return function() return error2tmpl(status, reason) end end,
  serveContent = function(tmpl, params) return function() return render(tmpl, params) end end,
  serveRedirect = function(loc, status) return function() return ServeRedirect(status or 307, loc) end end,
  serveAsset = function(path) return function() return ServeAsset(checkpath(path)) end end,
  serveResponse = function(status, headers, body)
    -- since headers is optional, handle the case when headers are not present
    if type(headers) == "string" and body == nil then
      body, headers = headers, nil
    end
    argerror(type(status) == "number", 1, "(number expected)")
    argerror(not headers or type(headers) == "table", 2, "(table expected)")
    argerror(not body or type(body) == "string", 3, "(string expected)")
    return function()
      SetStatus(status)
      if headers then getRequest().headers = headers end
      if body then Write(body) end
      return true
    end
  end,
}, {__index =
  function(t, key)
    -- handle serve204 and similar calls
    local serveStatus = key:match("serve(%d%d%d)")
    if serveStatus then return t.serveResponse(tonumber(serveStatus)) end
    -- handle logVerbose and other log calls
    local kVal = _G[key:gsub("^l(og%w*)$", function(name) return "kL"..name end)]
    if kVal then
      t[key] = function(...) return logf(kVal, ...) end
      return t[key]
    end
    return
  end})

-- register default 500 status template
fm.addTemplate("500", [[
  <!doctype html><title>{%& status %} {%& reason %}</title>
  <h1>{%& status %} {%& reason %}</h1>
  {% if message then %}<pre>{%& message %}</pre>{% end %}]]
)

--[[-- various tests --]]--

tests = function()
  -- provide methods not available outside of Redbean or outside of request handling
  SetStatus = function() end
  ServeError = function() end
  IsLoopbackIp = function() return true end
  GetRemoteAddr = function() end
  GetHttpReason = function(status) return tostring(status).." reason" end

  -- suppress default logging during tests
  if SetLogLevel then SetLogLevel(kLogWarn) end

  local out = ""
  reqenv.write = function(s) out = out..s end
  local num = 1
  local section = ""
  local function outformat(s) return type(s) == "string" and ("%q"):format(s):gsub("\n","n") or tostring(s) end
  local function is(result, expected, message)
    local ok = result == expected
    local msg = ("%s %d\t%s%s"):format((ok and "ok" or "not ok"), num, (section > "" and section.." " or ""), message or "")
    if not ok then
      msg = msg .. ("\n\treceived: %s\n\texpected: %s"):format(outformat(result), outformat(expected))
    end
    print(msg)
    num = num + 1
    out = ""
  end

  --[[-- template engine tests --]]--

  section = "(template)"
  local tmpl1 = "tmpl1"
  fm.addTemplate(tmpl1, "Hello, World!")
  fm.render(tmpl1)
  is(out, "Hello, World!", "text rendering")

  fm.addTemplate(tmpl1, "Hello, {%& title %}!")
  fm.render(tmpl1, {title = "World"})
  is(out, "Hello, World!", "text with parameter")

  fm.render(tmpl1, {title = "World&"})
  is(out, "Hello, World&amp;!", "text with encoded parameter")

  fm.addTemplate(tmpl1, "Hello, {% for i, v in ipairs({3,2,1}) do %}-{%= v %}{% end %}")
  fm.render(tmpl1)
  is(out, "Hello, -3-2-1", "Lua code")

  local tmpl2 = "tmpl2"
  fm.addTemplate(tmpl2, [[{a: "{%= title %}"}]])
  fm.render(tmpl2)
  is(out, '{a: ""}', "JSON with empty local value")

  do
    fm.addTemplate(tmpl2, [[{a: "{%= title %}"}]], {title = "set when adding template"})
    fm.render(tmpl2)
    is(out, '{a: "set when adding template"}', "JSON with value set when adding template")

    local title = "local value" -- do not remove; to provide a value for the template
    fm.render(tmpl2)
    is(out, '{a: "local value"}', "JSON with local value")

    fm.render(tmpl2, {title = "set from render"})
    is(out, '{a: "set from render"}', "JSON with a passed value set at rendering")

    fm.addTemplate(tmpl2, [[{% local title = "set from template" %}{a: "{%= title %}"}]])
    fm.render(tmpl2)
    is(out, '{a: "set from template"}', "JSON with value set from template")

    fm.addTemplate(tmpl2, [[{a: "{%= title %}"}]], {title = "set when adding"})
    fm.render(tmpl2)
    is(out, '{a: "local value"}', "JSON with local value overwriting the one set when adding template")
  end

  fm.addTemplate(tmpl1, "Hello, {% include('tmpl2') %}")
  fm.render(tmpl1)
  is(out, [[Hello, {a: "local value"}]], "`include` other template with a local value")

  fm.addTemplate(tmpl1, [[Hello, {% include('tmpl2', {title = "value"}) %}]])
  fm.render(tmpl1)
  is(out, [[Hello, {a: "value"}]], "`include` other template with passed value set at rendering")

  fm.addTemplate(tmpl1, [[Hello, {% local title = "another value"; include('tmpl2') %}]])
  fm.render(tmpl1)
  is(out, [[Hello, {a: "another value"}]], "`include` other template with value set from template")

  fm.addTemplate(tmpl1, "Hello, World!\n{% main() %}")
  local _, err = pcall(render, tmpl1)
  is(err ~= nil, true, "report Lua error in template")
  is(err:match('string "Hello, World!'), 'string "Hello, World!', "error references original template code")
  is(err:match(':2: '), ':2: ', "error references expected line number")

  fm.addTemplate(tmpl1, "Hello, {% main() %}World!", {main = function() end})
  fm.render(tmpl1)
  is(out, [[Hello, World!]], "used function can be passed when adding template")

  fm.addTemplate(tmpl2, [[{% local function main() %}<h1>Title</h1>{% end %}{% include "tmpl1" %}]])
  fm.render(tmpl2)
  is(out, [[Hello, <h1>Title</h1>World!]], "function can be overwritten with template fragments in extended template")

  fm.addTemplate(tmpl2, [[{% local function main() write"<h1>Title</h1>" end %}{% include "tmpl1" %}]])
  fm.render(tmpl2)
  is(out, [[Hello, <h1>Title</h1>World!]], "function can be overwritten with direct write in extended template")

  --[[-- routing engine tests --]]--

  section = "(routing)"
  is(route2regex("/foo/bar"), "^/foo/bar$", "simple route")
  is(route2regex("/foo/:bar"), "^/foo/([^/]+)$", "route with a named parameter")
  is(route2regex("/foo(/:bar)"), "^/foo(/([^/]+))?$", "route with a named optional parameter")
  is(route2regex("/foo/:bar[\\d]"), "^/foo/([0-9]+)$", "route with a named parameter and a customer set (posix syntax)")
  is(route2regex("/foo/:bar[%d]"), "^/foo/([0-9]+)$", "route with a named parameter and a customer set (Lua syntax)")
  is(route2regex("/foo(/:bar(/:more))"), "^/foo(/([^/]+)(/([^/]+))?)?$", "route with two named optional parameters")
  is(route2regex("/foo(/:bar)/*.zip"), "^/foo(/([^/]+))?/(.*)\\.zip$", "route with an optional parameter and a splat")
  local _, params = route2regex("foo(/:bar)/*.zip")
  is(params[1], false, "'foo(/:bar)/*.zip' - parameter 1 is optional")
  is(params[2], "bar", "'foo(/:bar)/*.zip' - parameter 2 is 'bar'")
  is(params[3], "splat", "'foo(/:bar)/*.zip' - parameter 3 is 'splat'")

  local handler = function() end
  fm.addRoute("/foo/bar", handler)
  local index = routes["/foo/bar"]
  is(routes[index].handler, handler, "assign handler to a regular route")
  fm.addRoute("/foo/bar")
  is(routes["/foo/bar"], index, "route with the same name is reassigned")
  is(routes[routes["/foo/bar"]].handler, nil, "assign no handler to a static route")

  local route = "/foo(/:bar(/:more[%d]))(.:ext)/*.zip"
  fm.addRoute(route, isRedbean and function(r)
      is(r.params.bar, "some", "[1/4] default optional parameter matches")
      is(r.params.more, "123", "[2/4] customer set matches")
      is(r.params.ext, "myext", "[3/4] optional extension matches")
      is(r.params.splat, "mo/re", "[4/4] splat matches path separators")
    end)
  match("/foo/some/123.myext/mo/re.zip")
  fm.addRoute(route, isRedbean and function(r)
      is(r.params.bar, "some.myext", "[1/4] default optional parameter matches dots")
      is(not r.params.more, true, "[2/4] missing optional parameter gets `false` value")
      is(not r.params.ext, true, "[3/4] missing optional parameter gets `false` value")
      is(r.params.splat, "more", "[4/4] splat matches")
    end)
  match("/foo/some.myext/more.zip")
  if isRedbean then
    local called = false
    fm.addRoute(route, function() called = true end)
    match("/foo/some.myext/more")
    is(called, false, "non-matching route handler is not called")
  end

  --[[-- makePath tests --]]--

  section = "(makepath)"
  route = "/foo(/:bar(/:more[%d]))(.:ext)/*.zip"
  fm.addRoute(route, nil, {name = "foobar"})

  _, err = pcall(fm.makePath, route)
  is(err:match("missing required splat"), "missing required splat", "required splat is checked")
  _, err = pcall(fm.makePath, "foo/:bar")
  is(err:match("missing required parameter bar"), "missing required parameter bar", "required parameter is checked")
  is(fm.makePath(route, {splat = "name"}), "/foo/name.zip", "required splat is filled in")
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

  is(fm.makePath("http://some.website.com/:foo?param=:bar", {foo = "some", bar = 123}),
    "http://some.website.com/some?param=123", "external/static path")

  -- test using makePath from a template
  fm.addTemplate(tmpl1, "Hello, {%= makePath('foobar', {splat = 'name'}) %}")
  fm.render(tmpl1)
  is(out, [[Hello, /foo/name.zip]], "`makePath` inside template")

  --[[-- serve* tests --]]--

  local setStatus, getPath = SetStatus, GetPath
  local status
  SetStatus = function(s) status = s end
  GetPath = function() return "/status" end

  section = "(serveError)"
  fm.addRoute("/status", fm.serveError(403, "Access forbidden"))
  fm.addTemplate("403", "Server Error: {%& reason %}")
  local error403 = routes[routes["/status"]].handler()
  is(out, "Server Error: Access forbidden", "serveError used as a route handler")
  is(error403, "", "serveError finds registered template")

  fm.addRoute("/status", fm.serveError(405))
  handleRequest()
  is(status, 405, "direct serveError(405) sets expected status")

  fm.addRoute("/status", function() return fm.serveError(402) end)
  handleRequest()
  is(status, 402, "handler calling serveError(402) sets expected status")

  section = "(serveResponse)"
  fm.addRoute("/status", fm.serve401)
  handleRequest()
  is(status, 401, "direct serve401 sets expected status")

  section = "(serveContent)"
  fm.addTemplate(tmpl1, "Hello, {%& title %}!")
  fm.addRoute("content", fm.serveContent(tmpl1, {title = "World"}))
  routes[routes["content"]].handler()
  is(out, "Hello, World!", "serveContent used as a route handler")

  --[[-- log* tests --]]--

  if Log then
    section = "(log)"
    is(type(fm.logVerbose), "function", "logVerbose is a (dynamic) method")
    is(type(fm.logInfo), "function", "logInfo is a (dynamic) method")
  end
end

-- run tests if launched as a script
if not pcall(debug.getlocal, 4, 1) then run{tests = true} end

-- return library if called with `require`
return fm
