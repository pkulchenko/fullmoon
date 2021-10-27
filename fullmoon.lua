--
-- ultra-light webframework for Redbean web server (https://redbean.dev/)
-- Copyright 2021 Paul Kulchenko
-- 

--[[-- support functions --]]--

local Write = Write or io.write
local EscapeHtml = EscapeHtml or function(s) return (string.gsub(s, "&", "&amp;"):gsub('"', "&quot;"):gsub("<","&lt;"):gsub(">","&gt;")) end
local re = re or {compile = function() return {search = function() return end} end}
local logVerbose = Log and function(fmt, ...) return Log(kLogVerbose, "(fm) "..(select('#', ...) == 0 and fmt or (fmt or ""):format(...))) end or function() end

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
  logVerbose("render template: %s", name)
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
  logVerbose("add template: %s", name)
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
  logVerbose("add route: %s", route)
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
  logVerbose("matching %d route(s) against %s", #routes, path)
  if not req then req = {params = {}} end
  for _, route in ipairs(routes) do
    -- skip static routes that are only used for path generation
    if type(route.handler) == "function" then
      local res = {route.comp:search(path)}
      logVerbose("route %s %smatched", route.route, #res > 0 and "" or "not ")
      if table.remove(res, 1) then -- path matched
        for ind, val in ipairs(route.params) do
          if val then req.params[val] = res[ind] > "" and res[ind] or false end
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
  route = route:gsub(":(%w+)([^(/]*)", function(param, rest)
      return (params[param] or ":"..param)..rest:gsub("^%b[]","")
    end)
  -- replace splat with provided parameter, if any
  -- more than one splat is not expected, since it's already checked
  route = route:gsub("*", function(splat) return params.splat or "*" end)
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
local function run(opt)
  opt = opt or {}
  if opt.tests then tests(); os.exit() end
  OnHttpRequest = function()
    local res = match(GetPath():sub(2), setmetatable({params = {}}, envmt))
    -- if nothing matches, then attempt to serve the static content or return 404
    local tres = type(res)
    if res == true then
      -- do nothing, as it was already handled
    elseif not res then
      -- set status, but allow handlers to overwrite it
      SetStatus(404)
      -- use show404 template if available
      local ok, res = pcall(render, "show404")
      return ok and res
    elseif tres == "string" then
      Write(res)
    end
  end
end

reqenv = { write = Write, escapeHtml = EscapeHtml, makePath = makePath }
local FM = {
  addTemplate = addTemplate, render = render,
  addRoute = addRoute, makePath = makePath,
  getResource = LoadAsset, run = run,
  -- serve index.lua or index.html if available; continue if not
  showIndex = function() return ServeIndex(GetPath()) end,
  -- return existing static/other assets if available
  showDefault = function() return RoutePath() end,
}

--[[-- various tests --]]--

tests = function()
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
  addTemplate(tmpl1, "Hello, World!")
  render(tmpl1)
  is(out, "Hello, World!", "text rendering")

  addTemplate(tmpl1, "Hello, {%& title %}!")
  render(tmpl1, {title = "World"})
  is(out, "Hello, World!", "text with parameter")

  render(tmpl1, {title = "World&"})
  is(out, "Hello, World&amp;!", "text with encoded parameter")

  addTemplate(tmpl1, "Hello, {% for i, v in ipairs({3,2,1}) do %}-{%= v %}{% end %}")
  render(tmpl1)
  is(out, "Hello, -3-2-1", "Lua code")

  local tmpl2 = "tmpl2"
  addTemplate(tmpl2, [[{a: "{%= title %}"}]])
  render(tmpl2)
  is(out, '{a: ""}', "JSON with empty local value")

  do
    addTemplate(tmpl2, [[{a: "{%= title %}"}]], {title = "set when adding template"})
    render(tmpl2)
    is(out, '{a: "set when adding template"}', "JSON with value set when adding template")

    local title = "local value" -- to provide a value for the template
    render(tmpl2)
    is(out, '{a: "local value"}', "JSON with local value")

    render(tmpl2, {title = "set from render"})
    is(out, '{a: "set from render"}', "JSON with a passed value set at rendering")

    addTemplate(tmpl2, [[{% local title = "set from template" %}{a: "{%= title %}"}]])
    render(tmpl2)
    is(out, '{a: "set from template"}', "JSON with value set from template")

    addTemplate(tmpl2, [[{a: "{%= title %}"}]], {title = "set when adding"})
    render(tmpl2)
    is(out, '{a: "local value"}', "JSON with local value overwriting the one set when adding template")
  end

  addTemplate(tmpl1, "Hello, {% include('tmpl2') %}")
  render(tmpl1)
  is(out, [[Hello, {a: "local value"}]], "`include` other template with a local value")

  addTemplate(tmpl1, [[Hello, {% include('tmpl2', {title = "value"}) %}]])
  render(tmpl1)
  is(out, [[Hello, {a: "value"}]], "`include` other template with passed value set at rendering")

  addTemplate(tmpl1, [[Hello, {% local title = "another value"; include('tmpl2') %}]])
  render(tmpl1)
  is(out, [[Hello, {a: "another value"}]], "`include` other template with value set from template")

  addTemplate(tmpl1, "Hello, World!\n{% main() %}")
  local _, err = pcall(render, tmpl1)
  is(err ~= nil, true, "report Lua error in template")
  is(err:match('string "Hello, World!'), 'string "Hello, World!', "error references original template code")
  is(err:match(':2: '), ':2: ', "error references expected line number")

  addTemplate(tmpl1, "Hello, {% main() %}World!", {main = function() end})
  render(tmpl1)
  is(out, [[Hello, World!]], "used function can be passed when adding template")

  addTemplate(tmpl2, [[{% local function main() %}<h1>Title</h1>{% end %}{% include "tmpl1" %}]])
  render(tmpl2)
  is(out, [[Hello, <h1>Title</h1>World!]], "function can be overwritten with template fragments in extended template")

  addTemplate(tmpl2, [[{% local function main() write"<h1>Title</h1>" end %}{% include "tmpl1" %}]])
  render(tmpl2)
  is(out, [[Hello, <h1>Title</h1>World!]], "function can be overwritten with direct write in extended template")

  --[[-- routing engine tests --]]--

  section = "(routing)"
  is(route2regex("foo/bar"), "^foo/bar$", "simple route")
  is(route2regex("foo/:bar"), "^foo/([^/]+)$", "route with a named parameter")
  is(route2regex("foo(/:bar)"), "^foo(/([^/]+))?$", "route with a named optional parameter")
  is(route2regex("foo/:bar[\\d]"), "^foo/([0-9]+)$", "route with a named parameter and a customer set (posix syntax)")
  is(route2regex("foo/:bar[%d]"), "^foo/([0-9]+)$", "route with a named parameter and a customer set (Lua syntax)")
  is(route2regex("foo(/:bar(/:more))"), "^foo(/([^/]+)(/([^/]+))?)?$", "route with two named optional parameters")
  is(route2regex("foo(/:bar)/*.zip"), "^foo(/([^/]+))?/(.*)\\.zip$", "route with an optional parameter and a splat")
  local _, params = route2regex("foo(/:bar)/*.zip")
  is(params[1], false, "'foo(/:bar)/*.zip' - parameter 1 is optional")
  is(params[2], "bar", "'foo(/:bar)/*.zip' - parameter 2 is 'bar'")
  is(params[3], "splat", "'foo(/:bar)/*.zip' - parameter 3 is 'splat'")

  local handler = function() end
  addRoute("foo/bar", handler)
  local index = routes["foo/bar"]
  is(routes[index].handler, handler, "assign handler to a regular route")
  addRoute("foo/bar")
  is(routes["foo/bar"], index, "route with the same name is reassigned")
  is(routes[routes["foo/bar"]].handler, nil, "assign no handler to a static route")

  local route = "foo(/:bar(/:more[%d]))(.:ext)/*.zip"
  addRoute(route, function(r)
      is(r.params.bar, "some", "[1/4] default optional parameter matches")
      is(r.params.more, "123", "[2/4] customer set matches")
      is(r.params.ext, "myext", "[3/4] optional extension matches")
      is(r.params.splat, "mo/re", "[4/4] splat matches path separators")
    end)
  match("foo/some/123.myext/mo/re.zip")
  addRoute(route, function(r)
      is(r.params.bar, "some.myext", "[1/4] default optional parameter matches dots")
      is(not r.params.more, true, "[2/4] missing optional parameter gets `false` value")
      is(not r.params.ext, true, "[3/4] missing optional parameter gets `false` value")
      is(r.params.splat, "more", "[4/4] splat matches")
    end)
  match("foo/some.myext/more.zip")
  local called = false
  addRoute(route, function() called = true end)
  match("foo/some.myext/more")
  is(called, false, "non-matching route handler is not called")

  --[[-- makePath tests --]]--

  section = "(makepath)"
  route = "foo(/:bar(/:more[%d]))(.:ext)/*.zip"
  addRoute(route, nil, {name = "foobar"})

  _, err = pcall(makePath, route)
  is(err:match("missing required splat"), "missing required splat", "required splat is checked")
  _, err = pcall(makePath, "foo/:bar")
  is(err:match("missing required parameter bar"), "missing required parameter bar", "required parameter is checked")
  is(makePath(route, {splat = "name"}), "foo/name.zip", "required splat is filled in")
  is(makePath("foobar", {splat = "name"}), makePath(route, {splat = "name"}),
    "`makePath` by name and route produce same results")
  is(makePath(route, {splat = "name", more = "foo"}), "foo/name.zip",
    "missing optional parameter inside another missing parameter is removed")
  is(makePath(route, {splat = "name", bar = "some"}), "foo/some/name.zip", "single optional parameter is filled in")
  is(makePath(route, {splat = "name", bar = "some", more = 12, ext = "json"}), "foo/some/12.json/name.zip",
    "multiple optional parameters are filled in")
  is(makePath("foo/:bar", {bar = "more"}), "foo/more", "unregistered route is handled")
  is(makePath("foo(/*.zip)"), "foo", "optional splat is not required")
  is(makePath("foo(/*.zip)", {splat = "more"}), "foo/more.zip", "optional splat is filled in")

  -- test using makePath from a template
  addTemplate(tmpl1, "Hello, {%= makePath('foobar', {splat = 'name'}) %}")
  render(tmpl1)
  is(out, [[Hello, foo/name.zip]], "`makePath` inside template")
end

-- run tests if launched as a script
if not pcall(debug.getlocal, 4, 1) then run{tests = true} end

-- return library if called with `require`
return FM
