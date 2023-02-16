-- Test suite for fullmoon
-- 1. Include fullmoon.lua in ./redbean.com
-- 2. execute `./redbean.com -i test.lua`
-- `test.lua` can also be run by Lua 5.4 interpreter for a subset of tests

local fm = require "fullmoon"
local unpack = table.unpack or unpack

local out = ""
local reqenv = fm.test.reqenv
local routes = fm.test.routes
local headerMap = fm.test.headerMap
local getRequest = fm.test.getRequest
local detectType = fm.test.detectType
local matchRoute = fm.test.matchRoute
local setSession = fm.test.setSession
local route2regex = fm.test.route2regex
local handleRequest = fm.test.handleRequest
local matchCondition = fm.test.matchCondition

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

--[[-- misc tests --]]--

section = "(misc)"
local X = fm.reg2x{"FIRST", "SECOND", "THIRD"}
is(X.THIRD, 4, "reg2x multiplies")
local P = fm.reg1p{"FIRST", "SECOND", "THIRD"}
is(P.THIRD, 3, "reg1p adds")

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
local ok, err = pcall(fm.render, tmpl1)
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
      local _, err = pcall(fm.render, "hello3")
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
    is(r.params.bar, "some", "default optional parameter matches (1/4)")
    is(r.params.more, "123", "customer set matches (2/4)")
    is(r.params.ext, "myext", "optional extension matches (3/4)")
    is(r.params.splat, "mo/re", "splat matches path separators (4/4)")
  end)
matchRoute("/foo/some/123.myext/mo/re.zip", {params = {}})
fm.setRoute(route, function(r)
    is(r.params.bar, "some.myext", "default optional parameter matches dots (1/4)")
    is(not r.params.more, true, "missing optional parameter gets `false` value (2/4)")
    is(not r.params.ext, true, "missing optional parameter gets `false` value (3/4)")
    is(r.params.splat, "more", "splat matches (4/4)")
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

section = "(request)"

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

route = "/foo(/:bar(/:more[%d]))(.:ext)/*.zip"
do local rname
  fm.setRoute({"/something/else", routeName = "foobar"})
  local index = routes["foobar"]
  fm.setRoute({route, routeName = "foobar"})
  is(routes["foobar"] ~= index, true, "different route with the same routeName is registered anew")
  is(routes["/something/else"], index, "overwritten route is still present")
end
is(routes.foobar, routes[route], "route name can be used as alias")
is(routes[routes.foobar].routeName, nil, "route name is removed from conditions")

--[[-- makePath tests --]]--

section = "(makePath)"
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
is(fm.makePath("foobar", {splat = "name"}),
  fm.makePath(route, {splat = "name"}),
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
  is(fm.makeUrl(), url, "makeUrl produces original url")
  is(fm.makeUrl({path = "/short"}), url:gsub("/path/more/name.ext", "/short"), "makeUrl uses path")
  is(fm.makeUrl({scheme = "https"}), url:gsub("http:", "https:"), "makeUrl uses scheme")
  is(fm.makeUrl({fragment = "newfrag"}), url:gsub("#frag", "#newfrag"), "makeUrl uses fragment")
  is(fm.makeUrl({fragment = false}), url:gsub("#frag", ""), "makeUrl removes fragment")
  is(fm.makeUrl("", {path = "/path", params = {{"a", 1}, {"b", 2}, {"c"}}}), "/path?a=1&b=2&c",
    "makeUrl generates path and query string")
  is(fm.makeUrl("", {params = {a = 1, b = "", c = true, ["d[1][name]"] = "file" }}),
    "?a=1&b=&c&d%5B1%5D%5Bname%5D=file", "makeUrl generates query string from hash table")

  -- test using makeUrl from a template
  -- confirm that the URL is both url (%xx) and html (&...) escaped
  fm.setTemplate(tmpl1, "Hello, {%& makeUrl({path = '<some&/path>'}) %}")
  fm.render(tmpl1)
  is(out, [[Hello, http://domain.com/%3Csome&amp;/path%3E?param1=val1&amp;param2=val2#frag]],
    "`makeUrl` inside template")
end

--[[-- multipart tests --]]--
section = "(multipart)"
local ct1 = "multipart/mixed; boundary=41111539122868; start=photo2"
local m1 = ([[
preamble
--41111539122868
Content-Disposition: form-data;
  name="files[]";
  filename="photo1.jpg"
Content-Type: image/jpeg

SomeBinaryData
--41111539122868
Content-Disposition: form-data; name="files[]"; filename="photo2.jpg"
Content-Type: image/jpeg
content-ID: photo2

MoreBinaryData
--41111539122868
Content-Disposition: form-data;
  name="simple"

Simple value
--41111539122868

No header
--41111539122868--
epilogue
]]):gsub("\r?\n", "\r\n")
local r1 = fm.parseMultipart(m1, ct1)
is(r1[1].filename, "photo2.jpg", "multipart message shows 'start' content-id first")
is(r1.simple.data, "Simple value", "multipart message handles simple value")
is(r1[4].data, "No header", "multipart message returns value with no header")
is(#r1, 4, "multipart message reports number of parts")

HasParam = function(p) return p == "foo" end
GetParam = function(p) return p == "foo" and "bar" or nil end
GetBody = function() return m1 end
GetHeader = function(h) return h == "Content-Type" and ct1 or nil end
fm.setTemplate(tmpl1, "-{%= table.concat({a[1].data, a[2].data, b, c, n[1], n[2], d}, '-') %}-")
local pnum = 0
-- match multipart "simple" parameter to its value as a filter
fm.setRoute({"/params/multi", simple = "Simple value"}, function(r)
    local none = r.params.none -- access non-existing parameter
    local foo = r.params.foo -- access existing, but not multipart parameter
    pnum = #r.params.multipart
    local fnames = {}
    for i, v in ipairs(r.params.files) do
      table.insert(fnames, v.filename or "?")
    end
    none = r.params.none -- access non-existing parameter again
    return fm.render(tmpl1,
      {a = r.params["files[]"], b = r.params.simple, c = r.params[1], d = foo, n = fnames})
  end)
handleRequest("/params/multi")
is(out, "-MoreBinaryData-SomeBinaryData-Simple value-MoreBinaryData-photo2.jpg-photo1.jpg-bar-",
  "multipart parameters with [] are returned as array")
is(pnum, 4, "multipart returns all multipart components")

local ct2 = "multipart/form-data; boundary=AaB03x"
local m2 = ([[
--AaB03x
content-disposition: form-data; name="field1"

Joe Blow
--AaB03x
content-disposition: form-data; name="pics"
Content-type: multipart/mixed; boundary=BbC04y

--BbC04y
Content-disposition: attachment; filename="file1.txt"
Content-Type: text/plain

...contents of file1.txt...
--BbC04y
Content-disposition: attachment; filename="file2.gif"
Content-type: image/gif
Content-Transfer-Encoding: binary

...contents of file2.gif...
--BbC04y--
--AaB03x--
]]):gsub("\r?\n", "\r\n")
local r2 = fm.parseMultipart(m2, ct2)
is(#r2, 2, "multipart recursive message reports number of parts")
is(r2[1].data, "Joe Blow", "multipart recursive message shows parts in the original order")
is(#(r2[2].data), 2, "multipart recursive message returns number of sub-parts")
is(r2[2].data[1].filename, "file1.txt", "multipart recursive message shows parts in the original order")
is(r2[2].data.boundary, "BbC04y", "multipart recursive message returns enclosed boundary")

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

  fm.setRoute("/content", fm.serveRedirect("link"))
  routes[routes["/content"]].handler()
  is(status, 307, "serveRedirect without status sets 307 status when location is set")
  is(loc, "link", "serveRedirect with one string parameter sets it as location")

  fm.setRoute("/content", fm.serveRedirect(302))
  routes[routes["/content"]].handler()
  is(status, 302, "serveRedirect with one numeric parameter sets it as status")
  is(loc, GetPath(), "serveRedirect without location uses current path")

  fm.setRoute("/content", fm.serveRedirect(307, "link"))
  routes[routes["/content"]].handler()
  is(status, 307, "serveRedirect with two parameters in the corect order sets status")
  is(loc, "link", "serveRedirect with two parameters in the correct order sets location")

  -- this order of parameters is obsolete, but is still supported
  fm.setRoute("/content", fm.serveRedirect("link", 302))
  routes[routes["/content"]].handler()
  is(status, 302, "serveRedirect with two parameters in the 'wrong' order sets status")
  is(loc, "link", "serveRedirect with two parameters in the 'wrong' order sets location")
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

HasParam = function(s) return s == "a[]" end
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

fm.setRoute("/params/:bar", function(r)
    return fm.render(tmpl1, {a = r.params.a})
  end)
handleRequest()
is(out, "-10false12-", "parameters with [] are returned as array when short name is used")

--[[-- validator tests --]]--

section = "(validator)"
local validator = fm.makeValidator{
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
res = fm.makeBasicAuth({user = "pass"})
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
  is(fm.makeIpMatcher(mask)(ParseIp(ip)), res,
    ("makeIpMatcher %s (%d/%d)"):format(ip, n, #matcherTests))
end

local privateMatcher = fm.makeIpMatcher(
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
    create table test(key integer primary key, value text);
    create index test1 on test(value);
    create view test2 as select * from test;
    create trigger test3 before insert on test begin insert into test(key, value) values (-new.key, new.value); end;
    create table testref(key integer references test(key) on delete cascade);
    pragma foreign_keys=1;
  ]]
  local dbm = fm.makeStorage(":memory:", script)
  assert(dbm:execute([[
      insert into test values(1, 'value');
      insert into testref values(1)
    ]]))
  is(assert(dbm:fetchOne("select * from test where key = 1")) ~= dbm.NONE, true,
    "foreign key is present after initial insert")

  local rows = assert(dbm:fetchAll([[
      select * from test where key = ?;
      /* comment */;
      select * from testref where key = ?;
      -- comment
    ]], 1))
  is(#rows, 2, "fetch handles mult-statement query")
  is(rows[1].key, 1, "fetch for multi-statement returns value (1/2)")
  is(rows[2].key, 1, "fetch for multi-statement returns value (2/2)")

  local upchanges = assert(dbm:upgrade())
  is(#upchanges, 0, "no changes from initial upgrade")
  assert(dbm:execute("drop trigger test3"))
  assert(dbm:execute("drop index test1"))
  assert(dbm:execute("create index test4 on test(key)"))
  upchanges = assert(dbm:upgrade({delete = true}))
  is(#upchanges, 4, "changes added for upgrade after objects dropped/added")
  local upsql = table.concat(upchanges, ";")
  is(upsql:match("DROP index IF EXISTS test4"), "DROP index IF EXISTS test4", "index dropped if not needed")
  is(upsql:match("CREATE INDEX test1"), "CREATE INDEX test1", "index created if doesn't exist")
  is(upsql:match("CREATE TRIGGER test3"), "CREATE TRIGGER test3", "trigger created if doesn't exist")

  assert(dbm:execute("alter table test add column foo"))
  upchanges = assert(dbm:upgrade({delete = true}))
  is(upchanges[1], "PRAGMA legacy_alter_table=1", "ALTER table turns required pragma on")
  is(upchanges[6], "PRAGMA legacy_alter_table=0", "ALTER table turns required pragma off")
  is(assert(dbm:fetchOne("select * from testref where key = 1")) ~= dbm.NONE, true,
    "foreign key is present after upgrade with alter table")

  local changes, err = dbm:execute("insert into test values(2, 'abc')")
  is(changes, 1, "insert is processed")

  is(dbm:pragma("non-existing=10"), nil, "unknown pragma returns an error")
  is(dbm:pragma("user_version and more"), nil, "invalid pragma syntax returns an error")
  is(dbm:pragma("user_version=zzz"), dbm.NONE, "invalid pragma assignment returns NONE")
  is(dbm:pragma("user_version=5"), dbm.NONE, "valid pragma assignment returns NONE")
  is(dbm:pragma("user_version"), 5, "valid pragma query returns current value")

  dbm:exec("begin")  -- start transaction
  changes = dbm:execute({  -- this is done within a savepoint
      "insert into test values(3, 'abc')",
      "insert into test values(4, 'abc')",
      "update test set value = 'def' where key = 1",
    })
  dbm:exec("commit")  -- commit all changes

  is(changes, 3, "list of insert/update statements is processed")
  local row = dbm:fetchOne("select key, value from test where key = 1")
  is(row.key, 1, "select fetches expected value 1/2")
  is(row.value, "def", "select fetches expected value 2/2")
  is(row ~= dbm.NONE, true, "select fetch row not matching NONE")

  dbm:exec("begin")  -- start transaction
  dbm:exec("update test set value = 'abc' where key = 1")
  changes = dbm:execute({  -- this is done within a savepoint
      "update test set value = 'xyz' where key = 1",
      "update with some error",
    })
  dbm:exec("commit")  -- commit all changes
  is(changes, nil, "errors are reported from execute groups")

  local row = dbm:fetchOne("select key, value from test where key = 1")
  is(row.value, "abc", "changes with error get rolled back to savepoint")

  assert(dbm:pragma("foreign_keys=0"))
  assert(dbm:execute("delete from test where key = 1"))
  is(assert(dbm:fetchOne("select * from testref where key = 1")) ~= dbm.NONE, true,
    "foreign key is present when foreign_key check is disabled")
  ok, err = dbm:upgrade({delete = true})
  is(err, "foreign key check failed", "upgrade fails on foreign key violation")

  local none = dbm:fetchOne("select key, value from test where key = 0")
  is(none, dbm.NONE, "fetch returns NONE as empty result set")

  local query = "select key, value from test where key = 101"
  assert(dbm:fetchAll(query.."; -- comment"))
  is(dbm.prepcache[query] == nil, true, "compound statement is not cached (1/2)")
  is(dbm.prepcache[query.."; -- comment"] == nil, true, "compound statement is not cached (2/2)")

  assert(dbm:fetchOne(query))
  is(dbm.prepcache[query] ~= nil, true, "single statement is cached")

  assert(dbm:fetchAll(query..";"..query:gsub("101","102")))
  is(dbm.prepcache[query:gsub("101","102")] ~= nil, true, "last statement is cached")
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
fm.run{port = 8081, addr = {"abc", "def"}, headers = {RetryAfter = "bar"}}
is(brand:match("redbean/[.%d]+"), "redbean/2.1.3", "brand captured server version")
is(port, 8081, "port is set when passed")
is(addr, "-abc-def", "multiple values are set from a table")
is(header..":"..value, "Retry-After:bar", "default headers set when passed")

ok, err = pcall(fm.run, {cookieOptions = {}}) -- reset cookie options
is(ok, true, "run accepts valid options")

ok, err = pcall(fm.run, {invalidOptions = {}}) -- some invalid option
is(ok, false, "run fails on invalid options")
is(err:match("unknown option"), "unknown option", "run reports unknown option")

done()
