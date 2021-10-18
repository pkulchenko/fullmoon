--
-- nano-webframework implementation for Redbean web server (https://redbean.dev/)
-- Copyright 2021 Paul Kulchenko
-- 

--[[-- support functions --]]--

local Write = Write or io.write
local EscapeHtml = EscapeHtml or function(s) return (string.gsub(s, "&", "&amp;"):gsub('"', "&quot;"):gsub("<","&lt;"):gsub(">","&gt;")) end

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
local ref = "params"
local function render(name, opt)
  assert(type(name) == "string", "bad argument #1 to render (string expected)")
  assert(templates[name], "bad argument #1 to render (unknown template name)")
  -- take parameters from the caller (if any); useful for `include` in templates
  local parent = debug.getinfo(2, "f").func
  -- add local variables from the current environment
  local params = addlocals(getfenv(templates[name])[ref] or {})
  -- add explicitly passed parameters
  for k, v in pairs(type(opt) == "table" and opt or {}) do params[k] = v end
  -- set the calculated parameters to the current template
  getfenv(templates[name])[ref] = params
  return templates[name]()
end

local function parse(tmpl)
  local EOT = "\0"
  local function writer(s) return #s > 0 and ("Write(%q)"):format(s) or "" end
  local tupd = (tmpl.."{%"..EOT.."%}"):gsub("(.-){%%([=&]*)%s*(.-)%s*%%}", function(htm, pref, val)
      return writer(htm)
        ..(val ~= EOT -- this is not the suffix
            and (pref == "" -- this is a code fragment
              and val.." "
              or ("Write(%s(%s or ''))"):format(pref == "&" and "EscapeHtml" or "", val))
            or "")
    end)
  return tupd
end

local function addtemplate(name, code, opt)
  assert(type(name) == "string", "bad argument #1 to addtemplate (string expected)")
  assert(type(code) == "string", "bad argument #2 to addtemplate (string expected)")
  local env = setmetatable({Write = Write, EscapeHtml = EscapeHtml, include = render, [ref] = opt},
    {__index = function(t, key) return rawget(t, ref) and t[ref][key] or _G[key] end})
  templates[name] = setfenv(assert((loadstring or load)(parse(code), code)), env)
end

--[[-- return library --]]--

if pcall(debug.getlocal, 4, 1) then return {addtemplate = addtemplate, render = render} end

--[[-- run tests if launched as a script --]]--

local out = ""
Write = function(s) out = out..s end
local num = 1
local section = ""
local function outformat(s) return type(s) == "string" and ("%q"):format(s):gsub("\n","n") or tostring(s) end
local function is(result, expected, message)
  local ok = result == expected
  local msg = ("%s %d\t%s%s"):format((ok and "ok" or "not ok"), num, (section > "" and section.." " or ""), message)
  if not ok then
    msg = msg .. ("\n\treceived: %s\n\texpected: %s"):format(outformat(result), outformat(expected))
  end
  print(msg)
  num = num + 1
  out = ""
end

section = "(template)"
local tmpl1 = "tmpl1"
addtemplate(tmpl1, "Hello, World!")
render(tmpl1)
is(out, "Hello, World!", "text rendering")

addtemplate(tmpl1, "Hello, {%& title %}!")
render(tmpl1, {title = "World"})
is(out, "Hello, World!", "text with parameter")

render(tmpl1, {title = "World&"})
is(out, "Hello, World&amp;!", "text with encoded parameter")

addtemplate(tmpl1, "Hello, {% for i, v in ipairs({3,2,1}) do %}-{%= v %}{% end %}")
render(tmpl1)
is(out, "Hello, -3-2-1", "Lua code")

local tmpl2 = "tmpl2"
addtemplate(tmpl2, [[{a: "{%= title %}"}]])
render(tmpl2)
is(out, '{a: ""}', "JSON with empty local value")

do
  addtemplate(tmpl2, [[{a: "{%= title %}"}]], {title = "set when adding template"})
  render(tmpl2)
  is(out, '{a: "set when adding template"}', "JSON with value set when adding template")
  
  local title = "local value"
  render(tmpl2)
  is(out, '{a: "local value"}', "JSON with local value")

  render(tmpl2, {title = "set from render"})
  is(out, '{a: "set from render"}', "JSON with a passed value set at rendering")

  addtemplate(tmpl2, [[{% local title = "set from template" %}{a: "{%= title %}"}]])
  render(tmpl2)
  is(out, '{a: "set from template"}', "JSON with value set from template")

  addtemplate(tmpl2, [[{a: "{%= title %}"}]], {title = "set when adding"})
  render(tmpl2)
  is(out, '{a: "local value"}', "JSON with local value overwriting the one set when adding template")
end

addtemplate(tmpl1, "Hello, {% include('tmpl2') %}")
render(tmpl1)
is(out, [[Hello, {a: "local value"}]], "`include` other template with a local value")

addtemplate(tmpl1, [[Hello, {% include('tmpl2', {title = "value"}) %}]])
render(tmpl1)
is(out, [[Hello, {a: "value"}]], "`include` other template with passed value set at rendering")

addtemplate(tmpl1, [[Hello, {% local title = "another value"; include('tmpl2') %}]])
render(tmpl1)
is(out, [[Hello, {a: "another value"}]], "`include` other template with value set from template")

addtemplate(tmpl1, "Hello, World!\n{% main() %}")
local ok, err = pcall(render, tmpl1)
is(err ~= nil, true, "report Lua error in template")
is(err:match('string "Hello, World!'), 'string "Hello, World!', "error references original template code")
is(err:match(':2: attempt to call'), ':2: attempt to call', "error references expected line number")

addtemplate(tmpl1, "Hello, {% main() %}World!", {main = function() end})
render(tmpl1)
is(out, [[Hello, World!]], "used function can be passed when adding template")

addtemplate(tmpl2, [[{% local function main() %}<h1>Title</h1>{% end %}{% include "tmpl1" %}]])
render(tmpl2)
is(out, [[Hello, <h1>Title</h1>World!]], "function can be overwritten with template fragments in extended template")

addtemplate(tmpl2, [[{% local function main() Write"<h1>Title</h1>" end %}{% include "tmpl1" %}]])
render(tmpl2)
is(out, [[Hello, <h1>Title</h1>World!]], "function can be overwritten with direct write in extended template")
