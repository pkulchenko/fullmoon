-- showcase for various Fullmoon capabilities and usage examples

local fm = require "fullmoon"

-- template from a string
fm.setTemplate("hello", "Hello, {%& name %}")

-- template shown when 404 is returned
fm.setTemplate("404", "Nothing here")

-- serve 403 status code;
-- this is the same as any of the following:
-- - fm.serveError(403)
-- - fm.serveError(403, "Access forbidden")
-- - function(r) return fm.serveError(403) end
-- `fm.GET"route"` is equivalent to `{"route", method = "GET"}`
fm.setRoute(fm.GET"/status403", fm.serve403)

-- enforce https by forwarding all non-https requests to the same URL with https
-- the user needs to accept the warning, as Redbean is using self-signed cert
fm.setRoute({"/*", scheme = "https",
  otherwise = function() return fm.serveRedirect(fm.makeUrl{scheme = "https"}) end})

-- this triggers default processing for any (static/lua) file that matches the route
-- if nothing is matched, the next route is going to be checked
-- (this is the same behavior as triggered by returning `false` from a route handler)
-- for example, try /help.txt
fm.setRoute("/help.*", fm.serveAsset)

-- favicon.ico is served as a static asset
fm.setRoute("/favicon.ico", fm.serveAsset)

-- internal redirect to rewrite URLs for existing resources.
-- for example, `/static/help.txt` is mapped to `/help.txt` and returned
-- if it exists (it does in the default Redbean configuration).
-- if the resource doesn't exist, the next route is checked
fm.setRoute("/static/*", "/*")

-- this serves redirect to `/user/alice/foo`
-- 307 is sent by default, but another redirect code
-- can be set as the second parameter to `serveRedirect`
fm.setRoute("/user/redirect",
  fm.serveRedirect(fm.makePath("/user/:username/*", {username = "alice", splat = "foo"})))

-- this add basic auth protection to `/auth-only`
-- the password is (optionally) hashed and
-- can also be crypto hashed if `key` is specified
local hash = "SHA384"
local pass = GetCryptoHash(hash, "pass") -- simulates password pre-hashing
local basicAuth = fm.makeBasicAuth({user = pass}, {realm = "Need password", hash = hash})
fm.setRoute({"/auth-only", authorization = basicAuth},
  fm.serveResponse(200, "basic auth protected"))

-- this result is only available to a local client
-- (other requests fall through to other routes)
fm.setRoute({"/local-only", clientAddr = {fm.isLoopbackIp, otherwise = 403}},
  fm.serveResponse(200, "local only"))

-- check for the payload size and return 413 error if it's larger than the threshold
local function isLessThan(n) return function(l) return tonumber(l) < n end end
fm.setRoute(fm.POST{"/upload", ContentLength = {isLessThan(100000), otherwise = 413}},
  function(r) fm.storeAsset("uploaded", r.body) end)

-- specify route with an optional segment
-- :username is captured as "username", * is captured as "splat"
fm.setRoute({"/user(/:username(/*))",
    -- set additional filters;
    -- (can match method, host, port, clientAddr, serverAddr, request headers, and parameters)
    -- match "method" and check if the value is GET/POST; if not, return 405.
    -- HEAD method is also allowed and handled everywhere where GET is allowed;
    -- this behavior can be disabled by adding `HEAD=false` to the `method` table
    method = {"GET", "POST", otherwise = 405},
    -- splat (* capture) can be checked too; splat is only matched if present
    -- this uses "regex"; "pattern" is also available for Lua patterns
    splat = {regex = "^(foo|bar)$"},
    -- if something doesn't match, return 400
    -- (unless there is some condition-specific "otherwise" value,
    -- like the one set for `method`)
    otherwise = 400,
  }, function(r)
    -- log a message with INFO level
    fm.logInfo("serving user content")
    -- set a header value if splat value is set
    -- all optional parameters are set to `false` if not provided,
    -- which allows the user to distinguish between empty and not-provided value
    if r.params.splat then
      r.headers.xsplat = r.params.splat
    end
    -- serve content from template "hello" with specific parameters
    return fm.serveContent("hello", {name = r.params.username or "default"})
  end)

-- Lua value can be returned as JSON using provided "json" template
fm.setRoute("/json", fm.serveContent("json", {success = "ok"}))

-- Lua value can be returned as JSON using provided "json" template
fm.setRoute("/session", function(r)
    local counter = (r.session.counter or 0) + 1
    if counter >= 5 then
      r.session = nil
    else
      r.session.counter = counter
    end
    return fm.serveContent("json", {counter = counter})
  end)


-- any other path is redirected to .txt (if available)
-- this is an internal redirect, so no 3xx is going to be returned
-- this expression is roughly the same as replacing "/*path.txt" with
-- `function(r) return fm.servePath(fm.makePath("/*path.txt", r.params)) end`
-- for example, try `/help`
fm.setRoute("/*path", "/*path.txt")

-- if nothing matched, then 404 is triggered (and the 404 template is served if configured)

-- configure the main loop with the provided parameters
fm.run({port = 8080})
