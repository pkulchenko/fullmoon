# Fullmoon

Fullmoon is a fast and minimalistic web framework based on [Redbean](https://redbean.dev/)
-- a portable, single-file distributable web server.

Everything you need comes in a single file with no external dependencies
(both for development and distribution) that runs on Windows, Linux, or
macOS. The following is a complete example of a Fullmoon application:

```lua
local fm = require "fullmoon"
fm.setTemplate("hello", "Hello, {%& name %}")
fm.setRoute("/user/:name", function(r)
    return fm.serveContent("hello", {name = r.params.name})
  end)
fm.run()
```

After it's packaged with Redbean (using the [installation instructions](#installation)),
it can be launched with `./redbean.com`, which starts a server listening
on port 8080.

## Why Fullmoon

Redbean is a single-file distributable cross-platform web server with
unique and powerful qualities. While there are several Lua-based
web frameworks ([Lapis](https://leafo.net/lapis/),
[Lor](https://github.com/sumory/lor), [Sailor](https://github.com/sailorproject/sailor),
[Pegasus](https://github.com/EvandroLG/pegasus.lua), and others),
none of them integrate with Redbean (with the exception of [anpan](https://git.sr.ht/~shakna/anpan)).

Fullmoon is a lightweight and minimalistic web framework that is
written from the perspective of showcasing all the capabilities that
Redbean provides by extending and augmenting them in the simplest and
the most efficient way possible. It runs fast and comes with batteries
included (routes, templates, JSON support and more).

Fullmoon follows the Lua philosophy and provides a minimal set of tools
to combine as needed and use as the basis to build upon.

### What Redbean provides

- Single file deployment and distribution
- Efficient serving of static and gzip encoded assets
- Integrated SSL support (using MbedTLS) including SSL virtual hosting
- Integrated crypto hashing (SHA1, SHA224/256/384/512, and BLAKE2B256)
- Integrated password-hashing (using Argon2)
- HTTP/HTTPS client for external requests
- Ships with Lua 5.4 and SQLite 3.35

### What Fullmoon adds

- Lightweight package (~500 LOC) with no external dependencies
- Simple and flexible routing with variables and custom filters
- Templating engine with JSON support and efficient memory utilization
- Optimized execution with pre-compiled components and lazy loaded methods
- Cookie/header generation and processing
- Custom 404 and other status pages
- Access to all Redbean features

## Installation

### Step 1: Get the latest Redbean (version 1.5+)

```sh
curl -o redbean.com https://justine.lol/redbean/redbean-latest.com
chmod +x redbean.com
```

You can also build Redbean yourself by following instructions for
the [source build](https://redbean.dev/#source).

### Step 2: Prepare Fullmoon code

- Copy `fullmoon.lua` to `.lua/` folder
- Save your code to a file named `.init.lua` (for example, the Lua
  code shown in the description).

Another option is to place your framework code into a separate file
(for example, `.lua/myapp.lua`) and add `require "myapp"` to `.init.lua`.

### Step 3: Package Fullmoon code with Redbean

```sh
zip redbean.com .init.lua .lua/fullmoon.lua
```

If your framework code is stored in a separate Lua file, make sure to
place it inside the `.lua/` folder and zip that file as well.

### Step 4: Run the server

```sh
./redbean.com
```

### Step 5: Check the result

Point your browser to http://127.0.0.1:8080/hello/world and you should
see "Hello, world" (assuming you are using the code shown [above](#fullmoon)
or the one in the [Usage](#usage) section).

## Usage

The simplest application would need to load the module, configure one
route, and run the application:

```lua
local fm = require "fullmoon"
fm.setRoute("/hello", function(r) return "Hello, world" end)
fm.run()
```

This application responds to any request for `/hello` URL with returning
"Hello, world" content (and 200 HTTP status) and responds with returning
404 status for all other requests.

## Quick reference

- `setRoute(routeOrConditions[, handlerOrNewPath])`: registers a route.
  If `routeOrConditions` is a string, then it's used as an
  [expression](#basic-routes) to compare the request path against. If it
  is a table, then its elements are strings that are used as routes and
  its hash values are [conditions](#conditional-routes) that the routes
  are checked against. If the second parameter is a function, then it's
  executed if all conditions are satisfied. If it's a string, then it's
  used as a route expression and the request is processed as if it is
  the specified route (acts as internal redirect). If any condition is
  not satisifed, then the next route is checked. The route expression
  can have multiple [parameters](#variable-routes) and
  [optional parts](#optional-parameters). The handler accepts a
  `request` table that provides access to request and route parameters,
  as well as headers and cookies.

- `setTemplate(name, templateOrHandlerOrOptions)`: associates a name
  with a template handler.
  If `templateOrHandlerOrOptions` is a string, then it's compiled into a
  template handler. If it's a table, then its first element is a
  template or a function and the rest are used as options. For example,
  specifying `ContentType` as one of the options sets the `Content-Type`
  header for the generated content. Two templates (`500` and `json`) are
  provided by default and can be overwritten.

- `makePath(routeOrPath[, parameters])`: creates a path from either a
  route name or a path string by populating its parameters using values
  from the parameters table.
  The path doesn't need to be just a path and can be a URL as well.
  [Optional parts](#optional-parameters) are removed if they include
  parameters that are not provided.

- `makeUrl([url,] options)`: creates a URL using the provided value and
  a set of URL parameters provided in the `options` table: scheme, user,
  pass, host, port, path, and fragment.
  The `url` parameter is optional; the current path is used if `url` is
  not specified. Any of the options can be provided. For example,
  `fm.makeUrl({scheme="https"})` sets the scheme for the current URL to
  `https`.

- `serveResponse(status[, headers][, body])`: sends an HTTP response
  using provided `status`, `headers`, and `body` values.
  `headers` is an optional table populated with HTTP header name/value
  pairs. Header names are case-insensitive, but provided aliases for
  header names with dashes *are* case-sensitive: `{ContentType = "foo"}`
  is an alternative form for `{["Content-Type"] = "foo"}`. `body` is an
  optional string.

- `serveContent(name, parameters)`: renders a template using provided
  parameters.
  `name` is a string that names the template (as set by a `setTemplate`
  call) and `parameters` is a table with template parameters (referenced
  as variables in the template).

- `run([options])`: runs the server using configured routes.
  By default the server listens on localhost and port 8080. These values
  can be changed by setting `addr` and `port` values in the
  [`options` table](#running-application).

## Documentation

Each Fullmoon application follows the same basic flow with five main
components:

- runs redbean server with a desired configuration, which
- filters each request based on specified conditions, and
- routes it to an action handler, that
- generates some content (using provided template engine), and
- serves a response

Let's look at each of the components starting from the request routing.

### Requests and actions

Fullmoon handles each HTTP request using same process:

- takes the path URL and matches it against each route URL in the order
  in which routes are registered
- verifies conditions for those routes that match
- calls a specified action handler (passing a request table) for those
  routes that satisfy all conditions
- serves the result if anything other than `false` or `nil` returned
  from the action handler (and continues the process otherwise)

In general, route definitions bind request URLs (and a set of conditions)
to action handlers. All conditions are checked in a random order for
each URL that matches the route definition. As soon as any condition
fails, the route processing is aborted and the next route is checked
with one exception: the condition can set the `otherwise` value, which
sends a response with the specified status.

If no route matches the request, then the default 404 processing is
triggered, which can be customized by registering a custom 404 template
(`fm.setTemplate("404", "My 404 page...")`).

#### Basic routes

Each route takes a path that matches exactly, so the route `"/hello"`
matches requests for `/hello` and doesn't match `/hell`, `/hello-world`,
or `/hello/world`. To match a path where `/hello` is only a part of it,
[optional parameters and splat can be used](#optional-parameters)).

```lua
fm.setRoute("/hello", function(r) return "Hello, World!" end)
```

This application responds with "Hello, World!" for all requests
directed at the `/hello` path and returns 404 for all other requests.

#### Variable routes

In addition to fixed routes, any path may include placeholders for
parameters, which are identified by a `:` followed immediately by
the parameter name:

```lua
fm.setRoute("/hello/:name",
  function(r) return "Hello, "..(r.params.name) end)
```

Each parameter matches one or more characters except `/`, so the route
`"/hello/:name"` matches `/hello/alice`, `/hello/bob`, `/hello/123` and
does not match `/hello/bob/and/alice` (because of the non-matched
forward slashes) or `/hello/` (because the length of the to-be-matched
fragment is zero).

Parameter names can only include alphanumeric characters and `_`.

Parameters can be accessed using the request table and its `params`
table, such that `r.params.name` can be used to get the value of the
`name` parameter from the earlier example.

There is another kind of parameter called splat that is written as `*`
and matches zero or more characters, *including* a forward slash (`/`).
The splat is also stored in the `params` table under the `splat` name.
For example, the route `"/download/*"` matches `/download/my/file.zip`
and the splat gets the value of `my/file.zip`. If multiple splats are
needed in the same route, then splats can be assigned names similar to
other parameters: `/download/*splat/*rest.zip` (although the same result
can be achieved using `/download/*splat/:rest.zip`, as the first splat
is going to capture all path parts except the filename).

All parameters (including the splat) can appear in any part of the path
and can be surrounded by other text, which needs to be matched exactly.
This means that the route `"/download/*/:name.:ext"` matches
`/download/my/path/file.zip` and `params.name` gets `file`,
`params.ext` gets `zip` and `params.splat` gets `my/path` values.

#### Optional parameters

Any specified route fragment or parameter can be declared as optional by
wrapping it into parentheses:

```lua
fm.setRoute("/hello(/:name)",
  function(r) return "Hello, "..(r.params.name or "World!") end)
```

In the example above, both `/hello` and `/hello/Bob` are going to be
accepted, but not `/hello/`, as the trailing slash is part of the
optional fragment and `:name` still expects one or more characters.

Any optional parameter that is not matched gets a `nil` value, so in the
case above "Hello, World!" gets returned for the `/hello` request URL.

More than one optional parameter can be specified and optional
fragments can be nested, so both `"/posts(/:pid/comments(/:cid))"` and
`"/posts(/:pid)/comments(/:cid)"` are valid route values.

#### Custom parameters

The default value for the parameters is all characters (except `/`) of
length one or more. To specify a different set of valid characters, it
can be added at the end of the variable name; for example, using
`:id[%d]` instead of `:id` changes the parameter to match only digits.

```lua
fm.setRoute("/hello(/:id[%d])",
  function(r) return "Hello, "..(r.params.id or "World!") end)
```

The following Lua character classes are supported: `%w`, `%d`, `%a`,
`%l`, `%u`, and `%x`; any punctuation character (including `%` and `]`)
can also be escaped with `%`. Negative classes (written in Lua as `%W`)
are not supported, but not-in-set syntax is supported, so `[^%d]`
matches a parameter that doesn't include any digits.

Note that the number of repetitions can't be changed (so `:id[%d]*`
is not a valid way to accept zero-or-more digits), as only sets are
allowed and the values still accept one or more characters. If more
flexibility in describing acceptable formats is needed, then [custom
validators](#custom-valdators) can be used to extend the matching logic.

#### Query and Form parameters

Query and form parameters can be accessed in the same way as the path
parameters using the `params` table in the `request` table that is
passed to each action handler. Note that if there is a conflict between
parameter and query/form names, then parameter names take precedence.

#### Handling of HTTP methods

Each registered route by default responds to all HTTP methods (GET, PUT,
POST, etc.); if an application needs to execute different functions
depending on the request method, the library provides two main options
to support this: (1) check for the request method inside an action
handler (using `request.method` value) and (2) add a condition that
filters out requests such that only request with the specified method(s)
reach the action handler:

```lua
fm.setRoute(fm.GET"/hello(/:name)",
  function(r) return "Hello, "..(r.params.name or "World!") end)
```

In this case, the syntax `fm.GET"/hello(/:name)"` configures the route
to only accept `GET` requests. This syntax is equivalent to passing a
table with the route and any additional filtering conditions:

```lua
fm.setRoute({"/hello(/:name)", method = "GET"},
  function(r) return "Hello, "..(r.params.name or "World!") end)
```

If more than one method needs to be specified, then a table with a list
of methods can be passed instead of one string value:

```lua
fm.setRoute({"/hello(/:name)", method = {"GET", "POST"}},
  function(r) return "Hello, "..(r.params.name or "World!") end)
```

Every route that allows a `GET` request also (implicitly) allows a
`HEAD` request and that request is handled by returning all headers
without sending the body itself. If for some reason this implicit
handling is not desirable, then adding `HEAD = false` to the method
table disables it (as in `method = {"GET", "POST", HEAD = false}`).

Note that requests with non-matching methods don't get rejected, but
rather fall through to be checked by other routes and trigger the 404
status returned if they don't get matched.

#### Conditional routes

In addition to `method`, other conditions can be applied using `host`,
`clientAddr`, `serverAddr`, `scheme`, request headers, and parameters.
For example, specifying `username = "Bob"` as one of the conditions
ensures the value of the `username` parameter to be "Bob" for the action
handler to be called.

Any request header can be checked using the header name as the key, so
`ContentType = "multipart/form-data"` is satisfied if the value of the
`Content-Type` header is `multipart/form-data`. Note that the header
value may include other elements (a boundary or a charset as part of
the `Content-Type` value) and the actual media type is compared.

#### Custom validators

String values are not the only values that can be used in conditional
routes. If more than one value is acceptable, passing a table allows to
provide a list of acceptable values. For example, if `Bob` and `Alice`
are acceptable values, then `username = {Bob = true, Alice = true}`
expresses this as a condition.

Two special values passed in a table allow to apply a *regex* or a
*pattern* validation:

- *regex*: accepts a string that has a regular expression. For example,
  `username = {regex = "^(Bob|Alice)$"}` has the same result as the hash
  check shown earlier in this section
- *pattern*: accepts a string with a Lua patern expression. For example,
  `username = {pattern = "^%u%l+$"}` accepts values that start with an
  uppercase character followed by one or more lowercase characters.

These two checks can be combined with the table existence check:
`username = {Bob = true, regex = "^Alice$"}` accepts both `Bob` and
`Alice` values. If the first table-existence check fails, then the
results of the `regex` or `pattern` expression is returned.

The last type of a custom validator is a function. The provided function
receives the value to validate and its result is evaluated as `false` or
`true`. For example, passing `id = tonumber` ensures that the passed
`id` value is a number. Alternatively, `clientAddr = fm.isLoopbackIp`
ensures that the client address is a loopback ip address.

```lua
fm.setRoute({"/local-only", clientAddr = fm.isLoopbackIp},
  function(r) return "Local content" end)
```

As the validator function can be generated dynamically, this works too:

```lua
local function isLessThan(n)
  return function(l) return tonumber(l) < n end
end
fm.setRoute(fm.POST{"/upload", ContentLength = isLessThan(100000),
    otherwise = 413}, function(r) ...handle the upload... end)
```

It's important to keep in mind that the validator function actually
returns a function that is going to be called during a request to apply
the check. In the previous example, the returned function accepts a
header value and compares it with the limit passed during its creation.

If the status returned needs to only apply to the `ContentLength` check,
then the `otherwise` value along with the validator function can be
moved to a table associated with the `ContentLength` check:

```lua
fm.setRoute(fm.POST{"/upload",
    ContentLength = {isLessThan(100000), otherwise = 413}
  }, function(r) ...handle the upload... end)
```

Note that when the checked value is `nil`, the check against a table is
deemed to be valid and the route is not going to be rejected. For
example, a check for an optional parameter made against a string
(`name = "Bo"`) fails if the value of `params.name` is `nil`, but passes
if the same check is made against a table (`name = {Bo=true, Mo=true}`),
including regex/pattern checks. If this is not desirable, then a custom
validator function can explicitly check for the correct value.

#### Responding on failed conditions

In some cases, failing to satisfy a condition is a sufficient reason to
returns some status back to the client without checking other routes. In
a case like this, setting `otherwise` value to a number or a function
returns either a response with the specified status or the result of the
function:

```lua
fm.setRoute({"/hello(/:name)",
    method = {"GET", "POST", otherwise = 405}},
  function(r) return "Hello, "..(r.params.name or "World!") end)
```

In this example, if this endpoint is accessed with the `PUT` method,
then instead of falling through to other routes (because the `method`
condition is not satisfied), 405 status is returned, as configured with
the `otherwise` value. As already mentioned, this route accepts a `HEAD`
request too (even when not listed), as a `GET` request is accepted.

When 405 (Bad method) status is returned and the `Allow` header is not
set, it is set to the list of methods allowed by the route. In the case
above it is set to `GET, POST, HEAD, OPTIONS` values, as those are the
methods allowed by this configuration. If the `otherwise` value is a
function (rather than a number), then returning a proper result and
setting the `Allow` header is the responsibility of this function.

The `otherwise` value can also be set to a function, which provides more
flexibility than just setting a status value. For example, setting
`otherwise = fm.serveResponse(413, "Payload Too Large")` triggers a
response with the specified status and message.

#### Multiple routes

Despite all examples showing a single route, it's rarely the case in
real applications; when multiple routes are present, they are always
*evaluated in the order in which they are registered*. Multiple action
handlers can be executed in the course of handling one request and as
soon as one handler returns a result that is evaluated as a non-`false`
value, the route handling process ends. Returning `false` or `nil` from
an action handlers continues the route processing, which allows
implementing some common processing that applies to multiple routes
(similar to what is done using "before" filters in other frameworks):

```lua
local uroute = "/user/:id"
fm.setRoute({uroute.."/*", method = {"GET", "POST", otherwise = 405}},
    function(r)
      -- retrieve user information based on r.params.id
      -- and store in r.user (as one of the options);
      -- return error if user is not found
      return false -- continue handling
  end)
fm.setRoute(fm.GET(uroute.."/view"), function(r) ... end)
fm.setRoute(fm.GET(uroute.."/edit"), function(r) ... end)
fm.setRoute(fm.POST(uroute.."/edit"), function(r) ... end)

```

In this example, the first route can generate three outcomes:

- if the route is not matched, then other (later set) routes are checked
- if the route is matched, but the condition (the `method` check) is not
  matched, then 405 status is returned
- if the route is matched and the action handler is executed, it either
  retrieves the user and returns `false`, which continues processing
  with other routes, or fails to retrieve the user and returns an error.

One `setRoute` call can also set multiple routes when they have the same
set of conditions and the same action handler:

```lua
fm.setRoute(fm.GET{"/route1", "/route2"}, handler)
```

This is equivalent to two calls setting each route individually:

```lua
fm.setRoute(fm.GET"/route1", handler)
fm.setRoute(fm.GET"/route2", handler)
```

Given that routes are evaluated in the order in which they are set, more
selective routes need to be set first, otherwise they may not get a
chance to be evaluated:

```lua
fm.setRoute(fm.GET"/user/bob", handlerBob)
fm.setRoute(fm.GET"/user/:name", handlerName)
```

If the routes are set in the opposite order, `/user/bob` may never be
checked as long as the `"/user/:name"` action handler returns some
non-false result.

#### Named routes

Each route can be provided with an optional name, which is useful in
referencing that route when its URL needs to be generated based on
specific parameter values. Provided `makePath` function accepts either
a route name or a route URL itself as well as the parameter table and
returns a path with populated parameter placeholders:

```lua
fm.setRoute("/user/:name", handlerName)
fm.setRoute({"/post/:id", routeName = "post"}, handlerPost)

fm.makePath("/user/:name", {name = "Bob"}) --> /user/Bob
fm.makePath("/post/:id", {id = 123}) --> /post/123
fm.makePath("post", {id = 123}) --> /post/123, same as the previous one
```

If two routes use the same name, then the name is associated with the
one that was registered last, but both routes are still be present.

The route name can also be used with external/static routes that are
only used for URL generation.

### Request table and parameters

### Templating engine

#### Configuring templates (including setting content type)

#### Serving template outputs

#### Including templates into other templates

#### Passing parameters to templates

#### Processing layouts

### Serving responses

In addition to strings and template output, the application can serve
other results: responses (`serveResponse`), redirects (`serveRedirect`),
static assets (`serveAsset`), errors (`serveError`), directory index
(`serveIndex`), and internal redirects/resources (`servePath`). This
section covers each of the results in more detail.

#### Serving response

#### Serving redirect

#### Serving static asset

#### Serving error

#### Serving directory index

#### Serving path (internal redirect)

### Running application

`run` method executes the configured application. By default the server
is launched listening on localhost and port 8080. Both of these
values can be changed by passing `addr` and `port` options:

```lua
fm.run({addr = "localhost", port = 8080})
```

The following options are supported; the default values are shown in
parentheses and options marked with `mult` can set multiple values by
passing a table:

- `addr`: sets the address to listen on (mult)
- `brand`: sets the Server header value (`"redbean/[ver] fullmoon/[ver]"`)
- `cache`: configures `Cache-Control` and `Expires` headers for all static
  assets served (in seconds). A negative value disables the headers.
  Zero means no cache.
- `certificate`: sets the TLS certificate value (mult)
- `directory`: sets local directory to serve assets from (mult)
- `header`: sets default headers added to each response by passing table
  with header-value pairs
- `logMessages`: enables logging of message headers
- `pidPath`: sets the pid file path on the local file system
- `port`: sets the port number to listen on (8080)
- `privateKey`: sets the TLS private key value (mult)
- `sslTicketLifetime`: sets the duration (sec) of the ssl ticket (86400)

The `key` and `certificate` string values can be populated using the
`getAsset` method that can access both assets packaged within the
webserver archive and those stored in the file system.

### Logging

## Status

Highly experimental with everything being subject to change.

## Author

Paul Kulchenko (paul@zerobrane.com)

## License

See [LICENSE](LICENSE).
