# Fullmoon

Fullmoon is a [fast](#benchmark) and minimalistic web framework
based on [Redbean](https://redbean.dev/)
-- a portable, single-file distributable web server.

Everything needed for development and distribution comes in a single file with
no external dependencies and after packaging with Redbean runs on Windows,
Linux, or macOS. The following is a complete example of a Fullmoon application:

```lua
local fm = require "fullmoon"
fm.setTemplate("hello", "Hello, {%& name %}")
fm.setRoute("/hello/:name", function(r)
    return fm.serveContent("hello", {name = r.params.name})
  end)
fm.run()
```

After it is [packaged with Redbean](#installation), it can be launched
using `./redbean.com`, which starts a server that returns "Hello, world"
to an HTTP(S) request sent to http://localhost:8080/hello/world.

## Contents

- [Why Fullmoon](#why-fullmoon)
  - [What Redbean provides](#what-redbean-provides)
  - [What Fullmoon adds](#what-fullmoon-adds)
- [Installation](#installation)
- [Usage](#usage)
- [Quick reference](#quick-reference)
- [Examples](#examples)
  - [Showcase example](#showcase-example)
  - [TechEmpower benchmark example](#techempower-benchmark-example)
  - [htmx board example](#htmx-board-example)
  - [htmx SSE example](#htmx-sse-example)
- [Documentation](#documentation)
  - [Routes](#routes)
    - [Basic routes](#basic-routes)
    - [Routes with parameters](#routes-with-parameters)
    - [Optional parameters](#optional-parameters)
    - [Custom parameters](#custom-parameters)
    - [Query and Form parameters](#query-and-form-parameters)
    - [Multiple routes](#multiple-routes)
    - [Named routes](#named-routes)
    - [External routes](#external-routes)
    - [Internal routes](#internal-routes)
  - [Conditions](#conditions)
    - [Handling of HTTP methods](#handling-of-http-methods)
    - [Conditional routes](#conditional-routes)
    - [Custom validators](#custom-validators)
    - [Responding on failed conditions](#responding-on-failed-conditions)
    - [Form validation](#form-validation)
  - [Actions](#actions)
  - [Requests](#requests)
    - [Headers](#headers)
    - [Cookies](#cookies)
    - [Session](#session)
    - [Utility functions](#utility-functions)
  - [Templates](#templates)
    - [Configuring templates](#configuring-templates)
    - [Serving template outputs](#serving-template-outputs)
    - [Passing parameters to templates](#passing-parameters-to-templates)
    - [Including templates in other templates](#including-templates-in-other-templates)
    - [Processing layouts](#processing-layouts)
  - [Schedules](#schedules)
  - [Responses](#responses)
    - [Serving response](#serving-response)
    - [Serving redirect](#serving-redirect)
    - [Serving static asset](#serving-static-asset)
    - [Serving error](#serving-error)
    - [Serving directory index](#serving-directory-index)
    - [Serving path (internal redirect)](#serving-path-(internal-redirect))
  - [Running application](#running-application)
    - [Cookie options](#cookie-options)
    - [Session options](#session-options)
  - [Logging](#logging)
  - [Database management](#Database-management)
- [Benchmark](#benchmark)
- [Status](#status)
- [Author](#author)
- [License](#license)

## Why Fullmoon

Redbean is a single-file distributable cross-platform web server with
unique and powerful qualities. While there are several Lua-based
web frameworks ([Lapis](https://leafo.net/lapis/),
[Lor](https://github.com/sumory/lor),
[Sailor](https://github.com/sailorproject/sailor),
[Pegasus](https://github.com/EvandroLG/pegasus.lua), and others),
none of them integrate with Redbean (although there is an experimental
framework [anpan](https://git.sr.ht/~shakna/anpan)).

Fullmoon is a lightweight and minimalistic web framework that is
written from the perspective of showcasing all the capabilities that
Redbean provides by extending and augmenting them in the simplest and
the most efficient way. It runs fast and comes with batteries included
(routes, templates, JSON generation and more).

Fullmoon follows the Lua philosophy and provides a minimal set of tools
to combine as needed and use as the basis to build upon.

### What Redbean provides

- Single file deployment and distribution (Linux, Windows, and macOS)
- Integrated SSL support (using MbedTLS) including SSL virtual hosting
- Integrated crypto hashing (SHA1, SHA224/256/384/512, and BLAKE2B256)
- Efficient serving of static and gzip encoded assets
- Integrated password-hashing (using Argon2)
- pledge/unveil sandboxing (where supported)
- unix.* module for Unix system interfaces
- HTTP/HTTPS client for external requests
- JSON and Lua serialization and parsing
- Ships with Lua 5.4 and SQLite 3.35

### What Fullmoon adds

- Lightweight package (~1000 LOC) with no external dependencies
- Simple and flexible routing with variables and custom filters
- Template engine with JSON support and efficient memory utilization
- Optimized execution with pre-compiled routes and lazy loaded methods
- Response streaming and Server-Sent Events support
- Cookie/header/session generation and processing
- Parametrized URL rewrites and re-routing
- Form validation with a variety of checks
- Cron syntax for scheduling Lua functions
- Custom 404 and other status pages
- Access to all Redbean features

## Installation

### Step 1: Get the latest Redbean (v2.0+)

Download a copy of Redbean by running the following commands (skip the second
one if running these commands on Windows):

```sh
curl -o redbean.com https://justine.lol/redbean/redbean-latest.com
chmod +x redbean.com
```

Another option is to build Redbean from source by following instructions for
the [source build](https://redbean.dev/#source).

Note that using response streaming and Server-Sent Events requires using
[Redbean v2.0 or later](https://redbean.dev/).

### Step 2: Prepare Fullmoon code

- Copy `fullmoon.lua` to `.lua/` folder
- Save the application code to a file named `.init.lua` (for example, the Lua
  code shown in the [description](#fullmoon)).

Another option is to place the application code into a separate file
(for example, `.lua/myapp.lua`) and add `require "myapp"` to `.init.lua`.
This is how [all included examples](#examples) are presented.

### Step 3: Package Fullmoon code with Redbean

```sh
zip redbean.com .init.lua .lua/fullmoon.lua
```

If the application code is stored in a separate Lua file, as described above,
make sure to place it inside the `.lua/` folder and zip that file as well.

### Step 4: Run the server

```sh
./redbean.com
```

If this command is executed on Linux and throws an error about not finding
interpreter, it should be fixed by running the following command (although note
that it may not survive a system restart):

```sh
sudo sh -c "echo ':APE:M::MZqFpD::/bin/sh:' >/proc/sys/fs/binfmt_misc/register"
```

If this command produces puzzling errors on WSL or WINE when using Redbean 2.x,
they may be fixed by disabling binfmt_misc:

```sh
sudo sh -c 'echo -1 >/proc/sys/fs/binfmt_misc/status'
```

### Step 5: Check the result

Launch a browser pointing at http://localhost:8080/hello/world and it should
return "Hello, world" (assuming the application is using the code shown in the
[introduction](#fullmoon) or the one in the [usage](#usage) section).

## Usage

The simplest example needs to (1) load the module, (2) configure one route,
and (3) run the application:

```lua
local fm = require "fullmoon" -- (1)
fm.setRoute("/hello", function(r) return "Hello, world" end) -- (2)
fm.run() -- (3)
```

This application responds to any request for `/hello` URL with returning
"Hello, world" content (and 200 HTTP status) and responds with returning
404 status for all other requests.

## Quick reference

- `setRoute(route[, action])`: registers a route.
  If `route` is a string, then it is used as a route [expression](#basic-routes)
  to compare the request path against. If it is a table, then its
  elements are strings that are used as [routes](#multiple-routes) and
  its hash values are [conditions](#conditional-routes) that the routes
  are checked against.
  If the second parameter is a [function](#actions), then it is executed
  if all conditions are satisfied. If it is a string, then it is used as
  a route expression and the request is processed as if it is sent at
  the specified route (acts as an [internal redirect](#internal-routes)).
  If any condition is not satisifed, then the next route is checked. The
  route expression can have multiple [parameters](#routes-with-parameters)
  and [optional parts](#optional-parameters). The action handler accepts
  a [request table](#requests) that provides access to request and route
  parameters, as well as [headers](#headers), [cookies](#cookies), and
  [session](#session).

- `setTemplate(name, template)`: registers a template with the specified
  name.
  If `template` is a string, then it's compiled into a template handler.
  If it is a function, it is stored and called when rendering of the
  template is requested. If it's a table, then its first element is a
  template or a function and the rest are used as options. For example,
  specifying `ContentType` as one of the options sets the `Content-Type`
  header for the generated content. Two templates (`500` and `json`) are
  provided by default and can be overwritten.

- `serveResponse(status[, headers][, body])`: sends an HTTP response
  using provided `status`, `headers`, and `body` values.
  `headers` is an optional table populated with HTTP header name/value
  pairs. If provided, this set of headers *removes all other headers*
  set earlier during handling of the same request. Header names are
  *case-insensitive*, but provided aliases for header names with dashes
  are *case-sensitive*: `{ContentType = "foo"}` is an alternative form
  for `{["Content-Type"] = "foo"}`. `body` is an optional string.

- `serveContent(name, parameters)`: renders a template using provided
  parameters.
  `name` is a string that names the template (as set by a `setTemplate`
  call) and `parameters` is a table with template parameters (referenced
  as variables in the template).

- `run([options])`: runs the server using configured routes.
  By default the server listens on localhost and port 8080. These values
  can be changed by setting `addr` and `port` values in the
  [`options` table](#running-application).

## Examples

Running examples requires including a `require` statement in the `.init.lua`
file, which loads the module with each example code, so for the showcase
example implemented in `showcase.lua`, `.init.lua` includes the following:

```lua
-- this is the content of .init.lua
require "showcase"
-- this loads `showcase` module from `.lua/showcase.lua` file,
-- which also loads its `fullmoon` dependency from `.lua/fullmoon.lua`
```

### Showcase example

The [showcase example](examples/showcase.lua) demonstrates several Fullmoon features:
- serving static assets (using `serveAsset`)
- setting http to https redirect
- setting 404 template
- configuring internal redirect
- configuring external redirect (using `serveRedirect`)
- filtering for loopback ip client addresses
- filtering based on parameter values using regex
- serving json

The following files need to be added to redbean executable/archive:

<pre>
.init.lua -- require "showcase"
.lua/fullmoon.lua
.lua/showcase.lua
</pre>

### TechEmpower benchmark example

The [TechEmpower example](examples/techbench.lua) implements various test types
for the [web framework benchmarks](https://www.techempower.com/benchmarks/)
using Fullmoon and an in-memory sqlite database.

This example demonstrates several Fullmoon/redbean features:
- routing for various endpoints
- serving text and json content
- filtering for specific HTTP methods
- using templates with embedded Lua code
- using select/insert statements with included SQLite engine
- executing prepared SQL statements

The following files need to be added to redbean executable/archive:

<pre>
.init.lua -- require "techbench"
.lua/fullmoon.lua
.lua/techbench.lua
</pre>

### htmx board example

The [htmx board example](examples/htmxboard/htmxboard.lua) demonstrates
a simple application that generates HTML fragments delivered to the client
using [htmx library](https://htmx.org/).

This example demonstrates several Fullmoon/redbean features:
- handling of GET, POST, PUT, and DELETE HTTP methods
- serving of dynamic HTML fragments and static assets
- processing of required and optional parameters
- loading of templates from a directory
- using 10+ templates of two different types
- including templates into other templates and passing parameters to templates
- serving of internal state for debugging purposes as a local-only resource
- using "fallthrough" routes to imitate "before" hook
- using internal redirects

The following files need to be added to redbean executable/archive:

<pre>
.init.lua -- require "htmxboard"
.lua/fullmoon.lua
.lua/htmxboard.lua
assets/stypes.css
tmpl/* -- all files from examples/htmxboard/tmpl folder
</pre>

Note 1: since all the data is stored in memory, **this example is executed
in the uniprocess mode.**

Note 2: this examples retrieves htmx, hyperscript, and sortable libraries from
external resources, but these libraries can be also stored as local assets,
thus providing a completely self-sufficient portable distribution package.

### htmx SSE example

The [htmx SSE example](examples/htmxsse.lua) demonstrates a way to generate
server-sent events (SSE) that can be streamed to a client (which shows
results using [htmx library](https://htmx.org/) and its SSE extension).

This example demonstrates several Fullmoon/redbean features:
- usage of "sse" template to generate SSE content
- streaming of responses (using `streamContent`)
- logging of messages

The following files need to be added to redbean executable/archive:

<pre>
.init.lua -- require "htmxsse"
.lua/fullmoon.lua
.lua/htmxsse.lua
</pre>

## Documentation

Each Fullmoon application follows the same basic flow with five main
components:

- [configures and runs](#running-application) a redbean server, which
- filters each request based on specified [conditions](#conditions), and
- [routes](#routes) it to an [action handler](#actions), that
- generates content (using provided [template engine](#templates)), and
- serves a [response](#responses).

Let's look at each of the components starting from the request routing.

### Routes

Fullmoon handles each HTTP request using the same process:

- takes the path URL and matches it against each route URL in the order
  in which routes are registered
- verifies conditions for those routes that match
- calls a specified action handler (passing a request table) for those
  routes that satisfy all conditions
- serves the response if anything other than `false` or `nil` returned
  from the action handler (and continues the process otherwise)

In general, route definitions bind request URLs (and a set of conditions)
to action handlers (which are regular Lua function). All conditions are
checked in a random order for each URL that matches the route definition.
As soon as any condition fails, the route processing is aborted and the
next route is checked *with one exception*: any condition can set the
[`otherwise` value](#responding-on-failed-conditions), which triggers a
response with the specified status.

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

#### Routes with parameters

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
other parameters: `/download/*path/*fname.zip` (although the same result
can be achieved using `/download/*path/:fname.zip`, as the first splat
captures all path parts except the filename).

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

In the example above, both `/hello` and `/hello/Bob` are accepted,
but not `/hello/`, as the trailing slash is part of the optional
fragment and `:name` still expects one or more characters.

Any unmatched optional parameter gets `false` as its value, so in the
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
are *not supported*, but not-in-set syntax is supported, so `[^%d]`
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
parameter and query/form names, then **parameter names take precedence**.

There is one special case that may result in a table returned instead of
a string value: if the query/form parameter name ends in `[]`, then all
matching results (one or more) will be returned as a table. For example,
for a query string `a[]=10&a[]&a[]=12&a[]=` the value of `params["a[]"]`
is `{10, false, 12, ""}`.

#### Multiple routes

Despite all earlier examples showing a single route, it's rarely the
case in real applications; when multiple routes are present, they are
always **evaluated in the order in which they are registered**.

One `setRoute` call can also set multiple routes when they have the same
set of conditions and share the same action handler:

```lua
fm.setRoute({"/route1", "/route2"}, handler)
```

This is equivalent to two calls setting each route individually:

```lua
fm.setRoute("/route1", handler)
fm.setRoute("/route2", handler)
```

Given that routes are evaluated in the order in which they are set, more
selective routes need to be set first, otherwise they may not get a
chance to be evaluated:

```lua
fm.setRoute("/user/bob", handlerBob)
fm.setRoute("/user/:name", handlerName)
```

If the routes are set in the opposite order, `/user/bob` may never be
checked as long as the `"/user/:name"` action handler returns some
non-`false` result.

As described earlier, if none of the routes match, a response with 404
status is returned. There may be cases when this is *not* desirable; for
example, when the application includes Lua scripts to handle requests that
are not explicitly registered as routes. In those cases, a catch-all route
can be added that implements the default redbean processing (the name of
the splat parameter is only used to disambiguate this route against other
`/*` routes that may be used elsewhere):

```lua
fm.setRoute("/*catchall", fm.servePath)
```

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
one that was registered last, but both routes are still present.

The route name can also be used with external/static routes that are
only used for URL generation.

#### External routes

If the route is only used for path generation, then it doesn't even need
to have a route handler:

```lua
fm.setRoute({"https://youtu.be/:videoid", routeName = "youtube"})
fm.makePath("youtube", {videoid = "abc"}) --> https://youtu.be/abc
```

A route without any action handler is skiped during the route matching
process.

#### Internal routes

Internal routes allow redirecting of one set of URLs to a different one.
The target URL can point to a static resource or a `.lua` script. For example,
if requests for one location need to be redirected to another, the following
configuration redirects requests for any resources under `/blog/` URL to those
under `/new-blog/` URL as long as the target resource exists:

```lua
fm.setRoute("/blog/*", "/new-blog/*")
```

This route accepts a request for `/blog/post1` and serves `/new-blog/post1`
as its reponse, as long as `/new-blog/post1` asset exists.
**If the asset doesn't exist, then the next route is checked.** Similarly,
using `fm.setRoute("/static/*", "/*")` causes requests for `/static/help.txt`
to be served resource `/help.txt`.

Both URLs can include parameters that will be filled in if resolved:

```lua
fm.setRoute("/blog/:file", "/new-blog/:file.html") --<<-- serve "nice" URLs
fm.setRoute("/new-blog/:file.html", fm.serveAsset) --<<-- serve original URLs
```

This example resolves "nice" URLs serving their "html" versions. Note that this
**doesn't trigger the client-side redirect by returning (`3xx`) status code**,
but instead handles the re-routing internally.
Also note that **the second rule is needed to serve the "original" URLs,**
as they are not handled by the first rule, because if the request is for
`/blog/mylink.html`, then the redirected URL is `/new-blog/mylink.html.html`,
which is not likely exist, so the route is skipped and the next one is checked.
If handling of path separators is required as well, then `*path` can be used
instead of `:file`, as `*` allows path separators.

### Conditions

If an application needs to execute different functions depending on
specific values of request attributes (for example, a method), this
library provides two main options: (1) check for the attribute value an
action handler (for example, using `request.method == "GET"` check) and
(2) add a condition that filters out requests such that only requests
using the specified attribute value reach the action handler. This
section describes the second option in more detail.

#### Handling of HTTP methods

Each registered route by default responds to all HTTP methods (GET, PUT,
POST, etc.), but it's possible to configure each route to only respond
to specific HTTP methods:

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
rather [fall through](#actions) to be checked by other routes and
trigger the 404 status returned if they don't get matched (with one
[exception](#responding-on-failed-conditions)).

#### Conditional routes

In addition to `method`, other conditions can be applied using `host`,
`clientAddr`, `serverAddr`, `scheme`, request headers, and parameters.
For example, specifying `name = "Bob"` as one of the conditions ensures
the value of the `name` parameter to be "Bob" for the action handler to
be called.

Any request header can be checked using the header name as the key, so
`ContentType = "multipart/form-data"` is satisfied if the value of the
`Content-Type` header is `multipart/form-data`. Note that the header
value may include other elements (a boundary or a charset as part of
the `Content-Type` value) and only the actual media type is compared.

Since names for headers, parameters and properties can overlap, they are
checked in the following order:
- request headers that consist of multiple words, like `ContentType`,
- request parameters,
- request properties (`method`, `port`, `host`, etc.), and
- request headers again.

`Host` header is also checked first (despite being a single word), so
referencing `Host` filters based on the header `Host`, while referencing
`host` filters based on the property `host`.

#### Custom validators

String values are not the only values that can be used in conditional
routes. If more than one value is acceptable, passing a table allows to
provide a list of acceptable values. For example, if `Bob` and `Alice`
are acceptable values, then `name = {Bob = true, Alice = true}`
expresses this as a condition.

Two special values passed in a table allow to apply a *regex* or a
*pattern* validation:

- `regex`: accepts a string that has a regular expression. For example,
  `name = {regex = "^(Bob|Alice)$"}` has the same result as the hash
  check shown earlier in this section
- `pattern`: accepts a string with a Lua patern expression. For example,
  `name = {pattern = "^%u%l+$"}` accepts values that start with an
  uppercase character followed by one or more lowercase characters.

These two checks can be combined with the table existence check:
`name = {Bob = true, regex = "^Alice$"}` accepts both `Bob` and `Alice`
values. If the first table-existence check fails, then the results of
the `regex` or `pattern` expression is returned.

The last type of a custom validator is a function. The provided function
receives the value to validate and its result is evaluated as `false` or
`true`. For example, passing `id = tonumber` ensures that the `id` value
is a number. As another example, `clientAddr = fm.isLoopbackIp` ensures
that the client address is a loopback ip address.

```lua
fm.setRoute({"/local-only", clientAddr = fm.isLoopbackIp},
  function(r) return "Local content" end)
```

As the validator function can be generated dynamically, this works too:

```lua
local function isLessThan(n)
  return function(l) return tonumber(l) < n end
end
fm.setRoute(fm.POST{"/upload", ContentLength = isLessThan(100000)},
  function(r) ...handle the upload... end)
```

It's important to keep in mind that the validator function actually
returns a function that is called during a request to apply the check.
In the previous example, the returned function accepts a header value
and compares it with the limit passed during its creation.

#### Responding on failed conditions

In some cases, failing to satisfy a condition is a sufficient reason to
return some response back to the client without checking other routes.
In a case like this, setting `otherwise` value to a number or a function
returns either a response with the specified status or the result of the
function:

```lua
local function isLessThan(n)
  return function(l) return tonumber(l) < n end
end
fm.setRoute(fm.POST{"/upload", ContentLength = isLessThan(100000),
    otherwise = 413}, function(r) ...handle the upload... end)
```

In this example the routing engine matches the route and then validates
the two conditions comparing the method value with `POST` and the value
of the `Content-Length` header with the result of the `isLessThan`
function. If one of the conditions doesn't match, the status specified
by the `otherwise` value is returned with the rest of the response.

If the returned status needs to only apply to the `ContentLength` check,
then the `otherwise` value along with the validator function can be
moved to a table associated with the `ContentLength` check:

```lua
fm.setRoute(fm.POST{"/upload",
    ContentLength = {isLessThan(100000), otherwise = 413}
  }, function(r) ...handle the upload... end)
```

The difference between the last two examples is that in this example
only the `ContentLength` check failure triggers the 413 response (and
all other methods fall through to other routes), while in the previous
one both `method` and `ContentLength` check failures trigger the same
413 response.

Note that when the checked value is `nil`, the check against a table is
deemed to be valid and the route is accepted. For example, a check for an
optional parameter made against a string (`name = "Bo"`) fails if the
value of `params.name` is `nil`, but passes if the same check is made
against a table (`name = {Bo=true, Mo=true}`), including regex/pattern checks.
If this is not desirable, then a custom validator function can explicitly
check for the correct value.

Consider the following example:

```lua
fm.setRoute({"/hello(/:name)",
    method = {"GET", "POST", otherwise = 405}},
  function(r) return "Hello, "..(r.params.name or "World!") end)
```

In this case, if this endpoint is accessed with the `PUT` method, then
instead of checking other routes (because the `method` condition is not
satisfied), the 405 status is returned, as configured with the specified
`otherwise` value. [As already mentioned](#handling-of-http-methods),
this route accepts a `HEAD` request too (even when not listed), as a
`GET` request is accepted.

When the 405 (Bad method) status is returned and the `Allow` header is
not set, it is set to the list of methods allowed by the route. In the
case above it is set to `GET, POST, HEAD, OPTIONS` values, as those are
the methods allowed by this configuration. If the `otherwise` value is a
function (rather than a number), then returning a proper result and
setting the `Allow` header is the responsibility of this function.

The `otherwise` value can also be set to a function, which provides more
flexibility than just setting a status value. For example, setting
`otherwise = fm.serveResponse(413, "Payload Too Large")` triggers a
response with the specified status and message.

#### Form validation

Handling form validation often requires specifying a set of conditions
for the same parameter and a custom error message that may need to be
returned when the conditions are not satisfied and these are provided
by special validators returned by `makeValidator` function:

```lua
local validator = fm.makeValidator{
  {"name", minlen = 5, maxlen = 64, msg = "Invalid %s format"},
  {"password", minlen = 5, maxlen = 128, msg = "Invalid %s format"},
}
fm.setRoute(fm.POST{"/signin", _ = validator}, function(r)
    -- do something useful with name and password
    return fm.serveRedirect("/", 303)
  end)
```

In this example, the validator is configured to check two parameters --
"name" and "password" -- for their min and max lengths and return a
message when one of the parameters fails the check.

Since the failing check causes the route to be skipped, providing the
`otherwise` value allows the error to be returned as part of the
response:

```lua
local validator = fm.makeValidator{
  {"name", minlen = 5, maxlen = 64, msg = "Invalid %s format"},
  {"password", minlen = 5, maxlen = 128, msg = "Invalid %s format"},
  otherwise = function(error)
    return fm.serveContent("signin", {error = error})
  end,
}
```

In this case the `otherwise` handler receives the error msg (or a table
with messages if requested) that can be then provided as a template
parameter and returned to the client.

Another option is to call the validator function directly in an action
handler and return its results:

```lua
local validator = fm.makeValidator{
  {"name", minlen = 5, maxlen = 64, msg = "Invalid %s format"},
  {"password", minlen = 5, maxlen = 128, msg = "Invalid %s format"},
}
fm.setRoute(fm.POST{"/signin"}, function(r)
    local valid, error = validator(r.params)
    if valid then
      return fm.serveRedirect("/", 303)
    else
      return fm.serveContent("signin", {error = error})
    end
  end)
```

In this example the validator is called directly and is passed a table
(`r.params`) with all parameter values to allow the validator function
to check the values against the specified rules.

The validator function then returns `true` to signal success or
`nil,error` to signal a failure to check one of the rules. This allows
the validator call to be wrapped into an `assert` if the script needs
to return an error right away:

```lua
assert(validator(r.params))  -- throw an error if validation fails
return fm.serveRedirect("/", 303)  -- return redirect in other cases
```

The following validator checks are available:
- `minlen`: (integer) checks minimal length of a string.
- `maxlen`: (integer) checks maximal length of a string.
- `test`: (function) calls a function that is passed one parameter
  and is expected to return `true` or `nil | false [,error]`.
- `oneof`: (`value | { table of values to be compared against }`)
  checks if the parameter matches one of the provided values.
- `pattern`: (string) checks if the parameter matches a Lua patern
  expression.

In addition to the checks, the rules may include options:
- `optional`: (bool) makes a parameter optional when it's `nil`.
  All the parameters are required by default, so this option allows
  the rules to be skipped when the parameter is not provided.
  All the rules are still applied if parameter is not nil.
- `msg`: (string) adds a customer message for this if one of its
  checks fails, which overwrites messages from individual checks.
  The message may include a placeholder (`%s`), which will be
  replaced by a parameter name.

The validator itself also accepts several options that modify how
the generated errors are returned or handled:
- `otherwise`: (function) sets an error handler that is called
  when one of the checks fails. The function receives the error(s)
  triggered by the checks.
- `all`: (bool) configures the validator to return all errors
  instead of just the first one. By default only one (first) error
  is returned as a string, so if all errors are requested, they
  are returned as a table with each error being a separate item.
- `key`: (bool) configures the validator to return error(s) as
  values in a hash table (instead of element) where the keys are
  parameter names. This is useful to pass the table with errors to
  a template that can then display `errors.name` and
  `errors.password` error messages next to their input fields.

### Actions

An action handler receives all incoming HTTP requests filtered for a
particular route. Each of the examples shown so far includes an action
handler, which is passed as a second parameter to the `setRoute` method.

**Multiple action handlers can be executed in the course of handling one
request and as soon as one handler returns a result that is evaluated as
a non-`false` value, the route handling process ends.** Returning `false`
or `nil` from an action handler continues the processing, which allows
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

- if the route is not matched, then other routes set later are checked
- if the route is matched, but the condition (the `method` check) is not
  matched, then 405 status is returned
- if the route is matched and the action handler is executed, it either
  retrieves the user and returns `false`, which continues processing
  with other routes, or fails to retrieve the user and returns an error.

In general, an action handler can return any of the following values:

- `true`: this stops any further processing, sets the headers that have
  been specified so far, and returns the generated or set response body.
- `false` or `nil`: this stops the processing of the current route and
  proceeds to the next one.
- a string value: this sends a response with 200 as the status and the
  returned string as its body. The `Content-Type` is set based on the
  body content (using a primitive heuristic) if not set explicitly.
- a function value (most likely as a call to one of `serve*` methods):
  this executes the requested method and returns an empty string or
  `true` to signal the end of the processing.
- any other returned value is ignored and interpreted as if `true` is
  returned (and a warning is logged).

### Requests

Each [action handler](#actions) accepts a request table that includes
the following attributes:

- `method`: request HTTP method (GET, POST, and others).
- `host`: request host (if provided) or the bind address.
- `serverAddr`: address to which listening server socket is bound.
- `remoteAddr`: client ip4 address encoded as a number. This takes into
  consideration reverse proxy scenarios. Use `formatIp` function to
  convert to a string representing the address.
- `scheme`: request URL scheme (if any).
- `path`: request URL path that is guaranteed to begin with `/`.
- `authority`: request URL with scheme, host, and port present.
- `url`: request URL as an ASCII string with illegal characters percent
  encoded.
- `body`: request message body (if present) or an empty string.
- `date`: request date as a Unix timestamp.
- `time`: current time as a Unix timestamp with 0.0001s precision.

The request table also has several [utility functions](utility-functions),
as well as [headers](#headers), [cookies](#cookies), and [session](#session)
tables that allow retrieving request headers, cookies, and session and
setting of headers and cookies that are included with the response.

The same request table is given as a parameter to all (matched) action
handlers, so it can be used as a mechanism to pass values between those
action handlers, as any value assigned as a field in one handler is
available in all other action handlers.

#### Headers

The `headers` table provides access to the request headers. For example,
`r.headers["Content-Type"]` returns the value of the `Content-Type`
header. This form of header access is case-insensitive. A shorter form
is also available (`r.headers.ContentType`), but only for registered
headers and *is* case-sensitive with the capitalization preserved.

The request headers can also be set using the same syntax. For example,
`r.headers.MyHeader = "value"` sets `MyHeader: value` response header.
As the headers are set at the end of the action handler processing,
headers set earlier can also be removed by assigning a `nil` value.

Repeatable headers can also be assigned with values separated by commas:
`r.headers.Allow = "GET, POST"`.

#### Cookies

The `cookies` table provides access to the request cookies. For example,
`r.cookies.token` returns the value of the `token` cookie.

The cookies can also be set using the same syntax. For example,
`r.cookies.token = "new value"` sets `token` cookie to `new value`.
If the cookie needs to have its attributes set as well, then the value
and the attributes need to be passed as a table:
`r.cookies.token = {"new value", secure = true, httponly = true}`.

The following cookie attributes are supported:
- `expires`: sets the maximum lifetime of the cookie as an HTTP-date
  timestamp. Can be specified as a date in the RFC1123 (string) format
  or as a UNIX timestamp (number of seconds).
- `maxage`: sets number of seconds until the cookie expires. A zero or
  negative number will expire the cookie immediately. If both `expires`
  and `maxage` are set, `maxage` has precedence.
- `domain`: sets the host to which the cookie will be sent.
- `path`: sets the path that must be present in the request URL, or
  the client will not send the Cookie header.
- `secure`: (bool) requests the cookie to be only send to the
  server when a request is made with the https: scheme.
- `httponly`: (bool) forbids JavaScript from accessing the cookie.
- `samesite`: (`Strict`, `Lax`, or `None`) controls whether a cookie is
  sent with cross-origin requests, providing some protection against
  cross-site request forgery attacks.

Note that `httponly` and `samesite="Strict"` are set by default;
a different set of defaults can be provided using `cookieOptions`
passed to the [run method](#running-application). Any attributes set
with a table **will overwrite the default**, so if `Secure` needs to
be enabled, make sure to also pass `httponly` and `samesite` options.

To delete a cookie, set its value to `false`: for example,
`r.cookies.token = false` deletes the value of the `token` cookie.

#### Session

The `session` table provides access to the session table that can
be used to set or retrieve session values. For example,
`r.session.counter` returns the `counter` value set previously.
The session values can also be set using the same syntax. For example,
`r.session.counter = 2` sets the `counter` value to `2`.

The session allows storing of nested values and other Lua values.
If the session needs to be removed, it can be set to an empty table
or a `nil` value. Each session is signed with an application secret,
which is assigned a random string by default and can be changed by
[setting session options](#session-options).

#### Utility functions

The following functions are available as both request functions (as
fields in the request table) and as library functions:

- `makePath(route[, parameters])`: creates a path from either a route
  name or a path string by populating its parameters using values from
  the parameters table (when provided).
  The path doesn't need to be just a path component of a URL and can be
  a full URL as well. [Optional parts](#optional-parameters) are removed
  if they include parameters that are not provided.
- `makeUrl([url,] options)`: creates a URL using the provided value and
  a set of URL parameters provided in the `options` table: scheme, user,
  pass, host, port, path, and fragment.
  The `url` parameter is optional; the current request URL is used if
  `url` is not specified. Any of the options can be provided or removed
  (using `false` as the value). For example, `makeUrl({scheme="https"})`
  sets the scheme for the current URL to `https`.
- `escapeHtml(string)`: escapes HTML entities (`&><"'`) by replacing them
  with their HTML entity counterparts (`&amp;&gt;&lt;&quot;&#39;`).
- `escapePath(path)`: applies URL encoding (`%XX`) escaping path unsafe
  characters (anything other than `-.~_@:!$&'()*+,;=0-9A-Za-z/`).
- `formatHttpDateTime(seconds)`: converts UNIX timestamp (in seconds) to
  an RFC1123 string (`Mon, 21 Feb 2022 15:37:13 GMT`).

### Templates

#### Configuring templates

#### Serving template outputs

#### Passing parameters to templates

#### Including templates in other templates

#### Processing layouts

### Schedules

Most of the time, the library configuration is focused on handling of
incoming requests, but in some cases it may be desirable to trigger
and handle internal events. The library supports job scheduling using
cron syntax, with configured jobs executed at the scheduled time (as
long as the redbean instance is running). A new schedule can be
registered using the `setSchedule` method:

```lua
--------------- ┌─────────── minute (0-59)
--------------- │ ┌───────── hour (0-23)
--------------- │ │ ┌─────── day of the month (1-31)
--------------- │ │ │ ┌───── month (1-12 or Jan-Dec)
--------------- │ │ │ │ ┌─── day of the week (0-6 or Sun-Mon)
--------------- │ │ │ │ │ --
--------------- │ │ │ │ │ --
fm.setSchedule("* * * * *", function() fm.logInfo("every minute") end)
```

All the standard and some non-standard cron expressions are supported:
- `*`: describes any values in the allowed range.
- `,`: uses to form a list of items, for example, `1,2,3`.
- `-`: creates an (inclusive) range; for example, `1-3` is equivalent
  to `1,2,3`. Open ranges are allowed as well, so `-3` is equivalent to
  `1-3` for months and `0-3` for minutes and hours.
- `/`: describes a step for ranges. It selects a subset of the values
  in the range, using the step value; for example, `2-9/3` is equivalent
  to `2,5,8` (it starts with 2, then adds a step value to get 5 and 8).

Non-numeric values are supported for months (`Jan-Dec`) and days of week
(`Sun-Mon`) in any capitalization. Using `7` for `Sun` is supported too.

By default all functions are executed in a separate (forked) process.
If the execution within the same process is needed, then `setSchedule`
can be passed a third parameter (a table) to set `sameProc` value
as one of the options: `{sameProc = true}`.

Some of the caveats to be aware of:
- using schedules relies on `OnServerHeartbeat` hook, so a version of
  Redbean that provides that (v2.0.16+) should be used.
- all schedule entries are interpreted as specified in GMT.
- day-of-month and day-of-week are combined with an `and` (instead of an
  `or`), so when *both* are specified, the job is executed when both are
  satisfied (and not when both or either are specified). In other words,
  `* * 13 * Fri` is only valid on Friday the 13th and not on any Friday.
  If the `or` behavior is needed, then the schedule can be split into
  two to handle each condition separately.
- each function is executed in a process forked from the main process;
  as noted above, set `sameProc = true` option to avoid forking.
- some schedules can be executed twice if redbean instance is restarted
  within the same minute, as the implementation is stateless.
- day-of-week makes `Sun` available on both ends (as 0 or 7), so it's
  better to use closed ranges in this case to avoid ambiguity.
- all parsing errors (on incorrect formats or expressions) are reported
  as fatal errors, but incorrect ranges are silently corrected into
  proper ones, so using `6-100` for months is corrected to `6-12`.

### Responses

Each action handler generates some sort of response to send back to the
client. In addition to [strings](#actions), the application can return
the following results:
- general responses (`serveResponse`),
- templates (`serveContent`),
- redirects (`serveRedirect`),
- static assets (`serveAsset`),
- errors (`serveError`),
- directory index (`serveIndex`), and
- internal redirects/resources (`servePath`).

Each of these methods can be used as the return value from an action
handler. `serveAsset`, `servePath`, and `serveIndex` methods can also
be used as action handlers directly:

```lua
fm.setRoute("/static/*", fm.serveAsset)
fm.setRoute("/blog/", fm.serveIndex("/new-blog/"))
```

The first route configures all existing assets to be served from
`/static/*` location; the second route configures `/blog/` URL to return
the index (`index.lua` or `index.html` resource) from `/new-blog/`
folder.

#### Serving response

`serveResponse(status[, headers][, body])`: sends an HTTP response using
provided `status`, `headers`, and `body` values.
`headers` is an optional table populated with HTTP header name/value
pairs. If provided, this set of headers *removes all other headers* set
earlier during the handling of the same request. Similar to the headers set
using the `request.headers` field, the names are *case-insensitive*, but
provided aliases for header names with dashes are *case-sensitive*:
`{ContentType = "foo"}` is an alternative form for
`{["Content-Type"] = "foo"}`. `body` is an optional string.

Consider the following example:

```lua
return fm.serveResponse(413, "Payload Too Large")
```

This returns the status value `413` and sets the body of the returned
message to `Payload Too Large` (with the header table not specified).

If only the status value needs to be set, the library provides a short
form using the `serve###` syntax:

```lua
return fm.serve413
```

It can also be used as the action handler itself:

```lua
fm.setRoute(fm.PUT"/status", fm.serve402)
```

#### Serving content

`serveContent(name, parameters)` renders a template using provided
parameters. `name` is a string that names the template (as set by a
`setTemplate` call) and `parameters` is a table with template parameters
(referenced as variables in the template).

#### Serving redirect

#### Serving static asset

#### Serving error

#### Serving directory index

#### Serving path (internal redirect)

### Running application

The `run` method executes the configured application. By default the server
is launched listening on localhost and port 8080. Both of these
values can be changed by passing `addr` and `port` options:

```lua
fm.run({addr = "localhost", port = 8080})
```

The following options are supported; the default values are shown in
parentheses and options marked with `mult` can set multiple values by
passing a table:

- `addr`: sets the address to listen on (mult)
- `brand`: sets the `Server` header value (`"redbean/v# fullmoon/v#"`)
- `cache`: configures `Cache-Control` and `Expires` headers (in seconds)
  for all static assets served. A negative value disables the headers.
  Zero value means no cache.
- `certificate`: sets the TLS certificate value (mult)
- `directory`: sets local directory to serve assets from in addition to
  serving them from the archive within the executable itself (mult)
- `headers`: sets default headers added to each response by passing a
  table with HTTP header name/value pairs
- `logMessages`: enables logging of response headers
- `logBodies`: enables logging of request bodies (POST/PUT/etc.)
- `logPath`: sets the log file path on the local file system
- `pidPath`: sets the pid file path on the local file system
- `port`: sets the port number to listen on (8080)
- `privateKey`: sets the TLS private key value (mult)
- `sslTicketLifetime`: sets the duration (in seconds) of the ssl ticket
  (86400)

The `key` and `certificate` string values can be populated using the
`getAsset` method that can access both assets packaged within the
webserver archive and those stored in the file system.

There are also default cookie and session options that can be assigned
using `cookieOptions` and `sessionOptions` tables described below.

#### Cookie options

`cookieOptions` sets default options for all [cookie values](#cookies)
assigned using `request.cookie.name = value` syntax (`{httponly=true,
samesite="Strict"}`). It is still possible to overwrite default values
using table assignment: `request.cookie.name = {value, secure=false}`.

#### Session options

`sessionOptions` sets default options for the [session](#session) value
assigned using `request.session.attribute = value` syntax
(`{name="fullmoon_session", hash="SHA256", secret=true, format="lua"}`).
If the `secret` value is set to `true`, then a random key is assigned
*each time the server is started*; if *verbose* logging is enabled (by either
adding `-v` option for Redbean or by using `fm.setLogLevel(fm.kLogVerbose)`
call), then a message will be logged explaining how to apply the current
random value to make it permanent.

Setting this value to `false` or an empty string applies hashing without a
secret key.

### Logging

### Database management

Fullmoon's function `makeStorage` is a way to connect to,  
and use a `SQLite3` database.  
`makeStorage` returns a _database management_ table which contains a rich set  
of functions to use with the connected database.  

## Benchmark

The results shown are from runs in the same environment and on the same
hardware as the [published redbean benchmark](https://redbean.dev/#benchmark)
(thanks to [@jart](https://github.com/jart/) for executing the tests!).
Even though these tests are using pre-1.5 version of redbean and 0.10 version
of Fullmoon, the current versions of redbean/Fullmoon are expected to deliver
similar performance.

The tests are using exactly the same code that is shown in the
[introduction](#fullmoon) with one small change: using `{%= name %}` instead of
`{%& name %}` in the template, which skips HTML escaping.
This code demonstrates routing, parameter handling and template processing.

<pre>
$ wrk -t 12 -c 120 http://127.0.0.1:8080/user/paul
Running 10s test @ http://127.0.0.1:8080/user/paul
  12 threads and 120 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   312.06us    4.39ms 207.16ms   99.85%
    Req/Sec    32.48k     6.69k   71.37k    82.25%
  3913229 requests in 10.10s, 783.71MB read
Requests/sec: <strong>387477.76</strong>
Transfer/sec:     77.60MB
</pre>

The following test is using the same configuration, but redbean is compiled
with `MODE=optlinux` option:

<pre>
$ wrk -t 12 -c 120 http://127.0.0.1:8080/user/paul
Running 10s test @ http://127.0.0.1:8080/user/paul
  12 threads and 120 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   346.31us    5.13ms 207.31ms   99.81%
    Req/Sec    36.18k     6.70k   90.47k    80.92%
  4359909 requests in 10.10s, 0.85GB read
Requests/sec: <strong>431684.80</strong>
Transfer/sec:     86.45MB
</pre>

The following two tests demonstrate the latency of the request handling by
Fullmoon and by redbean serving a static asset (no concurrency):

<pre>
$ wrk -t 1 -c 1 http://127.0.0.1:8080/user/paul
Running 10s test @ http://127.0.0.1:8080/user/paul
  1 threads and 1 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    <strong>15.75us    7.64us 272.00us</strong>   93.32%
    Req/Sec    65.54k   589.15    66.58k    74.26%
  658897 requests in 10.10s, 131.96MB read
Requests/sec:  65241.45
Transfer/sec:     13.07MB
</pre>

The following are the results from redbean itself on static compressed assets:

<pre>
$ wrk -H 'Accept-Encoding: gzip' -t 1 -c 1 htt://10.10.10.124:8080/tool/net/demo/index.html
Running 10s test @ htt://10.10.10.124:8080/tool/net/demo/index.html
  1 threads and 1 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency     <strong>7.40us    1.95us 252.00us</strong>   97.05%
    Req/Sec   129.66k     3.20k  135.98k    64.36%
  1302424 requests in 10.10s, 1.01GB read
Requests/sec: 128963.75
Transfer/sec:    102.70MB
</pre>

## Status

Highly experimental with everything being subject to change.

## Author

Paul Kulchenko (paul@zerobrane.com)

## License

See [LICENSE](LICENSE).
