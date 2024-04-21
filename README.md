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
    - [Splat parameters](#splat-parameters)
    - [Custom parameters](#custom-parameters)
    - [Query and Form parameters](#query-and-form-parameters)
    - [Multipart parameters](#multipart-parameters)
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
    - [Throwing errors](#throwing-errors)
  - [Requests](#requests)
    - [Headers](#headers)
    - [Cookies](#cookies)
    - [Session](#session)
    - [Utility functions](#utility-functions)
  - [Templates](#templates)
    - [Passing parameters to templates](#passing-parameters-to-templates)
    - [Handling undefined values in templates](#handling-undefined-values-in-templates)
    - [Including templates in other templates](#including-templates-in-other-templates)
    - [Using layouts and blocks](#using-layouts-and-blocks)
    - [Loading templates](#loading-templates)
    - [Serving template output](#serving-template-output)
    - [Special templates](#special-templates)
  - [Schedules](#schedules)
  - [Responses](#responses)
    - [Serving response](#serving-response)
    - [Serving redirect](#serving-redirect)
    - [Serving static asset](#serving-static-asset)
    - [Serving error](#serving-error)
    - [Serving directory index](#serving-directory-index)
    - [Serving path (internal redirect)](#serving-path-(internal-redirect))
  - [Database management](#database-management)
  - [Running application](#running-application)
    - [Cookie options](#cookie-options)
    - [Session options](#session-options)
  - [Logging](#logging)
- [Benchmark](#benchmark)
  - [3-rd party benchmarks](#3-rd-party-benchmarks)
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
none of them integrates with Redbean (although there is an experimental
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
- Integrated SSL support (using MbedTLS) with SSL virtual hosting
- Integrated crypto hashing (SHA1/SHA224/256/384/512/BLAKE2B256)
- Cross-platform `fork`, `socket`, shared memory, and more
- Efficient serving of static and gzip encoded assets
- Integrated password-hashing (using Argon2)
- pledge/unveil sandboxing (where supported)
- unix.* module for Unix system interfaces
- HTTP/HTTPS client for external requests
- JSON and Lua serialization and parsing
- Ships with Lua 5.4 and SQLite 3.40

### What Fullmoon adds

- Small package (~1700 LOC) with no external dependencies
- Simple and flexible routing with [parameters](#routes-with-parameters)
  and [custom filters](#conditions)
- [Template engine](#templates) with JSON support and efficient memory utilization
- Optimized execution with pre-compiled routes and lazy loaded methods
- Response streaming and Server-Sent Events support
- [Cookie](#cookies)/[header](#headers)/[session](#session) generation and processing
- [Multipart](#multipart-parameters) message processing for file uploads
- Parametrized URL [rewrites](#internal-routes) and re-routing
- [Form validation](#form-validation) with a variety of checks
- [Cron syntax](#schedules) for scheduling Lua functions
- DB management with schema migrations
- Custom 404 and other status pages
- Basic support to run CGI scripts
- Access to all Redbean features

## Installation

### Step 1: Get the latest Redbean (v2.0+)

Download a copy of Redbean by running the following commands (skip the second
one if running these commands on Windows):

```sh
curl -o redbean.com https://redbean.dev/redbean-2.2.com
chmod +x redbean.com
```

The latest version number can be retrieved with the following request:

```sh
curl https://redbean.dev/latest.txt
```

Another option is to build Redbean from source by following instructions for
the [source build](https://redbean.dev/#source).

### Step 2: Prepare Fullmoon code

- Copy `fullmoon.lua` to `.lua/` directory
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
make sure to place it inside the `.lua/` directory and zip that file as well.

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
"Hello, world" content (and the 200 status code) and responds with the
404 status code for all other requests.

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
  If any condition is not satisfied, then the next route is checked. The
  route expression can have multiple [parameters](#routes-with-parameters)
  and [optional parts](#optional-parameters). The action handler accepts
  a [request table](#requests) that provides access to request and route
  parameters, as well as [headers](#headers), [cookies](#cookies), and
  [session](#session).

- `setTemplate(name, template[, parameters])`: registers a template
  with the specified name or a [set of templates](#loading-templates)
  from a directory.
  If `template` is a string, then it's compiled into a template handler.
  If it is a function, it is stored and called when rendering of the
  template is requested. If it's a table, then its first element is a
  template or a function and the rest are used as options. For example,
  specifying `ContentType` as one of the options sets the `Content-Type`
  header for the generated content. Several templates (`500`, `json`,
  and others) are [provided by default](#special-templates) and can be
  overwritten. `parameters` is a table with template parameters stored as
  name/value pairs (referenced as variables in the template).

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
  call) and `parameters` is a table with template parameters stored as
  name/value pairs (referenced as variables in the template).

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
assets/styles.css
tmpl/* -- all files from examples/htmxboard/tmpl directory
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
response with the specified status code.

If no route matches the request, then the default 404 processing is
triggered, which can be customized by registering a custom 404 template
(`fm.setTemplate("404", "My 404 page...")`).

#### Basic routes

Each route takes a path that matches exactly, so the route `"/hello"`
matches requests for `/hello` and doesn't match `/hell`, `/hello-world`,
or `/hello/world`. The route below responds with "Hello, World!" for all
requests directed at the `/hello` path and returns 404 for all other
requests.

```lua
fm.setRoute("/hello", function(r) return "Hello, World!" end)
```

To match a path where `/hello` is only a part of it,
[optional parameters](#optional-parameters) and [splat](#splat-parameters)
can be used.

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

#### Splat parameters

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

Another reason to use splat is to allow multiple routes with the same
path to be registered in the system. The current implementation
overwrites routes with the same name and to avoid that a named splat can
be used to create unique paths. For example,

```lua
fm.setRoute("/*dosomething1", function(r) return "something 1" end)
fm.setRoute("/*dosomething2", function(r) return "something 2" end)
```

This can be used in situations when there is a set of conditions that
needs to be checked in the action handler and while it may be possible
to combine both routes into one, sometimes it's cleaner to keep them
separate.

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
validators](#custom-validators) can be used to extend the matching logic.

#### Query and Form parameters

Query and form parameters can be accessed in the same way as the path
parameters using the `params` table in the `request` table that is
passed to each action handler. Note that if there is a conflict between
parameter and query/form names, then **parameter names take precedence**.

There is one special case that may result in a table returned instead of
a string value: if the query/form parameter name ends in `[]`, then all
matching results (one or more) are returned as a table. For example,
for a query string `a[]=10&a[]&a[]=12&a[]=` the value of `params["a[]"]`
is `{10, false, 12, ""}`.

As writing these parameter names may require several brackets, `params.a`
can be used as a shortcut for `params["a[]"]` with both forms returning
the same table.

#### Multipart parameters

Multipart parameters are also processed when requested and can be
accessed in the same way as the rest of the parameters using the `params`
table. For example, parameters with names `simple` and `more` can be
retrieved from a message with `multipart/form-data` content type using
`params.simple` and `params.more`.

As some of the multipart content may include additional headers and
parameters within those headers, they can be accessed with `multipart`
field of the `params` table:

```lua
fm.setRoute({"/hello", simple = "value"}, function(r)
    return "Show "..r.params.simple.." "..r.params.multipart.more.data)
  end)
```

The `multipart` table includes all the parts of the multipart message
(so it can be iterated over using `ipairs`), but it also allows access
using parameter names (`params.multipart.more`). Each of the elements is
also a table that includes the following fields:

- data: the main field with the content. It contains a **string** with
  the content or a **table** in the case of recursive multipart messages.
- headers: a table with headers (as keys, **all lowercase**) and their
  content as values. This table is always present, but may be empty.
- name: the name of the parameter (if specified); `nil` if not.
- filename: the filename of the parameter (if specified); `nil` if not.

This multipart processing consumes any multipart sub-types and handles
recursive multipart messages. It also inserts a part with `Content-ID`
value matching the `start` parameter into the first position.

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

As described earlier, if none of the routes match, a response with a 404
status code is returned. There may be cases when this is *not* desirable;
for example, when the application includes Lua scripts to handle requests
that are not explicitly registered as routes. In those cases, a catch-all
route can be added that implements the default redbean processing (the name
of the splat parameter is only used to disambiguate this route against
other `/*` routes that may be used elsewhere):

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

A route without any action handler is skipped during the route matching
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
as its response, as long as `/new-blog/post1` asset exists.
**If the asset doesn't exist, then the next route is checked.** Similarly,
using `fm.setRoute("/static/*", "/*")` causes requests for `/static/help.txt`
to be served resource `/help.txt`.

Both URLs can include parameters that are filled in if resolved:

```lua
fm.setRoute("/blog/:file", "/new-blog/:file.html") --<<-- serve "nice" URLs
fm.setRoute("/new-blog/:file.html", fm.serveAsset) --<<-- serve original URLs
```

This example resolves "nice" URLs serving their "html" versions. Note that this
**doesn't trigger the client-side redirect by returning the `3xx` status code**,
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
trigger the 404 status code returned if they don't get matched (with
one [exception](#responding-on-failed-conditions)).

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
- `pattern`: accepts a string with a Lua pattern expression. For example,
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
fm.setRoute(fm.POST{"/upload",
    ContentLength = isLessThan(100000), otherwise = 413
  }, function(r) ...handle the upload... end)
```

In this example the routing engine matches the route and then validates
the two conditions comparing the method value with `POST` and the value
of the `Content-Length` header with the result of the `isLessThan`
function. If *one of the conditions* doesn't match, the status code
specified by the `otherwise` value is returned with the rest of the
response.

If the `otherwise` condition needs to *only* apply to the `ContentLength`
check, then the `otherwise` value along with the validator function can
be moved to a table associated with the `ContentLength` check:

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
check for the expected value.

Consider the following example:

```lua
fm.setRoute({"/hello(/:name)",
    method = {"GET", "POST", otherwise = 405}},
  function(r) return "Hello, "..(r.params.name or "World!") end)
```

In this case, if this endpoint is accessed with the `PUT` method, then
instead of checking other routes (because the `method` condition is not
satisfied), the 405 status code is returned, as configured with the
specified `otherwise` value. [As documented elsewhere](#handling-of-http-methods),
this route accepts a `HEAD` request too (even when not listed), as a
`GET` request is accepted.

When the 405 (Bad method) status code is returned and the `Allow` header
is not set, it is set to the list of methods allowed by the route. In
the case above it is set to `GET, POST, HEAD, OPTIONS` values, as those
are the methods allowed by this configuration. If the `otherwise` value
is a function (rather than a number), then returning a proper result and
setting the `Allow` header is the responsibility of this function.

The `otherwise` value can also be set to a function, which provides more
flexibility than just setting a status code. For example, setting
`otherwise = fm.serveResponse(413, "Payload Too Large")` triggers a
response with the specified status code and message.

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
    return fm.serveRedirect(307, "/")
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

In this case the `otherwise` handler receives the error message (or a table
with messages if requested by passing the `all` option covered below) that
can be then provided as a template parameter and returned to the client.

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
      return fm.serveRedirect("/") -- status code is optional
    else
      return fm.serveContent("signin", {error = error})
    end
  end)
```

In this example the validator is called directly and is passed a table
(`r.params`) with all parameter values to allow the validator function
to check the values against the specified rules.

The validator function then returns `true` to signal success or
`nil, error` to signal a failure to check one of the rules. This allows
the validator call to be wrapped into an `assert` if the script needs
to return an error right away:

```lua
assert(validator(r.params))  -- throw an error if validation fails
return fm.serveRedirect(307, "/")  -- return redirect in other cases
```

The following validator checks are available:
- `minlen`: (integer) checks minimal length of a string.
- `maxlen`: (integer) checks maximal length of a string.
- `test`: (function) calls a function that is passed one parameter
  and is expected to return `true` or `nil | false [, error]`.
- `oneof`: (`value | { table of values to be compared against }`)
  checks if the parameter matches one of the provided values.
- `pattern`: (string) checks if the parameter matches a Lua pattern
  expression.

In addition to the checks, the rules may include options:
- `optional`: (bool) makes a parameter optional when it's `nil`.
  All the parameters are required by default, so this option allows
  the rules to be skipped when the parameter is not provided.
  All the rules are still applied if parameter is not nil.
- `msg`: (string) adds a customer message for this if one of its
  checks fails, which overwrites messages from individual checks.
  The message may include a placeholder (`%s`), which is going to
  be replaced by a parameter name.

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

- if the route is not matched, then other routes set later are checked.
- if the route is matched, but the condition (the `method` check) is not
  matched, then the 405 status code is returned.
- if the route is matched and the action handler is executed, it either
  retrieves the user and returns `false`, which continues processing
  with other routes, or fails to retrieve the user and returns an error.

In general, an action handler can return any of the following values:

- `true`: this stops any further processing, sets the headers that have
  been specified so far, and returns the generated or set response body.
- `false` or `nil`: this stops the processing of the current route and
  proceeds to the next one.
- a string value: this sends a response with 200 as the status code and
  the returned string as its body. The `Content-Type` is set based on
  the body content (using a primitive heuristic) if not set explicitly.
- a function value (most likely as a call to one of `serve*` methods):
  this executes the requested method and returns an empty string or
  `true` to signal the end of the processing.
- any other returned value is ignored and interpreted as if `true` is
  returned (and a warning is logged).

#### Throwing errors

Normally any processing that results in a Lua error is returned to the
client as a server error response (with the 500 status code). To assist
with local debugging, the error message includes a stack trace, but only
if the request is sent from a loopback or private IP (or if redbean is
launched with the `-E` command line option).

It may be desirable to return a specific response through multiple
layers of function calls, in which case the error may be triggered with
a function value instead of a string value. For example, executing
`error(fm.serve404)` results in returning the 404 status code, which is
similar to using `return fm.serve404`, but can be executed in a function
called from an action handler (and *only* from inside an action handler).

Here is a more complex example that returns the 404 status code if no
record is fetched (assuming there is a table `test` with a field `id`):

```
local function AnyOr404(res, err)
  if not res then error(err) end
  -- serve 404 when no record is returned
  if res == db.NONE then error(fm.serve404) end
  return res, err
end
fm.setRoute("/", function(r)
    local row = AnyOr404(dbm:fetchOne("SELECT id FROM test"))
    return row.id
  end)
```

This example uses the `serve404` function, but any other [serve*](#responses)
method can also be used.

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
  negative number expires the cookie immediately. If both `expires`
  and `maxage` are set, `maxage` has precedence.
- `domain`: sets the host to which the cookie is going to be sent.
- `path`: sets the path that must be present in the request URL, or
  the client is not going to send the Cookie header.
- `secure`: (bool) requests the cookie to be only send to the
  server when a request is made with the https: scheme.
- `httponly`: (bool) forbids JavaScript from accessing the cookie.
- `samesite`: (`Strict`, `Lax`, or `None`) controls whether a cookie is
  sent with cross-origin requests, providing some protection against
  cross-site request forgery attacks.

Note that `httponly` and `samesite="Strict"` are set by default;
a different set of defaults can be provided using `cookieOptions`
passed to the [run method](#running-application). Any attributes set
with a table **overwrite the default**, so if `Secure` needs to
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

Templates provide a simple and convenient way to return a predefined and
parametrized content instead of generating it piece by piece.

The included template engine supports mixing an arbitrary text with Lua
statements/expressions wrapped into `{% %}` tags. All the code in templates
uses a regular Lua syntax, so there is no new syntax to learn. There are
three ways to include some Lua code:
- `{% statement %}`: used for Lua *statements*.
  For example, `{% if true then %}Hello{% end %}` renders `Hello`.
- `{%& expression %}`: used for Lua *expressions* rendered as HTML-safe text.
  For example, `{%& '2 & 2' %}` renders `2 &amp; 2`.
- `{%= expression %}`: used for Lua *expressions* rendered as-is (without escaping).
  For example, `{%= 2 + 2 %}` renders `4`.
  Be careful, as HTML is not escaped with `{%= }`, this should be used carefully
  due to the potential for XSS attacks.

The template engine provides two main functions to use with templates:
- `setTemplate(name, text[, parameters])`: registers a template with the
  provided name and text (and uses `parameters` as its default parameters).
  There are special cases where `name` or `text` parameters may not be
  strings, with some of those cases covered in
  the [Loading templates](#loading-templates) section.
  `parameters` is a table with template parameters as
  name/value pairs (referenced as variables in the template).
- `render(name, parameters)`: renders a registered template using the
  `parameters` table to set values in the template (with key/value in the
  table assigned to name/value in the template).

There is only one template with a given name, so registering a template
with an existing name replaces this previously registered template. This
is probably rarely needed, but can be used to overwrite default templates.

Here is an example that renders `Hello, World!` to the output buffer:

```lua
fm.setTemplate("hello", "Hello, {%& title %}!")
fm.render("hello", {title = "World"})
```

Rendering statements using the expression syntax or expressions using
the statement syntax is a syntax error that is reported when the template
is registered. Function calls can be used with either syntax.

Any template error (syntax or run-time) includes a template name and a line
number within the template. For example, calling
`fm.setTemplate("hello", "Hello, {%& if title then end %}!")` results in
throwing `hello:1: unexpected symbol near 'if'` error (as it inserts a Lua
statement using the expression syntax).

Templates can also be loaded from a file or a directory using the same
`setTemplate` function, which is described later in
the [Loading templates](#loading-templates) section.

There are several aspects worth noting, as they may differ from how
templates are processed in other frameworks:
- Templates *render directly to the output buffer*. This is done primarily
  for simplicity and performance reasons to delegate the output management
  to redbean. This means that template rendering doesn't return the output,
  although there are alternative ways to access it if needed.
- Templates only have access to a *restricted environment*. Every value
  a template is using needs to be explicitly registered or passed as a
  parameter to be accessible (although there are several
  [utility functions](#utility-functions) available).
- Each template is parsed during registration and is converted to function
  that gets executed when a template is rendered. This allows to handle
  all the parsing and related processing once (during the initialization)
  and then call generated functions during rendering.
- As all *templates are converted to functions*, it is also possible to
  pass a function directly (instead of a template), which provides a
  convenient extension mechanism that reuses the rest of the library. For
  example, [`json` and `sse` templates](#special-templates) are
  implemented using this approach.
- There is *no whitespace control or escaping* provided (mostly for
  simplicity, as the same effect can be achieved with some reformatting).

#### Passing parameters to templates

Each template accepts parameters that then can be used in its rendering logic.
Parameters can be passed in two ways: (1) when the template is registered and
(2) when the template is rendered. Passing parameters during registration
allows to set default values that are used if no parameter is provided
during rendering. For example,

```lua
fm.setTemplate("hello", "Hello, {%& title %}!", {title = "World"})
fm.render("hello") -- renders `Hello, World!`
fm.render("hello", {title = "All"}) -- renders `Hello, All!`
```

`nil` or `false` values are rendered as empty strings without throwing any
error, but any operation on a `nil` value is likely to result in a Lua
error. For example, doing `{%& title .. '!' %}` (without `title` set)
results in `attempt to concatenate a nil value (global 'title')` error.

There is no constraint on what values can be passed to a template, so any
Lua value can be passed and then used inside a template.

In addition to the values that can be passed to templates, there are two
special tables that provide *access to cross-template values*:
- `vars`: provides access to values registered with `setTemplateVar`, and
- `block`: provides access to template fragments that can be [overwritten
  by other templates](#using-layouts-and-blocks).

Any value registered with `setTemplateVar` becomes *accessible from any
template* through the `vars` table. In the following example, the
`vars.title` value is set by the earlier `setTemplateVar('title', 'World')`
call:

```lua
fm.setTemplateVar('title', 'World')
fm.setTemplate("hello", "Hello, {%& vars.title %}!")
fm.render("hello") -- renders `Hello, World!`
```

#### Handling undefined values in templates

While undefined values are rendered as empty string by default (which may be
convenient in most cases), there are still situations when it is preferrable
to not allow undefined values to be silently handled. In this a special
template variable (`if-nil`) can be set to handle those cases to throw
an error or to log a message. For example, the following code throws an
error, as the `missing` value is undefined, which triggers `if-nil` handler:

```lua
fm.setTemplateVar('if-nil', function() error"missing value" end)
fm.setTemplate("hello", "Hello, {%& vars.missing %}!")
fm.render("hello") -- throws "missing value" error
```

#### Including templates in other templates

Templates can be also rendered from other templates by using the `render`
function, which is available in every template:

```lua
fm.setTemplate("hello", "Hello, {%& title %}!")
fm.setTemplate("header", "<h1>{% render('hello', {title = title}) %}</h1>")
---------------------------------└──────────────────────────────┘----------
fm.render("header", {title = 'World'}) -- renders `<h1>Hello, World!</h1>`
```

There are no limits on how templates can be rendered from other templates,
but no checks for loops are made either, so having circular references in
template rendering (when a template A renders a template B, which in turn
renders A again) is going to cause a Lua error.

It's worth noting that the `render` function doesn't return the value of
the template it renders, but instead puts it directly into the output
buffer.

#### Using layouts and blocks

This ability to render templates from other templates allows producing
layouts of any complexity. There are two ways to go about it:
- to use dynamic template selection or
- to use blocks.

##### Dynamic template selection

To dynamically choose the template to use at render time, the template
name itself can be passed as a parameter:

```lua
fm.setTemplate("hello", "Hello, {%& title %}!")
fm.setTemplate("bye", "Bye, {%& title %}!")
fm.setTemplate("header", "<h1>{% render(content, {title = title}) %}</h1>")
fm.render("header", {title = 'World', content = 'hello'})
```

This example renders either `<h1>Hello, World!</h1>` or
`<h1>Bye, World!</h1>` depending on the value of the `content` parameter.

##### Blocks

Using blocks allows defining template fragments that can (optionally) be
overwritten from other templates (usually called "child" or "inherited"
templates). The following example demonstrates this approach:

```lua
fm.setTemplate("header", [[
  <h1>
    {% function block.greet() %} -- define a (default) block
      Hi
    {% end %}
    {% block.greet() %}, -- render the block
    {%& title %}!
  </h1>
]])
fm.setTemplate("hello", [[
  {% function block.greet() %} -- overwrite the `header` block (if any)
    Hello
  {% end %}
  {% render('header', {title=title}) %}!
]])
fm.setTemplate("bye", [[
  {% function block.greet() %} -- overwrite the `header` block (if any)
    Bye
  {% end %}
  {% render('header', {title=title}) %}!
]])

-- normally only one of the three `render` calls is needed,
-- so all three are shown for illustrative purposes only
fm.render("hello", {title = 'World'})  -- renders <h1>Hello, World!</h1>
fm.render("bye", {title = 'World'})    -- renders `<h1>Bye, World!</h1>`
fm.render("header", {title = 'World'}) -- renders `<h1>Hi, World!</h1>`
```

In this example the `header` template becomes the "layout" and defines the
`greet` block with `Hi` as its content. The block is defined as a function
in the `block` table with the content it needs to produce. It's followed by
a call to the `block.greet` function to include its content in the template.

This is important to emphasize, as *in addition to defining a block, it
also needs to be called from the base/layout template* at the point where
it is expected to be rendered.

The `hello` template also defines `block.greet` function with a different
content and then renders the `header` template. When the `header` template
is rendered, it uses the content of the `block.greet` function as defined in
the `hello` template. In this way, the child template "redefines" the `greet`
block with its own content, inserting it into the appropriate place into
the parent template.

It works the same way for the `bye` and `header` templates. There is
nothing special about these "block" functions other than the fact that
they are defined in the `block` table.

This concepts is useful for template composition at any depth. For example,
let's define a modal template with a header and a footer with action
buttons:

```lua
fm.setTemplate("modal", [[
  <div class="modal">
    <div class="modal-title">
      {% function block.modal_title() %}
        Details
      {% end %}
      {% block.modal_title() %}
    </div>
    <div class="modal-content">
      {% block.modal_content() %}
    </div>
    <div class="modal-actions">
      {% function block.modal_actions() %}
        <button>Cancel</button>
        <button>Save</button>
      {% end %}
      {% block.modal_actions() %}
    </div>
  </div>
]])
```

Now, in a template that renders the modal, the blocks can be overwritten
to customize the content:

```lua
fm.setTemplate("page", [[
  {% function block.modal_title() %}
    Insert photo
  {% end %}
  {% function block.modal_content() %}
    <div class="photo-dropzone">Upload photo here</div>
  {% end %}

  {% render('modal') %}
]])
```

This enables easily building composable layouts and components, such as
headers and footers, cards, modals, or anything else that requires the
ability to dynamically customize sections in other templates.

Here is an example to illustrate how nested blocks work together:

```lua
-- base/layout template
{% function block.greet() %} -- 1. defines default "greet" block
  Hi
{% end %}
{% block.greet() %}          -- 2. calls "greet" block

-- child template
{% function block.greet() %} -- 3. defines "greet" block
  Hello
{% end %}
{% render('base') %}         -- 4. renders "base" template

-- grandchild template
{% function block.greet() %} -- 5. defines "greet" block
  Bye
{% end %}
{% render('child') %}        -- 6. renders "child" template
```

In this example the "child" template "extends" the base template and any
`block.greet` content defined in the child template is rendered inside
the "base" template (when and where the `block.greet()` function is
called). The default `block.greet` block doesn't need to be defined in
the base template, but when it is present (step 1), it sets the content
to be rendered (step 2) if the block is not overwritten in a child
template and needs to be defined *before* `block.greet` function is called.

Similarly, `block.greet` in the child template needs to be defined
*before* (step 3) the base template is rendered (step 4) to have
a desired effect.

If one of the templates in the current render tree doesn't define the
block, then the later defined block is going to be used. For example,
if the grandchild template doesn't define the block in step 5, then
the `greet` block from the child template is going to be used when the
grandchild template is rendered.

If none of the `block.greet` functions is defined, then `block.greet()`
fails (in the `base` template). *To make the block optional*, just
check the function before calling. For example,
`block.greet and block.greet()`.

In those cases where the "overwritten" block may still need to be rendered,
it's possible to reference that block directly from the template that
defines it, as shown in the following example:

```lua
fm.setTemplate("header", [[
  <h1>
    {% function block.greet() %}
      Hi
    {% end %}
    {% block.greet() %}, {%& title %}!
  </h1>
]])
fm.setTemplate("bye", [[
 {% block.header.greet() %},
  {% function block.greet() %}
    Bye
  {% end %}
  {% render('header', {title=title}) %}!
]])
fm.render("bye", {title = 'World'}) -- renders `<h1>Hi, Bye, World!</h1>`
```

In this case, `{% block.header.greet() %}` in the `bye` template renders
the `greet` block from the `header` template. This only works with the
templates that are currently being rendered and is intended to simulate the
"super" reference (albeit with explicit template references). The general syntax
of this call is `block.<templatename>.<blockname>()`.

As blocks are simply regular Lua functions, there are no restrictions
on how blocks can be nested into other blocks or how blocks are defined
relative to template fragments or other Lua statements included in
the templates.

#### Loading templates

In addition to registering templates from a string, the templates can be
loaded and registered from a file or a directory using the same
`setTemplate` function, but passing a table with the directory and a list
of mappings from file extensions to template types to load. For example,
calling `fm.setTemplate({"/views/", tmpl = "fmt"})` loads all `*.tmpl`
files from the `/views/` directory (and its subdirectories) and
registers each of them as the `fmt` template, which is the default
template type. Only those files that match the extension are loaded
and multiple extension mappings can be specified in one call.

Each loaded template gets its name based on the full path starting
from the specified directory: the file `/views/hello.tmpl` is registered
as a template with the name "hello" (without the extension), whereas the
file `/views/greet/bye.tmpl` is registered as a template with the name
"greet/bye" (and this is the exact name to use to load the template).

There are two caveats worth mentioning, both related to the directory
processing. The first one is related to the trailing slash in the
directory name passed to `setTemplate`. It's recommended to provide
one, as the specified value is used as a prefix, so if `/view` is
specified, it's going to match both `/view/` and `/views/` directories
(if present), which may or may not be the intended result.

The second caveat is related to how external directories are used during
template search. Since redbean allows access to external directories when
configured using the `-D` option or `directory` option
(see [Running application](#running-application) for details), there may
be multiple locations for the same template available. The search for the
template follows these steps:
- the internal (zip archive) is used to get the list of files matching
  a certain prefix (as specified in a `setTemplate` call);
- the external directories are checked (in the order in which they
  are specified) to load the file;
- the internal (zip archive) directory is checked to load the file.

This allows to have a working copy of a template to be modified and
processed from the file system (assuming the `-D` option is used) during
development without modifying its copy in the archive.

#### Serving template output

Even though using `fm.render` is sufficient to get a template rendered,
for consistency with other [serve*](#responses) functions, the library
provides the [`serveContent` function](#serving-content), which is
similar to `fm.render`, but allows the action handler to complete after
serving the content:

```lua
fm.setTemplate("hello", "Hello, {%& name %}")
fm.setRoute("/hello/:name", function(r)
    return fm.serveContent("hello", {name = r.params.name})
  end)
```

There is also one subtle difference between `render` and `serveContent`
methods that comes into play when *serving static templates*. It may be
tempting to directly render a static template in response to a route
with something like this:

```lua
fm.setTemplate("hello", "Hello, World!")
-- option 1:
fm.setRoute("/hello", fm.render("hello"))
-------------------------└─────┘-------- not going to work
-- option 2:
fm.setRoute("/hello", fm.serveContent("hello"))
-------------------------└───────────┘-- works as expected
```

The first approach is not going to work, as the call to `fm.render` is
going to be made when `setRoute` is called (and the route is only being
set up) and not when a request is being handled. When the `serveContent`
method is using (the second option), it's implemented in a way that delays
the processing until the request is handled, thus avoiding the issue.
If the template content depends on some values in the request, then the
`serverContent` call has to be wrapped into a function to accept and pass
those variables (as shown in the earlier `/hello/:name` route example).

#### Special templates

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
directory.

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

This returns the 413 status code and sets the body of the returned
message to `Payload Too Large` (with the header table not specified).

If only the status code needs to be set, the library provides a short
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

### Database management

Fullmoon's function `makeStorage` is a way to connect to, and use a `SQLite3`
database. `makeStorage` returns a _database management_ table which contains
a rich set of functions to use with the connected database.

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
- `trustedIp`: configures IP address to trust (mult).
  This option accepts two values (IP and CIDR values), so they need to
  be passed as a table within a table specifying multiple parameters:
  `trustedIp = {{ParseIp("103.31.4.0"), 22}, {ParseIp("104.16.0.0"), 13}}`
- `tokenBucket`: enables DDOS protection.
  This option accepts zero to 5 values (passed as a table within a table);
  an empty table can be passed to use default values: `tokenBucket = {{}}`

Each option can accept a simple value (`port = 80`), a list of values
(`port = {8080, 8081}`) or a list of parameters. Since both the list of
values and the list of parameters are passed as tables, the list of values
takes precedence, so if a list of parameters needs to be passed to an option
(like `trustedIp`), it has to be wrapped into a table:
`trustedIp = {{ParseIp("103.31.4.0"), 22}}`.
If only one parameter needs to be passed, then both
`trustedIp = {ParseIp("103.31.4.0")}` and `trustedIp = ParseIp("103.31.4.0")`
can work.

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
call), then a message is logged explaining how to apply the current random
value to make it permanent.

Setting this value to `false` or an empty string applies hashing without a
secret key.

### Logging

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

### 3-rd party benchmarks

[Berwyn Hoyt](https://berwyn.hashnode.dev/) included Redbean results in his
[lua server benchmark](https://github.com/berwynhoyt/lua-server-benchmark) results,
which shows redbean outperforming a comparable nginx/openresty implementation.

## Status

Highly experimental with everything being subject to change.

The core components are more stable and have been rarely updated since v0.3.
Usually, the documented interfaces are much more stable than undocumented
ones. Those commits that modified some of the interfaces are marked with
`COMPAT` label, so can be easily identified to review for any compatibility
issues.

Some of the obsolete methods are still present (with a warning logged when
used) to be removed later.

## Author

Paul Kulchenko (paul@zerobrane.com)

## License

See [LICENSE](LICENSE).
