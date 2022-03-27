-- Server-sent-events (SSE) example

local fm = require "fullmoon"

fm.setRoute("/sse", function(r)
    if r.session.sse == "done" then
      r.session.sse = nil
      fm.logInfo("Stop SSE processing")
      -- returning 204 is supposed to stop SSE processing,
      -- but htmx-sse doesn't seem to support it
      -- return fm.serve204 -- stop sse processing
      -- let's remove the sse element instead to stop it
      return fm.serveContent("sse", {
          event = "event0",
          data = [[<div id="sse" hx-swap-oob="true">
            Refresh page to restart</div>]],
        })
    end
    -- set session before the very first stream* call,
    -- as the headers can only be sent with the first response
    r.session.sse = "done"

    fm.streamContent("sse", {
        event = "event1",
        data = "Multi-line content: Line 1<br>\nLine 2",
        retry = 5,
      })
    fm.sleep(2)
    local steps = 5
    for n = 1, steps do
      fm.streamContent("sse", {
          event = "event2",
          data = ("Dynamic content: <b>step %d</b> out of %d"):format(n, steps),
          comment = "this is a comment",
        })
      fm.sleep(2)
    end
    return fm.serveContent("sse", {data = "Unnamed event"})
  end)

fm.setRoute("/*", function() return [[
<!DOCTYPE html><html><head>
<script src="https://unpkg.com/htmx.org@1.7.0" ></script>
<script src="https://unpkg.com/htmx.org/dist/ext/sse.js" ></script>
</head>
<body><h1>Server Sent Events Example</h1>
<div id="sse" hx-ext="sse" sse-connect="/sse">
    <h2>Events are updated every 2 seconds</h2>
    <div sse-swap="event0"></div>
    <div sse-swap="event1"></div>
    <div sse-swap="event2"></div>
    <div sse-swap="message"></div>
</div></body></html>]]
end)

fm.run({port = 8080})
