-- Minimalistic trello-like example using Fullmoon web framework
-- Based on https://github.com/rajasegar/htmx-trello
-- Copyright 2022 Paul Kulchenko

-- NOTE: current imlementation requires redbean launched with -u (uniprocess) option

local fm = require "fullmoon"

local function finder(type)
  return function (tbl, id, checkonly)
    for i, v in ipairs(tbl) do
      if v.id == id then return v, i end
    end
    if checkonly then return nil end
    assert(false, "can't find "..type.." for id "..id)
  end
end
local function newid()
  return fm.encodeBase64(fm.getRandomBytes(6)):gsub("%W",""):lower()
end
local lists = {find = finder("list")}

fm.setTemplate({"/tmpl/", fmt = "fmt", fmg = "html"})
fm.setRoute("/favicon.ico", fm.serveAsset)
fm.setRoute("/*", "/assets/*")
fm.setRoute(fm.GET"/", fm.serveContent("index", {lists = lists}))

fm.setRoute(fm.GET{"/list/add", routeName="list-add"},
  fm.serveContent("list-add"))
fm.setRoute(fm.GET{"/list/cancel", routeName="list-cancel"},
  fm.serveContent("list-new"))
fm.setRoute(fm.POST{"/board/?", routeName="board"},
  function(r)
    table.insert(lists, {
      name = r.params.name,
      id = 'l'..newid(),
      cards = {find = finder("card")},
    })
    return fm.serveContent("board", {lists = lists})
  end)

-- this is a hook/before route that loads the card value
-- and stores them in the request object
fm.setRoute("/card/:listid(/:id)(/*)", function(r)
    r.list = lists:find(r.params.listid)
    r.card = r.params.id and r.list.cards:find(r.params.id) or nil
    -- check other routes, as nothing (falsy value) is returned here
  end)

fm.setRoute(fm.PUT{"/card/:listid(/:id)", routeName="card-save"},
  function(r)
    local card = r.card
    if not card then
      card = { id = 'c'..newid(), listid = r.params.listid }
      table.insert(r.list.cards, card)
    end
    card.label = r.params.label
    return fm.serveContent("card", {card = card})
  end)
fm.setRoute(fm.GET{"/card/:listid/:id/edit", routeName="card-edit"},
  function(r)
    return fm.serveContent("card-edit", {card = r.card})
  end)
fm.setRoute(fm.GET{"/card/:listid/:id", routeName="card-get"},
  function(r)
    return fm.serveContent("card", {card = r.card})
  end)
fm.setRoute(fm.DELETE{"/card/:listid/:id", routeName="card-delete"},
  function(r)
    local _, idx = r.list.cards:find(r.params.id)
    table.remove(r.list.cards, idx)
    return ""
  end)
fm.setRoute(fm.POST{"/card/move", routeName="card-move"},
  function(r)
    local fromlist = lists:find(r.params.from:gsub("list%-",""))
    local tolist = lists:find(r.params.to:gsub("list%-",""))
    local cardid = r.params.movedCard:gsub("card%-","")
    -- check if ids are the different
    if fromlist.id ~= tolist.id
    -- check if the card is still there
    and fromlist.cards:find(cardid, true) then
      local card, idx = fromlist.cards:find(cardid)
      table.remove(fromlist.cards, idx)
      card.listid = tolist.id
      table.insert(tolist.cards, card)
    end
    return fm.serveContent("board", {lists = lists})
  end)

-- debugging route; only available locally
fm.setRoute(fm.GET{"/state/?", clientAddr = {fm.isLoopbackIp, otherwise = 403}},
  fm.serveContent("state-show", {lists = lists}))

fm.run()
