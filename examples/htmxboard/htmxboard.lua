-- Minimalistic trello-like clone using Fullmoon web framework
-- Based on https://github.com/rajasegar/htmx-trello
-- Copyright 2022 Paul Kulchenko

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
fm.setRoute("/", fm.serveContent("index", {lists = lists}))

fm.setRoute(fm.GET{"/list/add", routeName="list-add"},
  fm.serveContent("add-list"))
fm.setRoute(fm.GET{"/list/cancel", routeName="list-cancel"},
  fm.serveContent("new-list"))
fm.setRoute(fm.POST{"/board/?", routeName="board"},
  function(r)
    table.insert(lists, {
      name = r.params.name,
      id = newid(),
      cards = {find = finder("card")},
    })
    return fm.serveContent("board", {lists = lists})
  end)

fm.setRoute(fm.POST{"/card/new/:listid", routeName="card-new"},
  function(r)
    local listid = r.params.listid
    local list = lists:find(listid)
    local card = {
      label = r.params['label-' .. listid],
      id = newid(),
      listid = listid,
    }
    table.insert(list.cards, card)
    return fm.serveContent("card", {card = card})
  end)
fm.setRoute(fm.GET{"/card/edit/:listid/:id", routeName="card-edit"},
  function(r)
    local list = lists:find(r.params.listid)
    local card = list.cards:find(r.params.id)
    return fm.serveContent("edit-card", {card = card})
  end)
fm.setRoute(fm.PUT{"/card/:listid/:id", routeName="card-save"},
  function(r)
    local list = lists:find(r.params.listid)
    local card = list.cards:find(r.params.id)
    card.label = r.params.label
    return fm.serveContent("card", {card = card})
  end)
fm.setRoute(fm.GET{"/card/cancel-edit/:listid/:id",
    routeName="card-edit-cancel"},
  function(r)
    local list = lists:find(r.params.listid)
    local card = list.cards:find(r.params.id)
    return fm.serveContent("card", {card = card})
  end)
fm.setRoute(fm.DELETE{"/card/:listid/:id", routeName="card-delete"},
  function(r)
    local list = lists:find(r.params.listid)
    local card, idx = list.cards:find(r.params.id)
    table.remove(list.cards, idx)
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
fm.setRoute(fm.GET{"/showstate", clientAddr = {fm.isLoopbackIp, otherwise = 403}},
  function(r)
    fm.write("<pre>")
    for _, l in ipairs(lists) do
      fm.write(("list %s (%s)</br>"):format(l.name, l.id))
      for _, c in ipairs(l.cards) do
        fm.write(("  card %s (%s in %s)</br>"):format(c.label, c.id, c.listid))
      end
    end
    fm.write("</pre>")
    return true -- everything has been served already
  end)

fm.run()
