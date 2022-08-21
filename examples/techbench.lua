-- TechEmpower Benchmark implementation for Fullmoon web framework
-- (https://github.com/TechEmpower/FrameworkBenchmarks/)
-- Copyright 2021-22 Paul Kulchenko

-- data setup
local lsqlite3 = require"lsqlite3"
local dbm = lsqlite3.open_memory()
if dbm:exec[[
CREATE TABLE IF NOT EXISTS World (id INTEGER PRIMARY KEY, randomNumber INTEGER NOT NULL default 0);
CREATE TABLE IF NOT EXISTS Fortune (id INTEGER PRIMARY KEY, message TEXT);
CREATE TABLE IF NOT EXISTS CachedWorld (id INTEGER PRIMARY KEY, randomNumber INTEGER NOT NULL default 0);
INSERT INTO Fortune (id, message) VALUES (1, 'fortune: No such file or directory');
INSERT INTO Fortune (id, message) VALUES (2, 'A computer scientist is someone who fixes things that aren''t broken.');
INSERT INTO Fortune (id, message) VALUES (3, 'After enough decimal places, nobody gives a damn.');
INSERT INTO Fortune (id, message) VALUES (4, 'A bad random number generator: 1, 1, 1, 1, 1, 4.33e+67, 1, 1, 1');
INSERT INTO Fortune (id, message) VALUES (5, 'A computer program does what you tell it to do, not what you want it to do.');
INSERT INTO Fortune (id, message) VALUES (6, 'Emacs is a nice operating system, but I prefer UNIX. — Tom Christaensen');
INSERT INTO Fortune (id, message) VALUES (7, 'Any program that runs right is obsolete.');
INSERT INTO Fortune (id, message) VALUES (8, 'A list is only as strong as its weakest link. — Donald Knuth');
INSERT INTO Fortune (id, message) VALUES (9, 'Feature: A bug with seniority.');
INSERT INTO Fortune (id, message) VALUES (10, 'Computers make very fast, very accurate mistakes.');
INSERT INTO Fortune (id, message) VALUES (11, '<script>alert("This should not be displayed in a browser alert box.");</script>');
INSERT INTO Fortune (id, message) VALUES (12, 'フレームワークのベンチマーク');
]] > 0 then error("can't create tables: "..dbm:errmsg()) end
local function fetchRow(stmt, ...)
  if stmt:bind_values(...) > 0 then error("can't bind values: "..dbm:errmsg()) end
  local f, s = stmt:nrows()
  local row = f(s)
  stmt:reset()
  return row
end
local function exec(stmt, ...)
  if stmt:bind_values(...) > 0 then error("can't bind values: "..dbm:errmsg()) end
  if stmt:step() ~= lsqlite3.DONE then error("can't execute prepared statement: "..dbm:errmsg()) end
  stmt:reset()
end

local randomInsertDStmt = dbm:prepare("INSERT INTO World (id, randomNumber) VALUES (?, ?)")
local randomInsertMStmt = dbm:prepare("INSERT INTO CachedWorld (id, randomNumber) VALUES (?, ?)")
dbm:exec("begin") -- open transaction for bulk insert
for i = 1, 10000 do
  exec(randomInsertDStmt, i, math.random(10000))
  exec(randomInsertMStmt, i, math.random(10000))
end
dbm:exec("end")

-- framework setup
local fm = require "fullmoon"
fm.setTemplate("fortune", [[<!DOCTYPE html><html><head><title>Fortunes</title></head><body>
 <table><tr><th>id</th><th>message</th></tr>
 {% for i = 1,#fortunes do %}
   <tr><td>{%= fortunes[i][1] %}</td><td>{%& fortunes[i][2] %}</td></tr>
 {% end %}
 </table></body></html>]])

local function inRange(value, min, max)
  value = tonumber(value) or 1
  return value < min and min or value > max and max or value
end
local randomSelectDStmt = dbm:prepare"SELECT id, randomNumber FROM World WHERE id = ?"
local randomSelectMStmt = dbm:prepare"SELECT id, randomNumber FROM CachedWorld WHERE id = ?"
local randomUpdateStmt = dbm:prepare"UPDATE World SET randomnumber = ? WHERE id = ?"

fm.setRoute(fm.GET"/plaintext", fm.serveResponse(200, "Hello, World!"))
fm.setRoute(fm.GET"/json", fm.serveContent("json", {Message = "Hello, World!"}))
fm.setRoute(fm.GET"/db", function(r)
    return fm.serveContent("json", fetchRow(randomSelectDStmt, math.random(10000)))
  end)
fm.setRoute(fm.GET{"/queries/?", "/cached-worlds/?"}, function(r)
    local stmt = r.path:find("^/queries") and randomSelectDStmt or randomSelectMStmt
    local results = {}
    for i = 1, inRange(r.params.queries, 1, 500) do
      results[i] = fetchRow(stmt, math.random(10000))
    end
    return fm.serveContent("json", results)
  end)
fm.setRoute(fm.GET"/updates/?", function(r)
    local results = {}
    for i = 1, inRange(r.params.queries, 1, 500) do
      results[i] = fetchRow(randomSelectDStmt, math.random(10000))
      results[i].randomNumber = math.random(10000) -- assign new random number
      exec(randomUpdateStmt, results[i].randomNumber, results[i].id)
    end
    return fm.serveContent("json", results)
  end)
fm.setRoute(fm.GET"/fortunes", function(r)
    local num, fortunes = 2, {{0, "Additional fortune added at request time."}}
    for id, message in dbm:urows("SELECT id, message FROM Fortune") do
      fortunes[num] = {id, message}
      num = num + 1
    end
    table.sort(fortunes, function(a, b) return a[2] < b[2] end)
    return fm.serveContent("fortune", {fortunes = fortunes})
  end)
fm.run({port = 8080})
