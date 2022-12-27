-- showcase for the database management capabilities of Fullmoon

local fm = require "fullmoon"

-- `makeStorage` can have an optional setup query
-- this is executed when the database is opened
local initQuery = [[CREATE TABLE test (id INTEGER PRIMARY KEY, content);]]

-- open the database in :memory:  -  sqlite.org/inmemorydb.html
-- or open an already existing database by providing the filepath
local db = fm.makeStorage(":memory:", initQuery)

-- execute multiple statements in a list with `execall`
assert(db:execall({
    "INSERT INTO test VALUES (NULL, 'Hello Fullmoon');",
    "INSERT INTO test VALUES (NULL, 'Hello Redbean');",
    "INSERT INTO test VALUES (NULL, 'Hello Sqlite3');"
}))

-- insert values to the '?' placeholder in the query with `exec`
assert(db:exec([[INSERT INTO test (content) VALUES (?)]], "Smart insert!"))

-- fetch all the rows of the query with `fetchall`
local result = assert(db:fetchall[[SELECT * FROM test;]])

-- the resulting rows are key-value pair with the column as the key
for _, row in ipairs(result) do
    local content = row["content"]   -- can also use row.content
    print("content: "..content)
end


-- temporary open a database with the following `do` block
-- <close> is introduced in Lua5.4 for fast release of valuable limited resources
-- with this tag the database will close whenever the variable goes out of scope
local row
do
    -- open the `database` temporarily by using the <close> tag
    local database <close> = fm.makeStorage(":memory:")
    -- fetch one row with `fetchone`
    row = assert(database:fetchone[[SELECT sqlite_version() as version;]])
end
-- `database` is no longer open
print("SQLite verion: "..row.version)


fm.run({port = 8080})