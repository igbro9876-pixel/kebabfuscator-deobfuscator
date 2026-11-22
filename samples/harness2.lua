-- harness.lua: run the obfuscated Kebabfuscator sample under Lua 5.1 with
-- minimal Roblox stubs; report what happens (prints/errors).
-- NOTE: 'hi' printing and any error line are the outputs of interest.

-- bit32 shim (Lua 5.1 lacks bit32)
if not bit32 then
  bit32 = {
    band = function(a, b) a = a % 4294967296; b = b % 4294967296
      local r, bitv = 0, 1
      while bitv <= a or bitv <= b do
        if (a % (2*bitv) >= bitv) and (b % (2*bitv) >= bitv) then
          r = r + bitv
        end
        bitv = bitv * 2
      end
      return r end,
    bor = function(a, b) a = a % 4294967296; b = b % 4294967296
      local r, bitv = 0, 1
      while bitv <= a or bitv <= b do
        if (a % (2*bitv) >= bitv) or (b % (2*bitv) >= bitv) then
          r = r + bitv
        end
        bitv = bitv * 2
      end
      return r end,
    bxor = function(a, b) a = a % 4294967296; b = b % 4294967296
      local r, bitv = 0, 1
      while bitv <= a or bitv <= b do
        local pa = a % (2*bitv) >= bitv
        local pb = b % (2*bitv) >= bitv
        if (pa and not pb) or (pb and not pa) then r = r + bitv end
        bitv = bitv * 2
      end
      return r end,
    bnot = function(x) return (4294967295 - x) end,
    rshift = function(a, b) return math.floor((a % 4294967296) / 2 ^ b) end,
    lshift = function(a, b)
      local r = (a % 4294967296) * 2 ^ b
      return r - (r % 4294967296)
    end,
  }
end
table.unpack = table.unpack or unpack

-- magic object constructor
local function magic(name)
  local metat = {
    __index = function(t, k) return magic(name .. '.' .. tostring(k)) end,
    __call = function(t, ...) return magic(name .. '()') end,
    __tostring = function(t) return '<STUB ' .. name .. '>' end,
    __STUB = true,
    __NAME = name,
  }
  local o = setmetatable({}, metat)
  return o
end

-- tag helper: mark a plain table with a Roblox typeof class
local function tagged(t, cls)
  local mt = getmetatable(t) or {}
  mt.__TYPEOF = cls
  mt.__STUB = true
  return setmetatable(t, mt)
end

local game = magic('game')
game.ClassName = 'DataModel'
local workspace = magic('Workspace')
workspace.ClassName = 'Workspace'
rawset(workspace, 'Parent', game)
game.Parent = game
workspace.Gravity = 196.2

-- make stub objects read as 'userdata' (Roblox instances are userdata)
local orig_type = type
_G.orig_type = orig_type
_G.type = function(x)
  local mt = orig_type(x) == 'table' and getmetatable(x) or nil
  if mt ~= nil and mt.__STUB then return 'userdata' end
  return orig_type(x)
end

_G.game = game
_G.workspace = workspace
_G.typeof = function(x)
  local t = orig_type(x)
  local mt = (t == 'table' or t == 'userdata') and getmetatable(x) or nil
  if mt ~= nil and mt.__TYPEOF then return mt.__TYPEOF end
  if mt ~= nil and mt.__STUB then
    local nm = mt.__NAME
    if nm ~= nil and not nm:find('^Instance')
        and not nm:find('^game') and not nm:find('^Workspace') then
      return nm
    end
    return 'Instance'
  end
  return t
end
-- userdata-backed Part stub: metaevents must fire for ALL writes,
-- including overwrites of existing fields (Roblox coerces enum strings)
local function newpart()
  local state = {}
  local px = newproxy(true)
  local mt = getmetatable(px)
  mt.__STUB = true
  mt.__tostring = function() return '<STUB Instance.Part>' end
  mt.__index = function(t, k)
    local v = state[k]
    if v ~= nil then return v end
    if k == 'AssemblyLinearVelocity' then
      local pv = state.Velocity or state.AssemblyLinearVelocity
      if pv ~= nil then return pv end
      return _G.Vector3.new(0, 0, 0)
    end
    if k == 'Velocity' then return state.Velocity or _G.Vector3.new(0, 0, 0) end
    return magic('Instance.Part.' .. tostring(k))
  end
  mt.__newindex = function(t, k, v)
    if k == 'Shape' and v == 'Cylinder' then
      v = _G.Enum.PartType.Cylinder
    end
    state[k] = v
  end
  _G.__LASTPART = px
  _G.__LASTPART_STATE = state
  _G.__PARTS = _G.__PARTS or {}
  _G.__PARTS[#_G.__PARTS + 1] = { px = px, state = state }
  return px
end

-- BodyVelocity / BodyPosition stub that drives the part it is parented to
local function newcontraption(cls, drivekey)
  local state = {}
  local px = newproxy(true)
  local mt = getmetatable(px)
  mt.__STUB = true
  mt.__NAME = 'Instance.' .. cls
  mt.__tostring = function() return '<STUB Instance.' .. cls .. '>' end
  mt.__index = function(t, k)
    local v = state[k]
    if v ~= nil then return v end
    return magic('Instance.' .. cls .. '.' .. tostring(k))
  end
  mt.__newindex = function(t, k, v)
    if k == 'Parent' and rawequal(v, _G.__LASTPART) then
      -- emulate physics: the constraint drives the parented part
      _G.__LASTPART_STATE.__drive = drivekey
      if state[drivekey] ~= nil then
        _G.__LASTPART_STATE[drivekey] = state[drivekey]
      end
    end
    state[k] = v
  end
  return px
end
_G.Instance = {
  new = function(cls, ...)
    if cls == 'Part' then return newpart() end
    if cls == 'BodyVelocity' then return newcontraption('BodyVelocity', 'Velocity') end
    if cls == 'BodyPosition' then return newcontraption('BodyPosition', 'Position') end
    return magic('Instance.' .. cls)
  end,
}
_G.task = {
  wait = function(t)
    t = t or 0
    -- free parts (no constraint attached) fall under workspace.Gravity
    for _, entry in ipairs(_G.__PARTS or {}) do
      local st = entry.state
      if st.__drive == nil then
        local vy = 0
        if st.Velocity ~= nil and type(st.Velocity) == 'table' then
          vy = st.Velocity.Y or 0
        end
        vy = vy - (workspace.Gravity or 0) * t
        st.Velocity = _G.Vector3.new(0, vy, 0)
      end
    end
    return t, t
  end,
  spawn = function(f, ...)
    local co = coroutine.create(f)
    local ok, e = coroutine.resume(co, ...)
    if not ok then print('TASK_SPAWN_ERR: ' .. tostring(e)) end
    return co
  end,
  delay = function(t, f, ...)
    local co = coroutine.create(f)
    local ok, e = coroutine.resume(co, ...)
    if not ok then print('TASK_DELAY_ERR: ' .. tostring(e)) end
    return co
  end,
  cancel = function(co)
    pcall(coroutine.resume, co)
    return nil
  end,
}
local orig_pcall = pcall
_G.pcall = function(f, ...)
  local r = { orig_pcall(f, ...) }
  if not r[1] then
    print('PCALL_ERR: ' .. tostring(r[2]))
  end
  return unpack(r)
end
_G.Enum = { PartType = { Cylinder = { EnumType = 'PartType' } } }
rawset(_G.Enum.PartType.Cylinder, 'Name', 'Cylinder')
rawset(_G.Enum.PartType.Cylinder, 'Value', 2)
local keyA = tagged({ Name = 'A', Value = 97, EnumType = 'Enum.KeyCode' }, 'EnumItem')
_G.Enum.KeyCode = tagged({ A = keyA }, 'Enum')
_G.UDim2 = { new = function(...) return magic('UDim2') end }
_G.CFrame = {
  new = function(...)
    local pos = tagged({ Unit = {}, LookVector = { X = 0, Y = 1, Z = 0 } }, 'Vector3')
    pos.Unit.LookVector = { X = 0, Y = 1, Z = 0 }
    pos.Unit.Unit = tagged({ WorldPosition = { X = 0, Y = 0, Z = 0 } }, 'Vector3')
    local cf = tagged({ Position = pos, LookVector = { X = 0, Y = 1, Z = 0 } }, 'CFrame')
    return cf
  end,
  lookAt = function(...) return tagged({}, 'CFrame') end,
}
_G.Vector3 = {
  new = function(x, y, z)
    x = x or 0; y = y or 0; z = z or 0
    local mag = math.sqrt(x * x + y * y + z * z)
    local function norm()
      if mag == 0 then
        return tagged({ X = 0, Y = 0, Z = 0, Magnitude = 0, LookVector = { X = 0, Y = 0, Z = 0 } }, 'Vector3')
      end
      return tagged({ X = x / mag, Y = y / mag, Z = z / mag,
        Magnitude = 1, LookVector = { X = x / mag, Y = y / mag, Z = z / mag } }, 'Vector3')
    end
    return tagged({ X = x, Y = y, Z = z,
      FuzzyEq = function(a, b) return true end,
      Unit = norm(),
      LookVector = tagged({ X = x / (mag == 0 and 1 or mag),
        Y = y / (mag == 0 and 1 or mag), Z = z / (mag == 0 and 1 or mag) }, 'Vector3'),
      Magnitude = mag,
      WorldPosition = tagged({ X = 0, Y = 0, Z = 0 }, 'Vector3') }, 'Vector3')
  end,
}
_G.Color3 = { new = function(...) return magic('Color3') end }
_G.Random = setmetatable({ new = function(...) return magic('Random') end }, {
  __call = function(t, n) return 0.5 end })
_G.coroutine = coroutine
_G.settings = function() return magic('settings') end
_G.bit32 = bit32
if not _G.OsClock then _G.os = os end
_G._G = _G

print('== shims ready; loading sample ==')
-- instrument string.char to log a failing call's args
__CHAR_FAILED = nil
local orig_char = string.char
string.char = function(...)
  local a = { ... }
  for i = 1, #a do
    local v = a[i]
    if type(v) ~= 'number' or v ~= math.floor(v) or v < 0 or v > 255 then
      if not __CHAR_FAILED then
        __CHAR_FAILED = { n = #a, bad = i, val = v, args = {} }
        for j = 1, math.min(#a, 80) do
          __CHAR_FAILED.args[j] = tostring(a[j])
        end
      end
      error('CHAR_FAIL: bad arg #' .. i, 2)
    end
  end
  return orig_char(...)
end


local fh2 = assert(io.open('lifted_main.lua', 'rb'))
local lsrc = fh2:read('*a')
fh2:close()
lsrc = lsrc:gsub('^%xef%xbb%xbf', '')
local lifted, lerr = loadstring(lsrc, 'lifted')
if not lifted then
  print('LIFTED LOAD ERROR:', tostring(lerr))
  return
end
local ok2, rerr2 = xpcall(lifted, function(e)
  return 'FAIL: ' .. tostring(e)
end)
print('== lifted finished ok=', ok2, ' err=', rerr2 and tostring(rerr2):sub(1, 400))
