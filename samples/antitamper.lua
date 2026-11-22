-- oh my days deobfuscated this obfuscator with this special deobfuscator so insane
local antitamper = function()
    if _G.lune ~= nil or _G.lute ~= nil then
        return true
    end
    local ok = pcall(function()
        local fs = require("@lune/fs")
        return fs
    end)
    if ok then
        return true
    end
    if type(game) ~= "userdata" or type(workspace) ~= "userdata" then
        return true
    end
    if typeof == nil or typeof(game) ~= "Instance" or game.ClassName ~= "DataModel" then
        return true
    end
    if typeof(workspace) ~= "Instance" or workspace.ClassName ~= "Workspace" or workspace.Parent ~= game then
        return true
    end
    if Instance == nil or task == nil or Enum == nil or Vector3 == nil or CFrame == nil or UDim2 == nil or Color3 == nil or Random == nil then
        return true
    end
    if coroutine == nil or type(coroutine.wrap) ~= "function" then
        return true
    end
    local x173 = (debug ~= nil)
    if debug ~= nil then
        local ok2 = pcall(function()
            return debug.getinfo(print).what
        end)
        x173 = (not ok2)
    end
    if x173 then
        return true
    end
    if Enum.PartType.Cylinder.Name ~= "Cylinder" then
        return true
    end
    if Enum.PartType.Cylinder.Value ~= 2 then
        return true
    end
    if tostring(Enum.PartType.Cylinder.EnumType) ~= "PartType" then
        return true
    end
    local part = Instance.new("Part")
    local ok3 = pcall(function()
        part.Shape = Enum.PartType.Cylinder
        return
    end)
    local x218 = (not ok3)
    if ok3 then
        local ok4 = pcall(function()
            part.Shape = "Cylinder"
            return
        end)
        x218 = (not ok4)
    end
    if x218 then
        return true
    end
    part.Parent = workspace
    if part.Parent ~= workspace then
        return true
    end
    if part.Shape ~= Enum.PartType.Cylinder then
        return true
    end
    part:Destroy()
    if typeof(Vector3.new()) ~= "Vector3" then
        return true
    end
    if typeof(CFrame.new()) ~= "CFrame" then
        return true
    end
    if typeof(UDim2.new()) ~= "UDim2" then
        return true
    end
    if typeof(Color3.new()) ~= "Color3" then
        return true
    end
    if typeof(Random.new()) ~= "Random" then
        return true
    end
    if typeof(Enum.KeyCode.A) ~= "EnumItem" then
        return true
    end
    if Enum.KeyCode.A.Value ~= 97 then
        return true
    end
    if typeof(workspace.Gravity) ~= "number" then
        return true
    end
    local ok5 = pcall(function()
        return game:GetService("RunService"):IsClient()
    end)
    if not ok5 then
        return true
    end
    local ok6 = pcall(function()
        local Debris = game:GetService("Debris")
        return Debris
    end)
    if not ok6 then
        return true
    end
    if typeof(Vector3.new(1, 2, 3).Unit) ~= "Vector3" then
        return true
    end
    if Vector3.new(3, 4, 0).Magnitude ~= 5 then
        return true
    end
    local ok7 = pcall(function()
        return Vector3.new(1, 2, 3):FuzzyEq(Vector3.new(1.0001, 2.0001, 3.0001))
    end)
    if not ok7 then
        return true
    end
    local x356 = {}
    local mt = {}
    local __index = {}
    __index.a = 1
    mt.__index = __index
    setmetatable(x356, mt)
    if x356.a ~= 1 then
        return true
    end
    local x372 = task.spawn(function()
        return
    end)
    if typeof(x372) ~= "thread" then
        return true
    end
    task.cancel(x372)
    if type(typeof) ~= "function" then
        return true
    end
    local x392 = {}
    if typeof(x392) ~= "table" then
        return true
    end
    local x402 = ((2.5 // 1) ~= 2)
    if not ((2.5 // 1) ~= 2) then
        local x406 = (1 > 2)
        if 1 > 2 then
            x406 = 1
        end
        local x408 = x406
        if not x406 then
            x408 = 2
        end
        x402 = (x408 ~= 2)
    end
    if x402 then
        return true
    end
    if (7 % 3) ~= 1 or (2 ^ 5) ~= 32 then
        return true
    end
    if tostring((0.1 + 0.2)):sub(1, 3) ~= "0.3" then
        return true
    end
    if string.byte("A") ~= 65 or string.len("abc") ~= 3 then
        return true
    end
    local x457 = {}
    x457[1] = 1
    x457[2] = 2
    x457[3] = 3
    if table.concat(x457) ~= "123" then
        return true
    end
    if bit32.bxor(5, 3) ~= 6 or bit32.band(12, 10) ~= 8 then
        return true
    end
    local ok8, err = pcall(function()
        return loadstring
    end)
    if ok8 and err ~= nil then
        local ok9, err2 = pcall(function()
            return loadstring("return 1")()
        end)
        if not (ok9 and err2 == 1) then
            return true
        end
    end
    local x509 = {workspace.CurrentCamera}
    local x513 = (workspace.CurrentCamera ~= nil)
    if workspace.CurrentCamera ~= nil then
        local ok10 = pcall(function()
            return x509[1].CFrame:Inverse()
        end)
        x513 = (not ok10)
    end
    if x513 then
        return true
    end
    local Players = game:GetService("Players")
    if Players.LocalPlayer ~= nil and typeof(Players.LocalPlayer) ~= "Instance" then
        return true
    end
    if settings == nil then
        return true
    end
    local ok11 = pcall(function()
        return settings()
    end)
    if not ok11 then
        return true
    end
    if os ~= nil and os.time ~= nil and not (pcall(os.time)) then
        return true
    end
    if game:GetService("RunService"):IsRunning() then
        local part2 = Instance.new("Part")
        part2.Anchored = false
        part2.CanCollide = false
        part2.Size = Vector3.new(2, 2, 2)
        part2.Position = Vector3.new(0, 500, 0)
        part2.Parent = workspace
        local bodyVelocity = Instance.new("BodyVelocity")
        bodyVelocity.MaxForce = Vector3.new(100000, 100000, 100000)
        bodyVelocity.Velocity = Vector3.new(0, 10, 0)
        bodyVelocity.Parent = part2
        task.wait(0.2)
        part2:Destroy()
        if not (part2.AssemblyLinearVelocity.Y and part2.AssemblyLinearVelocity.Y > 1) then
            return true
        end
        local part3 = Instance.new("Part")
        part3.Anchored = false
        part3.CanCollide = false
        part3.Size = Vector3.new(2, 2, 2)
        part3.Position = Vector3.new(0, 500, 0)
        part3.Parent = workspace
        local bodyPosition = Instance.new("BodyPosition")
        bodyPosition.P = 10000
        bodyPosition.D = 1000
        bodyPosition.MaxForce = Vector3.new(0, 100000, 0)
        bodyPosition.Position = Vector3.new(0, 560, 0)
        bodyPosition.Parent = part3
        task.wait(0.3)
        part3:Destroy()
        if not (part3.Position.Y > 520) then
            return true
        end
        local part4 = Instance.new("Part")
        part4.Anchored = false
        part4.CanCollide = false
        part4.Size = Vector3.new(2, 2, 2)
        part4.Position = Vector3.new(0, 500, 0)
        part4.Parent = workspace
        task.wait(0.3)
        part4:Destroy()
        local x764 = {0}
        if part4.AssemblyLinearVelocity.Y ~= nil then
            x764[1] = (part4.AssemblyLinearVelocity.Y - ((-workspace.Gravity) * 0.3))
            if x764[1] < 0 then
                x764[1] = -x764[1]
            end
        end
        if not (part4.AssemblyLinearVelocity.Y and x764[1] < 12) then
            return true
        end
    end
    return false
end
return antitamper
