local out = io.open("CONOUT$", "w")
if out then out:setvbuf("no") end

local function w(s) if out then out:write(s .. "\n") end end

local access_flags = {
    [0x80000000] = "GENERIC_READ",
    [0x40000000] = "GENERIC_WRITE",
    [0x20000000] = "GENERIC_EXECUTE",
    [0x10000000] = "GENERIC_ALL",
}

local disposition_flags = {
    [1] = "CREATE_NEW",
    [2] = "CREATE_ALWAYS",
    [3] = "OPEN_EXISTING",
    [4] = "OPEN_ALWAYS",
    [5] = "TRUNCATE_EXISTING",
}

local function resolve_access(val)
    local found = {}
    for flag, name in pairs(access_flags) do
        if val & flag ~= 0 then
            found[#found + 1] = name
        end
    end
    return #found > 0 and table.concat(found, " | ") or string.format("0x%X", val)
end

local Handlers = {

    ["CreateFileW"] = function(args)
        w("========================================")
        w("[!] Interceptado: CreateFileW")
        w("    Arquivo    : " .. (args.filename or "(nil)"))
        w("    Acesso     : " .. resolve_access(args.desired_access or 0))
        w("========================================")
    end,

    ["DispatchMessageW"] = function(args)
            if args.message == 0x0102 then
                local letraOriginal = string.char(math.floor(args.wparam))
                w("[!] Letra digitada: " .. letraOriginal .. " -> Substituindo por G")
                
                return 0x47 
            end
        end,
    
    ["SetWindowTextW"] = function(args)
         w("[!] Notepad++ tentou mudar o título para: " .. args.title)
        return "Trabalho de diplomação Matheus | Nome original: " .. args.title
    end, 

    ["WriteFile"] = function(args)
        w("========================================")
        w("[!] ALERTA DE GRAVACAO DE ARQUIVO")
        w("    Tamanho do Bufaaafer: " .. args.bytes_to_write .. " bytes")
        
        if string.find(args.buffer_content, "senha_secreta") then
            w("[!!!] Informacao sensivel sendo salva!")
        end
        w("========================================")
    end

}

function OnHookTrigger(eventName, args)
    local handler = Handlers[eventName]
    if handler then
        local success, res = pcall(handler, args)
        if success then
            return res 
        else
            w("[-] Erro no handler [" .. eventName .. "]: " .. tostring(res))
        end
    end
end