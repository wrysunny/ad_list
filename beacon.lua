local beacon = {}
function Devicebeacon()
    beacon.vbatt = misc.getVbatt() / 1000                   -- 电池电压(V)
    beacon.temp = misc.getTemperature()                     -- mcu温度(℃)
    beacon.model = rtos.get_version()                       -- 模块型号
    beacon.imei = "*" .. string.sub(misc.getImei(), -4)  -- imei 串号
    beacon.rssi = 2 * net.getRssi() - 113                         -- 信号

    return beacon
end

function Gpsbeacon()
    beacon.lat = 
    beacon.long = 
    beacon.spd = 
    beacon.sat = 
    beacon.alt = 
    beacon.heading = -- 航向角

    return beacon
end


-- 一次性获取完整信标数据
function GetFullBeacon()
    -- 设备刚开机有些数据拿不到，要等会
    Devicebeacon()
    Gpsbeacon()
    return beacon
end

sys.taskInit(function ()
    while true do
        GetFullBeacon()
        log.info("beacon:",beacon)
        sys.wait(60000)
    end
end)