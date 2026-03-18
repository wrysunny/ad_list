
function OpenGps()
    -- gps 初始化上电  RDA8910芯片
    -- 中科微 AT6558 系列（合宙模组标配 GPS 芯片）
    pmd.ldoset(15,pmd.LDO_VIBR) -- 开启GPS电源
    rtos.sys32k_clk_out(1) -- 开启32K时钟
    
end

function CloseGps()
    -- 关闭gps供电
    pmd.ldoset(0, pmd.LDO_VIBR)
    rtos.sys32k_clk_out(0)
end