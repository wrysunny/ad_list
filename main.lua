PROJECT = "4G APRS Tracker"
VERSION = "2.0.0"

require "misc"
require "log"
LOG_LEVEL = log.LOGLEVEL_TRACE
require "sys"
require "net"
require "netLed"

require "gps" -- gps
require "beacon" -- 信标


--加载网络指示灯和LTE指示灯功能模块
pmd.ldoset(2,pmd.LDO_VLCD)
netLed.setup(true,pio.P0_1,pio.P0_4)
--每1分钟查询一次GSM信号强度
net.startQueryAll(60000, 60000)
--此处关闭RNDIS网卡功能
ril.request("AT+RNDISCALL=0,1")


--启动系统框架
sys.init(0, 0)
sys.run()
