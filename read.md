beacon.lua中 gps、device需要开机等一会才能拿到数据。等gps定位成功再执行？
gps.lua 如果开机3钟没有定位成功，就关闭gps供电直到10分钟后打开gps尝试定位 是否设置为局部函数 省内存 
gps模块使用中科微 AT6558 系列（合宙模组标配 GPS 芯片） [GPS] 型号 530Z 波特率 9600 require "gpsZkw" require "agpsZkw"
使用sys.subscribe("GPS_STATE" 订阅gps有没有准备好

