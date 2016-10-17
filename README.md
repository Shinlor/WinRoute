# WinRoute
Use Python to Manage Windows Route Table with IP Helper Functions（iphlpapi.dll）

##Python调用IP Helper Functions（iphlpapi.dll），实现对Windows路由表的操作（参考了MSDN及部分网络代码）
- 使用printroute，打印输出当前win路由表(IPv4)
- 使用getroute，得到当前win路由表(IPv4)
- 使用CreateIpForwardEntry，添加新的路由，使用参数dwForwardDest,dwForwardMask,dwForwardNextHop=None,dwForwardMetric=0,ForwardIfIndex=None，对应目标IP，掩码，网关（不提供与默认路由相同），跃点数（不提供与默认路由相同），接口（不提供与默认路由相同）


