#!/usr/bin/python
# -*- coding:utf-8 -*-

import winroute.winroute as winroute

#实例
route=winroute.WinRoute()

#输出当前路由表（IPv4）
route.printroute()

#添加一个路由，给出：目标IP，子网掩码，网关(即下一跳IP，不给出与默认路由的相同)，Metric值（不给出则与默认路由的相同），接口（不给出则与默认路由的相同）
route.CreateIpForwardEntry("1.0.7.0","255.255.255.0","192.168.1.1")