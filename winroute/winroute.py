#!/usr/bin/python
# -*- coding:utf-8 -*-
# 
__author__ = 'Shinlor'

import ctypes
import socket
import struct

DWORD = ctypes.c_ulong
NO_ERROR = 0
NULL = ""
bOrder = 0
ANY_SIZE=1

def printroute():
    #得到路由表的列表
    IpForwardTablelist=getroute()
    
    #格式化输出
    print( "%-13s %-11s %-12s %-12s %-4s %-11s %-11s %-11s %-10s %-12s %-15s %-15s %-15s %-15s" % 
           (
               '目标IP',
               '网络掩码',
               '多径路由策略',
               '下一跳IP',
               '接口索引',
               '路由类型',
               '路由协议',
               '路由时间',
               '下一跳编号',
               'Metric1',
               'Metric2',
               'Metric3',
               'Metric4',
               'Metric5')
           ) 
           
    
    for tmp in IpForwardTablelist:
        print("%-15s %-15s %-15s %-15s %-8s %-15s %-15s %-15s %-15s %-15s %-15s %-15s %-15s %-15s" % 
          (tmp['ForwardDest'],
           tmp['ForwardMask'],
           tmp['ForwardPolicy'],
           tmp['ForwardNextHop'],
           tmp['ForwardIfIndex'],
           tmp['ForwardType'],
           tmp['ForwardProto'],
           tmp['ForwardAge'],
           tmp['ForwardNextHopAS'],
           tmp['ForwardMetric1'],
           tmp['ForwardMetric2'],
           tmp['ForwardMetric3'],
           tmp['ForwardMetric4'],
           tmp['ForwardMetric5'],
           )
          )  

def getroute ():
    class MIB_IPFORWARDROW(ctypes.Structure):
        
        _fields_ = [('dwForwardDest', DWORD),#目标IP
                    ('dwForwardMask', DWORD),#网络掩码
                    ('dwForwardPolicy', DWORD),#多径路由策略
                    ('dwForwardNextHop', DWORD),#下一跳IP
                    ('dwForwardIfIndex', DWORD),#接口索引
                    ('dwForwardType', DWORD),#路由类型
                    ('dwForwardProto', DWORD),#路由协议
                    ('dwForwardAge', DWORD),#路由时间
                    ('dwForwardNextHopAS', DWORD),#下一跳编号
                    ('dwForwardMetric1', DWORD),#跃点数
                    ('dwForwardMetric2', DWORD),
                    ('dwForwardMetric3', DWORD),
                    ('dwForwardMetric4', DWORD),
                    ('dwForwardMetric5', DWORD)]

    dwSize = DWORD(0)
    IpForwardTablelist=[]
    
    # call once to get dwSize 
    dwStatus=ctypes.windll.iphlpapi.GetIpForwardTable(NULL, ctypes.byref(dwSize), bOrder)
    #print (dwStatus)
    
    # ANY_SIZE is used out of convention (to be like MS docs); even setting this
    # to dwSize will likely be much larger than actually necessary but much 
    # more efficient that just declaring ANY_SIZE = 65500.
    # (in C we would use malloc to allocate memory for the *table pointer and 
    #  then have ANY_SIZE set to 1 in the structure definition)    

    ANY_SIZE = dwSize.value
    class MIB_IPFORWARDTABLE(ctypes.Structure):
                     
        _fields_ = [('dwNumEntries', DWORD),
                    ('table', MIB_IPFORWARDROW * ANY_SIZE)] 
            
    #print (ANY_SIZE)
            
    IpForwardTable=MIB_IPFORWARDTABLE()
            
    if (ctypes.windll.iphlpapi.GetIpForwardTable(ctypes.byref(IpForwardTable), 
                                       ctypes.byref(dwSize), bOrder) == NO_ERROR):
                                        
        maxNum = IpForwardTable.dwNumEntries
        #print(IpForwardTable.dwNumEntries)
        #print (IpForwardTable.table)
        placeHolder = 0
            
        # loop through every connection
        while placeHolder < maxNum:
            item = IpForwardTable.table[placeHolder]
            IpForwardDcit={}
            placeHolder += 1
            ForwardNextHop=item.dwForwardNextHop
                                
            ForwardDest=item.dwForwardDest
            ForwardDest=socket.inet_ntoa(struct.pack('L', ForwardDest))
                
            ForwardMask=item.dwForwardMask
            ForwardMask=socket.inet_ntoa(struct.pack('L', ForwardMask))        
                   
            ForwardPolicy=item.dwForwardPolicy
            ForwardPolicy=socket.inet_ntoa(struct.pack('L', ForwardPolicy))          
                    
            ForwardNextHop=item.dwForwardNextHop
            #使用socket模块，转换32位打包的IPV4地址为IP地址的标准点号分隔字符串表示
            ForwardNextHop = socket.inet_ntoa(struct.pack('L', ForwardNextHop))   
            ForwardIfIndex=item.dwForwardIfIndex
            ForwardType=item.dwForwardType
            ForwardProto=item.dwForwardProto
            
            ForwardAge=item.dwForwardAge
                        
            ForwardNextHopAS=item.dwForwardNextHopAS
                 
            
            ForwardMetric1=item.dwForwardMetric1
            ForwardMetric2=item.dwForwardMetric2
            ForwardMetric3=item.dwForwardMetric3
            ForwardMetric4=item.dwForwardMetric4
            ForwardMetric5=item.dwForwardMetric5
            
            #字典IpForwardDcit赋值
            IpForwardDcit["ForwardDest"]=ForwardDest
            IpForwardDcit["ForwardMask"]=ForwardMask
            IpForwardDcit["ForwardPolicy"]=ForwardPolicy
            IpForwardDcit["ForwardNextHop"]=ForwardNextHop
            IpForwardDcit["ForwardIfIndex"]=ForwardIfIndex
            IpForwardDcit["ForwardType"]=ForwardType
            IpForwardDcit["ForwardProto"]=ForwardProto
            IpForwardDcit["ForwardAge"]=ForwardAge
            IpForwardDcit["ForwardNextHopAS"]=ForwardNextHopAS
            IpForwardDcit["ForwardMetric1"]=ForwardMetric1
            IpForwardDcit["ForwardMetric2"]=ForwardMetric2
            IpForwardDcit["ForwardMetric3"]=ForwardMetric3
            IpForwardDcit["ForwardMetric4"]=ForwardMetric4
            IpForwardDcit["ForwardMetric5"]=ForwardMetric5
            
            IpForwardTablelist.append(IpForwardDcit)
            
                       
    return IpForwardTablelist
                    
            
def CreateIpForwardEntry(dwForwardDest,dwForwardMask,dwForwardNextHop=None,dwForwardMetric=0,ForwardIfIndex=None):
    class MIB_IPFORWARDROW(ctypes.Structure):
            
            _fields_ = [('dwForwardDest', DWORD),#目标IP
                        ('dwForwardMask', DWORD),#网络掩码
                        ('dwForwardPolicy', DWORD),#多径路由策略
                        ('dwForwardNextHop', DWORD),#下一跳IP
                        ('dwForwardIfIndex', DWORD),#接口索引
                        ('dwForwardType', DWORD),#路由类型
                        ('dwForwardProto', DWORD),#路由协议
                        ('dwForwardAge', DWORD),#路由时间
                        ('dwForwardNextHopAS', DWORD),#下一跳编号
                        ('dwForwardMetric1', DWORD),#跃点数
                        ('dwForwardMetric2', DWORD),
                        ('dwForwardMetric3', DWORD),
                        ('dwForwardMetric4', DWORD),
                        ('dwForwardMetric5', DWORD)]   
            
    pRoute=MIB_IPFORWARDROW() #建立结构域
    
    IpForwardTablelist=getroute()#获得当前路由表
    
    for tmp in IpForwardTablelist:
        if  tmp["ForwardDest"]=="0.0.0.0": #查找默认路由的有关参数，除要修改的部分，其他元素使用默认路由的值
            
            pRoute.dwForwardDest = struct.unpack("I",socket.inet_aton(dwForwardDest))[0]  #转换“0.0.0.0”格式的IP地址为网络序，注意不是主机字节序
        
        
            pRoute.dwForwardMask =struct.unpack("I",socket.inet_aton(dwForwardMask))[0]
        
        

        
            #如果不给定网关，则默认为默认路由的网关
            pRoute.dwForwardNextHop = struct.unpack("I",socket.inet_aton(tmp["ForwardNextHop"]))[0]
            if dwForwardNextHop != None:
                pRoute.dwForwardNextHop = struct.unpack("I",socket.inet_aton(dwForwardNextHop))[0]
                         
            
            
            pRoute.dwForwardPolicy = struct.unpack("I",socket.inet_aton(tmp["ForwardPolicy"]))[0]
            
            #如果不给定ForwardIfIndex，则默认为默认路由的接口
            pRoute.dwForwardIfIndex=tmp["ForwardIfIndex"]
            if ForwardIfIndex != None:
                pRoute.dwForwardIfIndex=dwForwardIfIndex               
                
            
            pRoute.dwForwardType=tmp["ForwardType"]
            pRoute.dwForwardProto=tmp["ForwardProto"]
            pRoute.dwForwardAge=tmp["ForwardAge"]
            pRoute.dwForwardNextHopAS=tmp["ForwardNextHopAS"]
            
            #win7及win10无法设定小于默认路由的Metric值，这里使用了相加。若不给定，最终与默认路由的Metric相同
            pRoute.dwForwardMetric1=tmp["ForwardMetric1"]+dwForwardMetric
            
            
            
            pRoute.dwForwardMetric2=tmp["ForwardMetric2"]
            pRoute.dwForwardMetric3=tmp["ForwardMetric3"]
            pRoute.dwForwardMetric4=tmp["ForwardMetric4"]
            pRoute.dwForwardMetric5=tmp["ForwardMetric5"]   
            
            
            dwStatus=ctypes.windll.iphlpapi.CreateIpForwardEntry(ctypes.byref(pRoute)) 
            if dwStatus==5:
                print("权限不足")
            if dwStatus==5010:
                print("已存在")     
            if dwStatus==0:
                print ("添加路由成功")         
            
     
    
    return
                    
