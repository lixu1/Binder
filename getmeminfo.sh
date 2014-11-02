#!/bin/bash

while true
do
  DATE=$(date +%Y/%m/%d-%H:%M:%S)
  echo $DATE >> memoryinformation.txt
  adb shell cat /proc/meminfo >> memoryinformation.txt
  echo "" >> memoryinformation.txt
  sleep 5
done

"""
adb shell cat /proc/meminfo -n|grep "^ *[1-4]" >> memoryinformation.txt
cat draft -n|grep "^ *[1-4]"  

#该方式只能得出系统整个内存的大概使用情况。
-----------------------------------------------------------------------------------
MemTotal: 所有可用RAM大小 （即物理内存减去一些预留位和内核的二进制代码大小）
MemFree: LowFree与HighFree的总和，被系统留着未使用的内存
Buffers: 用来给文件做缓冲大小
Cached: 被高速缓冲存储器（cache memory）用的内存的大小（等于 diskcache minus SwapCache ）.
SwapCached: 被高速缓冲存储器（cache memory）用的交换空间的大小已经被交换出来的内存，但仍然被存放在swapfile中。用来在需要的时候很快的被替换而不需要再次打开I/O端口。
Active: 在活跃使用中的缓冲或高速缓冲存储器页面文件的大小，除非非常必要否则不会被移作他用.
Inactive: 在不经常使用中的缓冲或高速缓冲存储器页面文件的大小，可能被用于其他途径.
HighTotal:
HighFree: 该区域不是直接映射到内核空间。内核必须使用不同的手法使用该段内存。
LowTotal:
LowFree: 低位可以达到高位内存一样的作用，而且它还能够被内核用来记录一些自己的数据结构。Among many other things, it is where everything from the Slab is allocated.  Bad things happen when you're out of lowmem.
SwapTotal: 交换空间的总大小
SwapFree: 未被使用交换空间的大小
Dirty: 等待被写回到磁盘的内存大小。
Writeback: 正在被写回到磁盘的内存大小。
AnonPages：未映射页的内存大小
Mapped: 设备和文件等映射的大小。
Slab: 内核数据结构缓存的大小，可以减少申请和释放内存带来的消耗。
SReclaimable:可收回Slab的大小
SUnreclaim：不可收回Slab的大小（SUnreclaim+SReclaimable＝Slab）
PageTables：管理内存分页页面的索引表的大小。
NFS_Unstable:不稳定页表的大小
Bounce:
CommitLimit: Based on the overcommit ratio ('vm.overcommit_ratio'),this is the total amount of  memory currently available to be allocated on the system. This limit is only adhered to if strict overcommit accounting is enabled (mode 2 in 'vm.overcommit_memory').The CommitLimit is calculated with the following formula:CommitLimit =('vm.overcommit_ratio' * Physical RAM) + Swap For example, on a system with 1G of physical RAM and 7G of swap with a vm.overcommit_ratio of 30 it would yield a CommitLimit of 7.3G. For more details, see the memory overcommit documentation in vm/overcommit-accounting.

Committed_AS: The amount of memory presently allocated on the system. The committed memory is a sum of all of the memory which has been allocated by processes, even if it has not been used by them as of yet. A process which malloc()'s 1G of memory, but only touches 300M of it will only show up as using 300M of memory even if it has the address space allocated for the entire 1G. This 1G is memory which has been committed to by the VM and can be used at any time by the allocating application. With strict overcommit enabled on the system (mode 2 in 'vm.overcommit_memory'),allocations which would exceed the CommitLimit (detailed above) will not be permitted. This is useful if one needs to guarantee that processes will not fail due to lack of memory once that memory has been successfully allocated.
VmallocTotal: 可以vmalloc虚拟内存大小
VmallocUsed: 已经被使用的虚拟内存大小。
VmallocChunk: largest contigious block of vmalloc area which is free
------------------------------------------------------------------------------
"""
