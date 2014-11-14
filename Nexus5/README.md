Galaxy Nexus 5 使用Ftrace 与 Systrace 绘图
====================
系统配置：
--------------------
		Android 系统版本4.4 与4.4.3
		内核版本3.4.0
		git clone https://android.googlesource.com/kernel/msm.git
		分支：remotes/origin/android-msm-hammerhead-3.4-kitkat-mr2
		(zImage-dtb，boot.img为编译过的，可直接使用）

步骤：
--------------------
	1. 替换修改过的binder.c
	2. 编译源码：
		$make hammerhead_defconfig
		$make menuconfig

	3. 替换内核：
		下载相关工具并参考：https://github.com/xyongcn/cg-ftracer.git
		$cp arch/arm/boot/zImage-dtb ~/cg-ftracer/
		$cd ~/cg-ftracer/
		$./mkbootimg --base 0 --pagesize 2048 --kernel_offset 0x00008000 --ramdisk_offset 0x02900000 --second_offset 0x00f00000 --tags_offset 0x02700000 --cmdline 'console=ttyHSL0,115200,n8 androidboot.hardware=hammerhead user_debug=31 maxcpus=2 msm_watchdog_v2.enable=1' --kernel ./zImage-dtb --ramdisk ./ramdisk.cpio.gz -o ./boot.img
		$adb reboot bootloader
		$fastboot flash boot boot.img
		$fastboot reboot
	4. 开启Ftrace 追踪数据
		使用tracefunctiongraph.sh
		将追踪后的数据用sec1.py 处理，将相关数据导入数据库 
		$python sec1.py binder_ftrace_19700102000740.txt
		需要先安装MYSQL，并添加数据库
		给python 安装mysql驱动
		$sudo apt-get install python-mysqldb
		修改root密码：(或者修改脚本内的密码)
		$mysqladmin -u root -p password 123456
		登录：
		$mysql -u root -p
		建立新的数据库：
		mysql> drop database test;
		mysql> create database test;
	5. 表结构如下：
		mysql> show databases;
		mysql> use test;
		mysql> show tables;
		+----------------+
		| Tables_in_test |
		+----------------+
		| sec1           |
		| sec2           |
		+----------------+

		mysql> describe sec1;
		+-------+--------------+------+-----+---------+-------+
		| Field | Type         | Null | Key | Default | Extra |
		+-------+--------------+------+-----+---------+-------+
		| num   | int(11)      | YES  |     | NULL    |       |
		| stime | varchar(20)  | YES  |     | NULL    |       |
		| dtime | varchar(10)  | YES  |     | NULL    |       |
		| cpu   | varchar(10)  | YES  |     | NULL    |       |
		| fname | varchar(100) | YES  |     | NULL    |       |
		+-------+--------------+------+-----+---------+-------+
		5 rows in set (0.00 sec)

		mysql> describe sec2;

		+----------+-------------+------+-----+---------+-------+
		| Field    | Type        | Null | Key | Default | Extra |
		+----------+-------------+------+-----+---------+-------+
		| num      | int(11)     | YES  |     | NULL    |       |
		| time     | varchar(20) | YES  |     | NULL    |       |
		| pidname1 | varchar(10) | YES  |     | NULL    |       |
		| thread1  | varchar(10) | YES  |     | NULL    |       |
		| pidname2 | varchar(10) | YES  |     | NULL    |       |
		| thread2  | varchar(10) | YES  |     | NULL    |       |
		| way      | varchar(10) | YES  |     | NULL    |       |
		+----------+-------------+------+-----+---------+-------+
		7 rows in set (0.00 sec)

		mysql> select * from sec1;
		mysql> select * from sec2;
	6. 生成图形：
		$python count.py  输出两个表的数量
		$python sec2.py 0 100 > index.html 根据输入的条数范围，生成相应的图形


服务器端运行：
============
	1. 把改过的内核复制到n5服务器上
		$scp -P 1411 /home/lx/Binder/Nexus5/boot.img lxu@166.111.68.45:~/
		$ssh lxu@166.111.68.45 -p 1411
		$scp boot.img lxu@192.168.1.40:~/
		$ssh 192.168.1.40
	2. 输入改过的内核
		$sudo -i
		$/home/wjbang/adt-bundle-linux-x86-20131030/sdk/platform-tools/adb reboot-bootloader
		$/home/lxu/adt-bundle-linux-x86-20131030/sdk/platform-tools/fastboot  flash boot /home/lxu/boot.img
		$/home/lxu/adt-bundle-linux-x86-20131030/sdk/platform-tools/fastboot  reboot
		$/home/lxu/adt-bundle-linux-x86-20131030/sdk/platform-tools/fastboot  devices
		$/home/lxu/adt-bundle-linux-x86-20131030/sdk/platform-tools/adb shell
		$/home/lxu/adt-bundle-linux-x86-20131030/sdk/platform-tools/adb devices
	3. 输出Ftrace
		使用服务器上的脚本，或使用tracefunctiongraph.sh
		$cd /home/wjbang/
		$sh test.sh
	4. 使用一些脚本启动手机上的应用，使追踪数据更快
		打电话：
		#am start -a android.intent.action.CALL -d tel:10086
		启动 google map 直接定位到北京:
		#am start -a android.intent.action.VIEW geo:0,0?q=beijing
		Music 和 Video（音乐和视频）的启动方法为：
		# am start -n com.android.music/com.android.music.MusicBrowserActivity
		# am start -n com.android.music/com.android.music.VideoBrowserActivity
		# am start -n com.android.music/com.android.music.MediaPlaybackActivity
		calendar（日历）的启动方法为：
		# am start -n com.android.calendar/com.android.calendar.LaunchActivity
		计算器（calculator）的启动方法为：
		# am start -n com.android.calculator2/com.android.calculator2.Calculator
	5. 导出数据到本地
		$/home/lxu/adt-bundle-linux-x86-20131030/sdk/platform-tools/adb pull /sdcard/binder_ftrace_19700924180253.txt
		$exit
		$scp lxu@192.168.1.40:/home/lxu/binder_ftrace_19700924180253.txt ~/
		$exit
		$scp -P 1411 lxu@166.111.68.45:~/binder_ftrace_19700924180253.txt ~/
