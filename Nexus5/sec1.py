#--*-- coding:utf-8 --*--
import os,sys

import MySQLdb

"""
#处理下面格式的function_graph输出结果
argv[1]: ftrace function_graph output
#     TIME        CPU  DURATION                  FUNCTION CALLS
#      |          |     |   |                     |   |   |   |

  200.200134 |   1)   0.000 us    |              } /* _raw_spin_unlock_irqrestore */
  200.200134 |   1) + 61.035 us   |            } /* try_to_wake_up */
  200.200134 |   1) + 61.035 us   |          } /* wake_up_state */
  200.200134 |   1) + 61.035 us   |        } /* wake_futex */
  200.200134 |   1)               |        _raw_spin_unlock() {
  200.200134 |   1)   0.000 us    |          sub_preempt_count();
  200.200134 |   1)   0.000 us    |        }
  200.200134 |   1)   0.000 us    |        drop_futex_key_refs();
  200.200164 |   1) + 91.553 us   |      } /* futex_wake */
  200.200164 |   1) ! 122.070 us  |    } /* do_futex */
  200.200164 |   1) ! 122.070 us  |  } /* sys_futex */
  200.200164 |   1)               |  sys_ioctl() {
  
"""
def main():
  
  #关联数据库
  conn= MySQLdb.connect(
        host='localhost',
        port = 3306,
        user='root',
        passwd='123456',
        db='test',
        )
  cur = conn.cursor()

  #创建数据表（第一次执行创建，之后不再创建）
  cur.execute("create table if not exists sec1(num int,stime varchar(10) ,dtime varchar(10),cpu varchar(10),fname varchar(100))")
  cur.execute("create table if not exists sec2(num int,time varchar(20) ,pidname1 varchar(10),thread1 varchar(10),pidname2 varchar(10),thread2 varchar(10),way varchar(10))")

  #清空原数据表（？）
  cur.execute("delete  from sec2")
  cur.execute("delete  from sec1")
  
  with open(sys.argv[1],"r") as f:
    data = f.read()
  lines = [line for line in data.split("\n") if len(line.strip()) != 0]      
  temp_data = []
  #把绝对时间，函数运行时间与函数名分别提取
  for line in lines:
    temp_data.append([line[2:12],line[17:18],line[35:]])
  num=-1
  for i,t in enumerate(temp_data[:-1]):
    if i>50000:
      break
    if "binder_ioctl" in temp_data[i][2]:
    #针对binder_ioctl函数与其调用的函数进行分析
      temp_data3=[]
      temp_data3.append([-1," ","A","call / reply","B"])
      #call or reply from A to B
      temp_data3.append([0,temp_data[i][0]," ",temp_data[i][1],"binder_ioctl"])
      #调用层次,starttime,endtime,CPU,函数名
      depth=1;
      j=i;
      while depth>0:
        j=j+1
        #；结尾的是无子函数调用的函数
        if j==len(temp_data):
          break
        if "binder_ioctl" in temp_data[j][2]:
          break
        if "{" in temp_data[j][2]:
          name=temp_data[j][2].split("(")[0].split()[0]
          temp_data3.append([depth,temp_data[j][0]," ",temp_data[j][1],name])
          depth = depth + 1
        #{结尾的是包含子函数调用的函数的结束
        if "}" in temp_data[j][2]:
          depth = depth - 1
          flag=-1
          for k,z in enumerate(temp_data3[:-1]):
            if depth == temp_data3[k][0] and flag <0:
              flag=k
          temp_data3[flag][2]=temp_data[j][0].split()[0]
          #print str(depth)+' '+str(flag)+' '+temp_data3[flag][2]
        if "lx" in temp_data[j][2]:
        #处理添加的内核输出语句，从中读出通信的两个进程名
        #   /* lx buffer  reply from surfaceflinger:2438 to inaro.wallpaper:2290 node 0 handle -1 size 16:0 */
        #   /* lx buffer  call  from inaro.wallpaper:2290 to surfaceflinger:0 node 2741 handle 15 size 76:0 */
          fields = temp_data[j][2].split()
          way=fields[3]
          pidname1=fields[5]#.split(":")[0]
          pidname2=fields[7]#.split(":")[0]
          temp_data3[0][2]=pidname1
          temp_data3[0][4]=pidname2
          temp_data3[0][3]=way
      else:
        #把数据存入MySQL
        if "A" not in temp_data3[0][2] and "B" not in temp_data3[0][4] and " " not in temp_data3[1][2]:
          pidname1=temp_data3[0][2].split(":")[0]
          thread1=temp_data3[0][2].split(":")[1].split(" ")[0]
          pidname2=temp_data3[0][4].split(":")[0]
          thread2=temp_data3[0][4].split(":")[1]
          num+=1
          #print ("{0:12} {1:5} .... {2:4}: sched_switch: prev_comm=a prev_pid=0 prev_prio=0 prev_state=R ==> next_comm=0x191e000(0x68) next_pid={3:4} next_prio=0\\n\\".format(pidname1+"-104","[00"+temp_data3[1][3]+"]",temp_data3[1][1],pidname1))
          #print ("{0:12} {1:5} .... {2:4}: sched_switch: prev_comm=a prev_pid=0 prev_prio=0 prev_state=R ==> next_comm=a next_pid=0 next_prio=0\\n\\".format(pidname1+"-104","[00"+temp_data3[1][3]+"]",temp_data3[1][2]))
          cur.execute("insert into sec2 values('"+str(num)+"','"+temp_data[j][0]+"','"+pidname1+"','"+thread1+"','"+pidname2+"','"+thread2+"','"+way+"')")
          for k,z in enumerate(temp_data3[:-1]):
            if k > 0 and " " not in temp_data3[k][2]:
               cur.execute("insert into sec1 values('"+str(num)+"','"+temp_data3[k][1]+"','"+temp_data3[k][2]+"','"+temp_data3[k][3]+"','"+temp_data3[k][4]+"')")
            
      i=j;

  
  #关闭连接
  cur.close()
  conn.commit()
  conn.close()

     
if __name__ == '__main__':
  main()


