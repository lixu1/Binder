#coding=utf-8
import MySQLdb
import string

import os,sys


def main():
  html = open('index.html', 'w')
  html.write ("<html>\n<head>\n<title></title>\n<meta http-equiv=\"content-type\" content=\"text/html\" charset=\"utf-8\"><link rel=\"stylesheet\" type=\"text/css\" href=\"style.css\">\n<style>\n.view {overflow: hidden;top: 0;bottom: 0;left: 0;right: 0;}\n</style>\n</head>\n<body>\n<hr>\n<div class=\"view\">\n</div>\n<hr>\n<script language=\"javascript\" type=\"text/javascript\" src=\"script.js\">\n</script>")
  html.write ("<script language=\"javascript\">\ndocument.addEventListener('DOMContentLoaded', function() {\nif (!linuxPerfData)\nreturn;\nvar m = new tracing.TraceModel(linuxPerfData);\nvar timelineViewEl = document.querySelector('.view');\nui.decorate(timelineViewEl, tracing.TimelineView);\ntimelineViewEl.model = m;\ntimelineViewEl.tabIndex = 1;\ntimelineViewEl.timeline.focusElement = timelineViewEl;\n});\n</script>")
  html.write ("<script>\nvar linuxPerfData = \"\\\n# tracer: nop\\n\\\n#\\n\\\n# entries-in-buffer/entries-written: 42096/42096   #P:2\\n\\\n#\\n\\\n#                              _-----=> irqs-off\\n\\\n#                             / _----=> need-resched\\n\\\n#                            | / _---=> hardirq/softirq\\n\\\n#                            || / _--=> preempt-depth\\n\\\n#                            ||| /     delay\\n\\\n#           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION\\n\\\n#              | |       |   ||||       |         |\\n\\")
  #关联数据库
  conn= MySQLdb.connect(
        host='localhost',
        port = 3306,
        user='root',
        passwd='123456',
        db='test',
        )
  cur = conn.cursor()

  
  #获得表中有多少条数据
  aa=cur.execute("select * from sec2")
  #print aa
  
  #输入需要提取的范围
  num1=input('input start(ps:1):')
  num2=input('input end(ps:'+str(aa)+'):')
  
 
  temp_data = []
  #cur.fetch(aa)
  info2 = cur.fetchmany(aa)
  for ii in info2:
     float(ii[1])
     num = float(ii[1])
     if num > num1 and num < num2:
        temp_data.append(ii)

  bb=cur.execute("select * from sec1")
  #print bb
  temp_data2 = []
  info1 = cur.fetchmany(bb)
  for jj in info1:
      temp_data2.append(jj)

  #print temp_data,temp_data2


  #格式化输出结果
  # Thread_0x68-104 [000] ...1 6.269723552: tracing_mark_write: B|26337280|memblock_reserve\n\
  # Thread_0x68-104 [000] ...1 6.269856426: tracing_mark_write: E\n\
  """for j,x in enumerate(temp_data[:-1]):
    temp_data3=[]
    for i,y in enumerate(temp_data2[:-1]):
      if temp_data2[i][0] == temp_data[j][0]:
        temp_data3.append(temp_data2[i])
    #print temp_data3
    html.write ("{0:12} {1:5} .... {2:4}: sched_switch: prev_comm=a prev_pid=0 prev_prio=0 prev_state=R ==> next_comm=0x191e000(0x68) next_pid={3:4} next_prio=0\\n\\".format(temp_data[j][2]+"-104","[00"+temp_data3[0][3]+"]",temp_data3[0][1],temp_data[j][2]))
    html.write ("{0:12} {1:5} .... {2:4}: sched_switch: prev_comm=a prev_pid=0 prev_prio=0 prev_state=R ==> next_comm=a next_pid=0 next_prio=0\\n\\".format(temp_data[j][2]+"-104","[00"+temp_data3[0][3]+"]",temp_data3[0][2]))
    for k,z in enumerate(temp_data3[:-1]):
        html.write ("{0:16} {1:5} ...1 {2:10}: tracing_mark_write: B|{3:10}|{4:20}\\n\\".format(" Thread_"+temp_data[j][3]+"-104","[00"+temp_data3[k][3]+"]",temp_data3[k][1],temp_data[j][2],temp_data3[k][4]))
        html.write ("{0:16} {1:5} ...1 {2:10}: tracing_mark_write: E\\n\\".format(" Thread_"+temp_data[j][2]+"-104","[00"+temp_data3[k][3]+"]",temp_data3[k][2]))
  """
  
  for j,x in enumerate(temp_data):
    temp_data3=[]
    
    for i,y in enumerate(temp_data2):
      if temp_data2[i][0] == temp_data[j][0]:
        temp_data3.append(temp_data2[i])
        
    #print temp_data3
    
    html.write ("{0:12} {1:5} .... {2:4}: sched_switch: prev_comm=a prev_pid=0 prev_prio=0 prev_state=R ==> next_comm=0x191e000(0x68) next_pid={3:4} next_prio=0\\n\\".format(temp_data[j][2]+"-104","[00"+temp_data3[0][3]+"]",temp_data3[0][1],temp_data[j][2]))
    html.write ("{0:12} {1:5} .... {2:4}: sched_switch: prev_comm=a prev_pid=0 prev_prio=0 prev_state=R ==> next_comm=a next_pid=0 next_prio=0\\n\\".format(temp_data[j][2]+"-104","[00"+temp_data3[0][3]+"]",temp_data3[0][2]))
    for k,z in enumerate(temp_data3):
      html.write ("{0:16} {1:5} ...1 {2:10}: tracing_mark_write: B|{3:10}|{4:20}\\n\\".format(" Thread_"+temp_data[j][3]+"-104","[00"+temp_data3[k][3]+"]",temp_data3[k][1],temp_data[j][2],temp_data3[k][4]))
      html.write ("{0:16} {1:5} ...1 {2:10}: tracing_mark_write: E\\n\\".format(" Thread_"+temp_data[j][2]+"-104","[00"+temp_data3[k][3]+"]",temp_data3[k][2]))
  
  
  cur.close()
  conn.commit()
  conn.close()
  
  
      
  html.write ("\\n;\"\n</script><!-- END TRACE --></body></html>")
        
if __name__ == '__main__':
  main()
