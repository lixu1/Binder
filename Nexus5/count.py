#coding=utf-8
import MySQLdb
#import string
#import os,sys


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

  
  #获得表中有多少条数据
  aa=cur.execute("select * from sec1")
  print aa
  bb=cur.execute("select * from sec2")
  print bb

if __name__ == '__main__':
  main()
