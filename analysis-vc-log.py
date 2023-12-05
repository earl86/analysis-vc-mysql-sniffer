#!/usr/bin/python
#coding:utf8
# python analysis-vc-log.py -i mysqlip -p 3306 -t 60 -a my
# python analysis-vc-log.py -i mysqlip -p 3306 -t 60 -a pt
import re
import subprocess
import argparse
import time

logtime = time.strftime("%Y-%m-%d-%H%M%S", time.localtime())

parser = argparse.ArgumentParser(description='vc-mysql-sniffer help')
parser.add_argument('-i','--mysql_ip', dest='mysql_ip', action='store', help='mysql_ip list of comma', default=None)
parser.add_argument('-p','--mysql_port', dest='mysql_port', action='store', help='mysql_port', required=True, default=None)
parser.add_argument('-t', '--vc_sniffer_run_time', dest='vc_sniffer_run_time', action='store', help='vc-mysql-sniffer run time', default='60')
parser.add_argument('-a','--analyze_type', dest='analyze_type', action='store', help='analyze_type: pt or my', default='pt')
args = parser.parse_args()

MYSQL_IP = args.mysql_ip
MYSQL_PORT = args.mysql_port
VC_SNIFFER_RUN_TIME = args.vc_sniffer_run_time
ANALYZE_TYPE = args.analyze_type

if MYSQL_IP:
    vc_binding = "[%s]:%s" % (MYSQL_IP, MYSQL_PORT)
    s_ip_port = "%s_%s" % (MYSQL_IP, MYSQL_PORT)
else:
    vc_binding = "[::]:%s" % (MYSQL_PORT)
    s_ip_port = "0.0.0.0_%s" % (MYSQL_PORT)


vc_cmd=""" /usr/bin/timeout %s  ./vc-mysql-sniffer -binding="%s" -output="/tmp/tmp_vc_mysql_%s-%s.txt" """ % (VC_SNIFFER_RUN_TIME, vc_binding, s_ip_port, logtime)
ret = subprocess.call(vc_cmd, shell=True)

if ANALYZE_TYPE == "pt":
    cmd=""" /usr/bin/pt-query-digest /tmp/tmp_vc_mysql_%s-%s.txt > /tmp/pt_result_%s-%s.log """ % (s_ip_port, logtime, s_ip_port, logtime)
    ret = subprocess.call(cmd, shell=True)
    print("less /tmp/pt_result_%s-%s.log" % (s_ip_port, logtime))
elif ANALYZE_TYPE == "my":
    cmd=""" grep -i -Ev '# Time:|# User@Host|USE |SET NAMES |SET sql_mode |# Query_time' /tmp/tmp_vc_mysql_%s-%s.txt |grep -i -E '^insert|^delete|^update|^select|^replace' >/tmp/vc_mysql_%s-%s.txt""" % (s_ip_port, logtime, s_ip_port, logtime)
    ret = subprocess.call(cmd, shell=True)

    file = "/tmp/vc_mysql_%s-%s.txt" % (s_ip_port, logtime)
    myfile = "/tmp/my_result_%s-%s.log" % (s_ip_port, logtime)
    myf = open(myfile, "a")

    logFo = open(file)
    for line in logFo:
        line =line.replace("\n", "").replace("\r", "")
        line = re.sub(r"\n","",line)
        lineMatch = re.match(r".*",line)
        if lineMatch:
            lineTmp = lineMatch.group(0)
            # remove extra space
            lineTmp = re.sub(r"\s+", " ",lineTmp)
            # replace values (value) to values (x)
            lineTmp = re.sub(r"values\s*\(*.*([^;])", "values (x)", lineTmp)
            # replace VALUES (x,x,x) to VALUES (x)
            lineTmp = re.sub(r"VALUES\s*\(*.*([^;])", "VALUES (x)",lineTmp)
            # replace filed = 'value' to filed = 'x'
            #lineTmp = re.sub(r"(=|>|<|>=|<=)\s*('|\").*?\2","\\1 'x'",lineTmp)
            # replace filed = value to filed = x
            lineTmp = re.sub(r"(=|>|<|>=|<=)\s*\S+([^;])","\\1 x ",lineTmp)
            # replace filed=filed+value to filed=filed+'x'
            lineTmp = re.sub(r"[+]\S+\s"," + 'x' ",lineTmp)
            lineTmp = re.sub(r"[']\S+[']","'x'",lineTmp)
            # replace like 'value' to like 'x'
            lineTmp = re.sub(r"like\s+('|\").*?\1","like 'x'",lineTmp)
            # replace in (value) to in (x)
            lineTmp = re.sub(r"in\s+\(.*?\)","in (x)",lineTmp)
            # replace filed = value to filed = 'x'
            lineTmp = re.sub(r"(=|>|<|>=|<=)\s*.*?\,","\\1 'x',",lineTmp)
            # replace limit x,y to limit
            lineTmp = re.sub(r" limit.*"," limit 'x';",lineTmp)
            #print(lineTmp)
            myf.write(lineTmp+'\r\n')
    logFo.close()
    myf.close()
    print("grep xxxxx %s | sort | uniq -c | sort -nr |head -n 10" % (myfile))
    print("less %s | sort | uniq -c | sort -nr |head -n 10" % (myfile))

