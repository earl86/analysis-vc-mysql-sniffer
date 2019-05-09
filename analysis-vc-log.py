#!/usr/bin/python
#coding:utf8
# python analysis-vc-log.py ip 3306 | sort | uniq -c | sort -nr |head -n 10

import re
import sys
import os
import commands

vc_sniffer_time=10
ip=sys.argv[1]
port=sys.argv[2]
vc_cmd=""" /usr/bin/timeout %s  ./vc-mysql-sniffer -binding="%s:%s"  > /tmp/tmp_vc_mysql_%s_%s.txt """ % (vc_sniffer_time,ip,port,ip,port)
outtext = commands.getoutput(vc_cmd)
cmd=""" grep -Ev '# Time:|# User@Host|USE |SET NAMES |SET sql_mode ' /tmp/tmp_vc_mysql_%s_%s.txt |sed 's/# Query_time.*/myxxxxx/g' |awk BEGIN{RS=EOF}'{gsub(/\\n/," ");print}'|awk BEGIN{RS=EOF}'{gsub(/myxxxxx/,"\\n");print}' >/tmp/vc_mysql_%s_%s.txt""" % (ip,port,ip,port)
outtext = commands.getoutput(cmd)
file="/tmp/vc_mysql_%s_%s.txt" % (ip,port)

logFo = open(file)
for line in logFo:
    line = re.sub(r"\n","",line)
    lineMatch = re.match(r".*",line)
    if lineMatch:
        lineTmp = lineMatch.group(0)
        # remove extra space
        lineTmp = re.sub(r"\s+", " ",lineTmp)
        # replace values (value) to values (x)
        lineTmp = re.sub(r"values\s*\(.*?\)", "values (x)",lineTmp)
        # replace filed = 'value' to filed = 'x'
        lineTmp = re.sub(r"(=|>|<|>=|<=)\s*('|\").*?\2","\\1 'x'",lineTmp)
        # replace filed = value to filed = x
        lineTmp = re.sub(r"(=|>|<|>=|<=)\s*[0-9]+","\\1 x",lineTmp)
        # replace filed=filed+value to filed=filed+'x'
        lineTmp = re.sub(r"[+]\S+\s"," + 'x' ",lineTmp)
        lineTmp = re.sub(r"[']\S+[']","'x'",lineTmp)
        # replace like 'value' to like 'x'
        lineTmp = re.sub(r"like\s+('|\").*?\1","like 'x'",lineTmp)
        # replace in (value) to in (x)
        lineTmp = re.sub(r"in\s+\(.*?\)","in (x)",lineTmp)
        # replace limit x,y to limit
        lineTmp = re.sub(r" limit.*"," limit 'x';",lineTmp)
        print lineTmp

logFo.close()
