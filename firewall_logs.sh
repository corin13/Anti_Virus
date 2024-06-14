#!/bin/bash

logfile="/var/log/syslog"
outputfile="./logs/firewall/$(date +%y%m%d).log"

# tail -n 0 -F로 파일의 끝을 모니터링하고, 새로운 데이터가 추가되면 실시간으로 읽습니다.
tail -n 0 -F "$logfile" | grep --line-buffered -E "BLOCK|ALLOW" | awk '
{
    date = $1
    time = $2
    action = $6
    src = ""
    dst = ""
    dpt = ""
    spt = ""
    
    for (i=1; i<=NF; i++) {
        if ($i ~ /SRC=/) { src = substr($i, 5) }
        if ($i ~ /DST=/) { dst = substr($i, 5) }
        if ($i ~ /SPT=/) { spt = substr($i, 5) }
        if ($i ~ /DPT=/) { dpt = substr($i, 5) }
    }
    
    printf("%s %s %s SRC=%s DST=%s SPT=%s DPT=%s\n", date, time, action, src, dst, spt, dpt) >> "'$outputfile'"
}'
