#!/bin/bash

logfile="/var/log/syslog"
outputfile="./logs/firewall/$(date +%y%m%d).log"

tail -n 0 -F "$logfile" | grep --line-buffered -E "BLOCK|ALLOW" | tee -a "$outputfile"
