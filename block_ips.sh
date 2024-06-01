sudo fuser -v /run/xtables.lock

while IFS= read -r ip; do
    # 빈 라인 또는 주석(#)으로 시작하는 라인은 건너뜀
    [[ -z "$ip" || "$ip" == \#* ]] && continue

    echo "Blocking IP : $ip"

    # SSH 포트를 예외로 설정하여 IP를 차단
    sudo iptables -A INPUT -p tcp --dport 22 -s "$ip" -j ACCEPT
    sudo iptables -A OUTPUT -p tcp --sport 22 -d "$ip" -j ACCEPT

    # 나머지 트래픽을 차단
    sudo iptables -A INPUT -s "$ip" -j DROP
    sudo iptables -A OUTPUT -d "$ip" -j DROP

done < "malicious_ips.log"