---
title: "High DNS Requests Rate"
aliases:
  - "/rule/51186749-7415-46be-90e5-6914865c825a"
ruleid: 51186749-7415-46be-90e5-6914865c825a

tags:
  - attack.exfiltration
  - attack.t1048.003
  - attack.command_and_control
  - attack.t1071.004



status: experimental





date: Fri, 25 Oct 2019 04:30:55 +0200


---

High DNS requests amount from host per short period of time

<!--more-->


## Known false-positives

* Legitimate high DNS requests rate to domain name which should be added to whitelist




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/net_firewall_high_dns_requests_rate.yml))
```yaml
title: High DNS Requests Rate
id: 51186749-7415-46be-90e5-6914865c825a
status: experimental
description: High DNS requests amount from host per short period of time
author: Daniil Yugoslavskiy, oscd.community
date: 2019/10/24
modified: 2021/09/21
tags:
    - attack.exfiltration
    - attack.t1048.003
    - attack.command_and_control
    - attack.t1071.004
logsource:
    category: firewall
detection:
    selection:    
        dst_port: 53
    timeframe: 1m
    condition: selection | count() by src_ip > 1000
falsepositives:
    - Legitimate high DNS requests rate to domain name which should be added to whitelist
level: medium
```