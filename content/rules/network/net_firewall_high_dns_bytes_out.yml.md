---
title: "High DNS Bytes Out"
aliases:
  - "/rule/3b6e327d-8649-4102-993f-d25786481589"
ruleid: 3b6e327d-8649-4102-993f-d25786481589

tags:
  - attack.exfiltration
  - attack.t1048.003



status: experimental





date: Fri, 25 Oct 2019 04:30:55 +0200


---

High DNS queries bytes amount from host per short period of time

<!--more-->


## Known false-positives

* Legitimate high DNS bytes out rate to domain name which should be added to whitelist




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/net_firewall_high_dns_bytes_out.yml))
```yaml
title: High DNS Bytes Out
id: 3b6e327d-8649-4102-993f-d25786481589
status: experimental
description: High DNS queries bytes amount from host per short period of time
author: Daniil Yugoslavskiy, oscd.community
date: 2019/10/24
modified: 2021/09/21
tags:
    - attack.exfiltration
    - attack.t1048.003
logsource:
    category: firewall
detection:
    selection:
        dst_port: 53
    timeframe: 1m
    condition: selection | sum(message_size) by src_ip > 300000
falsepositives:
    - Legitimate high DNS bytes out rate to domain name which should be added to whitelist
level: medium
```
