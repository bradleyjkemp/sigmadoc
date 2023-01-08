---
title: "High DNS Bytes Out"
aliases:
  - "/rule/0f6c1bf5-70a5-4963-aef9-aab1eefb50bd"
ruleid: 0f6c1bf5-70a5-4963-aef9-aab1eefb50bd

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




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/net_high_dns_bytes_out.yml))
```yaml
title: High DNS Bytes Out
id: 0f6c1bf5-70a5-4963-aef9-aab1eefb50bd
status: experimental
description: High DNS queries bytes amount from host per short period of time
author: Daniil Yugoslavskiy, oscd.community
date: 2019/10/24
modified: 2021/09/21
tags:
    - attack.exfiltration
    - attack.t1048.003
logsource:
    category: dns
detection:
    selection:
        query: '*'
    timeframe: 1m
    condition: selection | sum(question_length) by src_ip > 300000
falsepositives:
    - Legitimate high DNS bytes out rate to domain name which should be added to whitelist
level: medium
```
