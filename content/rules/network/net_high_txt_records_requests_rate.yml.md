---
title: "High TXT Records Requests Rate"
aliases:
  - "/rule/f0a8cedc-1d22-4453-9c44-8d9f4ebd5d35"


tags:
  - attack.exfiltration
  - attack.t1048.003
  - attack.command_and_control
  - attack.t1071.004



status: test





date: Fri, 25 Oct 2019 04:30:55 +0200


---

Extremely high rate of TXT record type DNS requests from host per short period of time. Possible result of Do-exfiltration tool execution

<!--more-->


## Known false-positives

* Legitimate high DNS TXT requests rate to domain name which should be added to whitelist




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/net_high_txt_records_requests_rate.yml))
```yaml
title: High TXT Records Requests Rate
id: f0a8cedc-1d22-4453-9c44-8d9f4ebd5d35
status: test
description: Extremely high rate of TXT record type DNS requests from host per short period of time. Possible result of Do-exfiltration tool execution
author: Daniil Yugoslavskiy, oscd.community
date: 2019/10/24
modified: 2021/11/27
logsource:
  category: dns
detection:
  selection:
    record_type: 'TXT'
  timeframe: 1m
  condition: selection | count() by src_ip > 50
falsepositives:
  - Legitimate high DNS TXT requests rate to domain name which should be added to whitelist
level: medium
tags:
  - attack.exfiltration
  - attack.t1048.003
  - attack.command_and_control
  - attack.t1071.004

```
