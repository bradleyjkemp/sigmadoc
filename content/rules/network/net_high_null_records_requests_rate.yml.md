---
title: "High NULL Records Requests Rate"
aliases:
  - "/rule/44ae5117-9c44-40cf-9c7c-7edad385ca70"


tags:
  - attack.exfiltration
  - attack.t1048.003
  - attack.command_and_control
  - attack.t1071.004



status: test





date: Fri, 25 Oct 2019 04:30:55 +0200


---

Extremely high rate of NULL record type DNS requests from host per short period of time. Possible result of iodine tool execution

<!--more-->


## Known false-positives

* Legitimate high DNS NULL requests rate to domain name which should be added to whitelist




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/net_high_null_records_requests_rate.yml))
```yaml
title: High NULL Records Requests Rate
id: 44ae5117-9c44-40cf-9c7c-7edad385ca70
status: test
description: Extremely high rate of NULL record type DNS requests from host per short period of time. Possible result of iodine tool execution
author: Daniil Yugoslavskiy, oscd.community
date: 2019/10/24
modified: 2021/11/27
logsource:
  category: dns
detection:
  selection:
    record_type: 'NULL'
  timeframe: 1m
  condition: selection | count() by src_ip > 50
falsepositives:
  - Legitimate high DNS NULL requests rate to domain name which should be added to whitelist
level: medium
tags:
  - attack.exfiltration
  - attack.t1048.003
  - attack.command_and_control
  - attack.t1071.004

```
