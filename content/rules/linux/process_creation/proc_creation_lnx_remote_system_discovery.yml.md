---
title: "Linux Remote System Discovery"
aliases:
  - "/rule/11063ec2-de63-4153-935e-b1a8b9e616f1"


tags:
  - attack.discovery
  - attack.t1018



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the enumeration of other remote systems.

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_remote_system_discovery.yml))
```yaml
title: Linux Remote System Discovery
id: 11063ec2-de63-4153-935e-b1a8b9e616f1
status: test
description: Detects the enumeration of other remote systems.
author: Alejandro Ortuno, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1018/T1018.md
date: 2020/10/22
modified: 2021/11/27
logsource:
  category: process_creation
  product: linux
detection:
  selection_1:
    Image|endswith: '/arp'
    CommandLine|contains: '-a'
  selection_2:
    Image|endswith: '/ping'
    CommandLine|contains:
      - ' 10.' #10.0.0.0/8
      - ' 192.168.' #192.168.0.0/16
      - ' 172.16.' #172.16.0.0/12
      - ' 172.17.'
      - ' 172.18.'
      - ' 172.19.'
      - ' 172.20.'
      - ' 172.21.'
      - ' 172.22.'
      - ' 172.23.'
      - ' 172.24.'
      - ' 172.25.'
      - ' 172.26.'
      - ' 172.27.'
      - ' 172.28.'
      - ' 172.29.'
      - ' 172.30.'
      - ' 172.31.'
      - ' 127.' #127.0.0.0/8
      - ' 169.254.' #169.254.0.0/16
  condition: 1 of selection*
falsepositives:
  - Legitimate administration activities
level: low
tags:
  - attack.discovery
  - attack.t1018

```