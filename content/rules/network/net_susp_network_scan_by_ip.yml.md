---
title: "Network Scans Count By Destination IP"
aliases:
  - "/rule/4601eaec-6b45-4052-ad32-2d96d26ce0d8"


tags:
  - attack.discovery
  - attack.t1046



status: test





date: Wed, 8 Feb 2017 12:41:32 +0100


---

Detects many failed connection attempts to different ports or hosts

<!--more-->


## Known false-positives

* Inventarization systems
* Vulnerability scans
* Penetration testing activity




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/net_susp_network_scan_by_ip.yml))
```yaml
title: Network Scans Count By Destination IP
id: 4601eaec-6b45-4052-ad32-2d96d26ce0d8
status: test
description: Detects many failed connection attempts to different ports or hosts
author: Thomas Patzke
date: 2017/02/19
modified: 2021/11/27
logsource:
  category: firewall
detection:
  selection:
    action: denied
  timeframe: 24h
  condition: selection | count(dst_ip) by src_ip > 10
fields:
  - src_ip
  - dst_ip
  - dst_port
falsepositives:
  - Inventarization systems
  - Vulnerability scans
  - Penetration testing activity
level: medium
tags:
  - attack.discovery
  - attack.t1046

```
