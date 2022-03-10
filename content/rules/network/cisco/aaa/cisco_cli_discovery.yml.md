---
title: "Cisco Discovery"
aliases:
  - "/rule/9705a6a1-6db6-4a16-a987-15b7151e299b"


tags:
  - attack.discovery
  - attack.t1083
  - attack.t1201
  - attack.t1057
  - attack.t1018
  - attack.t1082
  - attack.t1016
  - attack.t1049
  - attack.t1033
  - attack.t1124



status: test





date: Thu, 14 Nov 2019 20:55:28 +0100


---

Find information about network devices that is not stored in config files

<!--more-->


## Known false-positives

* Commonly used by administrators for troubleshooting




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/cisco/aaa/cisco_cli_discovery.yml))
```yaml
title: Cisco Discovery
id: 9705a6a1-6db6-4a16-a987-15b7151e299b
status: test
description: Find information about network devices that is not stored in config files
author: Austin Clark
date: 2019/08/12
modified: 2021/11/27
logsource:
  product: cisco
  service: aaa
  category: accounting
detection:
  keywords:
    - 'dir'
    - 'show processes'
    - 'show arp'
    - 'show cdp'
    - 'show version'
    - 'show ip route'
    - 'show ip interface'
    - 'show ip sockets'
    - 'show users'
    - 'show ssh'
    - 'show clock'
  condition: keywords
fields:
  - src
  - CmdSet
  - User
  - Privilege_Level
  - Remote_Address
falsepositives:
  - Commonly used by administrators for troubleshooting
level: low
tags:
  - attack.discovery
  - attack.t1083
  - attack.t1201
  - attack.t1057
  - attack.t1018
  - attack.t1082
  - attack.t1016
  - attack.t1049
  - attack.t1033
  - attack.t1124

```
