---
title: "System Network Discovery - macOS"
aliases:
  - "/rule/58800443-f9fc-4d55-ae0c-98a3966dfb97"
ruleid: 58800443-f9fc-4d55-ae0c-98a3966dfb97

tags:
  - attack.discovery
  - attack.t1016



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects enumeration of local network configuration

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_system_network_discovery.yml))
```yaml
title: System Network Discovery - macOS
id: 58800443-f9fc-4d55-ae0c-98a3966dfb97
status: test
description: Detects enumeration of local network configuration
author: remotephone, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md
date: 2020/10/06
modified: 2021/11/27
logsource:
  product: macos
  category: process_creation
detection:
  selection1:
    Image:
      - '/usr/sbin/netstat'
      - '/sbin/ifconfig'
      - '/usr/sbin/ipconfig'
      - '/usr/libexec/ApplicationFirewall/socketfilterfw'
      - '/usr/sbin/networksetup'
      - '/usr/sbin/arp'
  selection2:
    Image: '/usr/bin/defaults'
    CommandLine|contains|all:
      - 'read'
      - '/Library/Preferences/com.apple.alf'
  condition: selection1 or selection2
falsepositives:
  - Legitimate administration activities
level: informational
tags:
  - attack.discovery
  - attack.t1016

```
