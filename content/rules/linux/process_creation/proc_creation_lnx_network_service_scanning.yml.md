---
title: "Linux Network Service Scanning"
aliases:
  - "/rule/3e102cd9-a70d-4a7a-9508-403963092f31"
ruleid: 3e102cd9-a70d-4a7a-9508-403963092f31

tags:
  - attack.discovery
  - attack.t1046



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects enumeration of local or remote network services.

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_network_service_scanning.yml))
```yaml
title: Linux Network Service Scanning
id: 3e102cd9-a70d-4a7a-9508-403963092f31
status: experimental
description: Detects enumeration of local or remote network services.
author: Alejandro Ortuno, oscd.community
date: 2020/10/21
modified: 2021/09/14
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md
tags:
  - attack.discovery
  - attack.t1046
logsource:
  category: process_creation
  product: linux
  definition: 'Detect netcat and filter our listening mode'
detection:
  netcat:
    Image|endswith:
      - '/nc'
      - '/netcat'
  network_scanning_tools:
    Image|endswith:
      - '/telnet' # could be wget, curl, ssh, many things. basically everything that is able to do network connection. consider fine tuning
      - '/nmap'
  netcat_listen_flag:
    CommandLine|contains: 'l'
  condition: (netcat and not netcat_listen_flag) or network_scanning_tools
falsepositives:
  - Legitimate administration activities
level: low
```