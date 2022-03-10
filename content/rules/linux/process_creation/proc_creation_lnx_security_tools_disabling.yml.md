---
title: "Disabling Security Tools"
aliases:
  - "/rule/e3a8a052-111f-4606-9aee-f28ebeb76776"


tags:
  - attack.defense_evasion
  - attack.t1562.004



status: experimental





date: Mon, 13 Jul 2020 01:32:24 +0300


---

Detects disabling security tools

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.004/T1562.004.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_security_tools_disabling.yml))
```yaml
title: Disabling Security Tools
id: e3a8a052-111f-4606-9aee-f28ebeb76776
status: experimental
description: Detects disabling security tools
author: Ömer Günal, Alejandro Ortuno, oscd.community
date: 2020/06/17
modified: 2021/09/14
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.004/T1562.004.md
tags:
    - attack.defense_evasion
    - attack.t1562.004
logsource:
    category: process_creation
    product: linux
detection:
    selection_iptables_1:
        Image|endswith: '/service'
        CommandLine|contains|all:
          - 'iptables'
          - 'stop'
    selection_iptables_2:
        Image|endswith: '/service'
        CommandLine|contains|all:
          - 'ip6tables'
          - 'stop'
    selection_iptables_3:
        Image|endswith: '/chkconfig'
        CommandLine|contains|all:
          - 'iptables'
          - 'stop'
    selection_iptables_4:
        Image|endswith: '/chkconfig'
        CommandLine|contains|all:
          - 'ip6tables'
          - 'stop'
    selection_firewall_1:
        Image|endswith: '/systemctl'
        CommandLine|contains|all:
          - 'firewalld'
          - 'stop'
    selection_firewall_2:
        Image|endswith: '/systemctl'
        CommandLine|contains|all:
          - 'firewalld'
          - 'disable'
    selection_carbonblack_1:
        Image|endswith: '/service'
        CommandLine|contains|all:
          - 'cbdaemon'
          - 'stop'
    selection_carbonblack_2:
        Image|endswith: '/chkconfig'
        CommandLine|contains|all:
          - 'cbdaemon'
          - 'off'
    selection_carbonblack_3:
        Image|endswith: '/systemctl'
        CommandLine|contains|all:
          - 'cbdaemon'
          - 'stop'
    selection_carbonblack_4:
        Image|endswith: '/systemctl'
        CommandLine|contains|all:
          - 'cbdaemon'
          - 'disable'
    selection_selinux:
        Image|endswith: '/setenforce'
        CommandLine|contains: '0'
    selection_crowdstrike_1:
        Image|endswith: '/systemctl'
        CommandLine|contains|all:
          - 'stop'
          - 'falcon-sensor'
    selection_crowdstrike_2:
        Image|endswith: '/systemctl'
        CommandLine|contains|all:
          - 'disable'
          - 'falcon-sensor'
    condition: 1 of selection*
falsepositives:
    - Legitimate administration activities
level: medium
```