---
title: "Disable System Firewall"
aliases:
  - "/rule/53059bc0-1472-438b-956a-7508a94a91f0"


tags:
  - attack.t1562.004
  - attack.defense_evasion



status: experimental





date: Sat, 22 Jan 2022 15:12:24 +0100


---

Detects disabling of system firewalls which could be used by adversaries to bypass controls that limit usage of the network.

<!--more-->


## Known false-positives

* Admin activity



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.004/T1562.004.md
* https://attack.mitre.org/techniques/T1562/004/
* https://firewalld.org/documentation/man-pages/firewall-cmd.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_disable_system_firewall.yml))
```yaml
title: Disable System Firewall
id: 53059bc0-1472-438b-956a-7508a94a91f0
status: experimental
description: Detects disabling of system firewalls which could be used by adversaries to bypass controls that limit usage of the network.
author: 'Pawel Mazur'
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.004/T1562.004.md
  - https://attack.mitre.org/techniques/T1562/004/
  - https://firewalld.org/documentation/man-pages/firewall-cmd.html
date: 2022/01/22
logsource:
  product: linux
  service: auditd
detection:
  service_stop:
    type: 'SERVICE_STOP'
    unit: 
         - 'firewalld'
         - 'iptables'
         - 'ufw'
  condition: service_stop
falsepositives:
  - Admin activity
level: high
tags:
  - attack.t1562.004
  - attack.defense_evasion
```
