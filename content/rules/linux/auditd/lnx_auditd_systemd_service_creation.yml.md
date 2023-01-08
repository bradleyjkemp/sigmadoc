---
title: "Systemd Service Creation"
aliases:
  - "/rule/1bac86ba-41aa-4f62-9d6b-405eac99b485"
ruleid: 1bac86ba-41aa-4f62-9d6b-405eac99b485

tags:
  - attack.persistence
  - attack.t1543.002



status: experimental





date: Thu, 3 Feb 2022 20:31:07 +0100


---

Detects a creation of systemd services which could be used by adversaries to execute malicious code.

<!--more-->


## Known false-positives

* Admin work like legit service installs.



## References

* https://attack.mitre.org/techniques/T1543/002/
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.002/T1543.002.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_systemd_service_creation.yml))
```yaml
title: Systemd Service Creation
id: 1bac86ba-41aa-4f62-9d6b-405eac99b485
status: experimental
description: Detects a creation of systemd services which could be used by adversaries to execute malicious code.
author: 'Pawel Mazur'
references:
  - https://attack.mitre.org/techniques/T1543/002/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.002/T1543.002.md
date: 2022/02/03
modified: 2022/02/06
logsource:
  product: linux
  service: auditd
detection:
  path:
    type: 'PATH'
    nametype: 'CREATE'
  name_1:
    name|startswith: 
         - '/usr/lib/systemd/system/'
         - '/etc/systemd/system/'
  name_2:
    name|contains:
         - '/.config/systemd/user/'
  condition: path and 1 of name_*
falsepositives:
  - Admin work like legit service installs.
level: medium
tags:
  - attack.persistence
  - attack.t1543.002

```
