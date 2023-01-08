---
title: "Install Root Certificate"
aliases:
  - "/rule/78a80655-a51e-4669-bc6b-e9d206a462ee"
ruleid: 78a80655-a51e-4669-bc6b-e9d206a462ee

tags:
  - attack.defense_evasion
  - attack.t1553.004



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects installed new certificate

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1553.004/T1553.004.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_install_root_certificate.yml))
```yaml
title: Install Root Certificate
id: 78a80655-a51e-4669-bc6b-e9d206a462ee
status: test
description: Detects installed new certificate
author: Ömer Günal, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1553.004/T1553.004.md
date: 2020/10/05
modified: 2021/11/27
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '/update-ca-certificates'
      - '/update-ca-trust'
  condition: selection
falsepositives:
  - Legitimate administration activities
level: low
tags:
  - attack.defense_evasion
  - attack.t1553.004

```
