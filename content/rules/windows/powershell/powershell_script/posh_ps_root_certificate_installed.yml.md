---
title: "Root Certificate Installed"
aliases:
  - "/rule/42821614-9264-4761-acfc-5772c3286f76"
ruleid: 42821614-9264-4761-acfc-5772c3286f76

tags:
  - attack.defense_evasion
  - attack.t1553.004



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.

<!--more-->


## Known false-positives

* Help Desk or IT may need to manually add a corporate Root CA on occasion. Need to test if GPO push doesn't trigger FP



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1553.004/T1553.004.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_root_certificate_installed.yml))
```yaml
title: Root Certificate Installed
id: 42821614-9264-4761-acfc-5772c3286f76
status: experimental
description: Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1553.004/T1553.004.md
author: 'oscd.community, @redcanary, Zach Stanford @svch0st'
date: 2020/10/10
modified: 2021/12/04
tags:
    - attack.defense_evasion
    - attack.t1553.004
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection1:
        ScriptBlockText|contains|all:
          - 'Move-Item'
          - 'Cert:\LocalMachine\Root'
    selection2:
        ScriptBlockText|contains|all:
          - 'Import-Certificate'
          - 'Cert:\LocalMachine\Root'
    condition: selection1 or selection2
level: medium
falsepositives:
    - Help Desk or IT may need to manually add a corporate Root CA on occasion. Need to test if GPO push doesn't trigger FP
```
