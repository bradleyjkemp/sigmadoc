---
title: "Remove Account From Domain Admin Group"
aliases:
  - "/rule/48a45d45-8112-416b-8a67-46e03a4b2107"
ruleid: 48a45d45-8112-416b-8a67-46e03a4b2107

tags:
  - attack.impact
  - attack.t1531



status: experimental





date: Sun, 26 Dec 2021 12:09:42 +0100


---

Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users.
Accounts may be deleted, locked, or manipulated (ex: changed credentials) to remove access to accounts. 


<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1531/T1531.md#atomic-test-3---remove-account-from-domain-admin-group


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_susp_remove_adgroupmember.yml))
```yaml
title: Remove Account From Domain Admin Group
id: 48a45d45-8112-416b-8a67-46e03a4b2107
status: experimental
author: frack113
date: 2021/12/26
description: |
  Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users.
  Accounts may be deleted, locked, or manipulated (ex: changed credentials) to remove access to accounts. 
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1531/T1531.md#atomic-test-3---remove-account-from-domain-admin-group
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains|all:
            - 'Remove-ADGroupMember'
            - '-Identity '
            - '-Members ' 
    condition: selection
falsepositives:
    - Unknown
level: medium
tags:
    - attack.impact
    - attack.t1531


```
