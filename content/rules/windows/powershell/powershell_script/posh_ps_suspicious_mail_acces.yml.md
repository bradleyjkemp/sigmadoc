---
title: "Powershell Local Email Collection"
aliases:
  - "/rule/2837e152-93c8-43d2-85ba-c3cd3c2ae614"
ruleid: 2837e152-93c8-43d2-85ba-c3cd3c2ae614

tags:
  - attack.collection
  - attack.t1114.001



status: experimental





date: Wed, 21 Jul 2021 15:27:12 +0200


---

Adversaries may target user email on local systems to collect sensitive information. Files containing email data can be acquired from a user’s local system, such as Outlook storage or cache files.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.001/T1114.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_suspicious_mail_acces.yml))
```yaml
title: Powershell Local Email Collection
id: 2837e152-93c8-43d2-85ba-c3cd3c2ae614
status: experimental
author: frack113
date: 2021/07/21
modified: 2021/10/16
description: Adversaries may target user email on local systems to collect sensitive information. Files containing email data can be acquired from a user’s local system, such as Outlook storage or cache files. 
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1114.001/T1114.001.md
tags:
    - attack.collection
    - attack.t1114.001
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains:
            - 'Get-Inbox.ps1'
            - 'Microsoft.Office.Interop.Outlook'
            - 'Microsoft.Office.Interop.Outlook.olDefaultFolders'
            - '-comobject outlook.application'
    condition: selection 
falsepositives:
    - Unknown
level: medium

```
