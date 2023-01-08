---
title: "PowerShell Deleted Mounted Share"
aliases:
  - "/rule/66a4d409-451b-4151-94f4-a55d559c49b0"
ruleid: 66a4d409-451b-4151-94f4-a55d559c49b0

tags:
  - attack.defense_evasion
  - attack.t1070.005



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects when when a mounted share is removed. Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation

<!--more-->


## Known false-positives

* Administrators or Power users may remove their shares via cmd line



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.005/T1070.005.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_suspicious_mounted_share_deletion.yml))
```yaml
title: PowerShell Deleted Mounted Share
id: 66a4d409-451b-4151-94f4-a55d559c49b0
status: experimental
description: Detects when when a mounted share is removed. Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.005/T1070.005.md
author: 'oscd.community, @redcanary, Zach Stanford @svch0st'
date: 2020/10/08
modified: 2021/10/16
tags:
    - attack.defense_evasion
    - attack.t1070.005
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains:
          - 'Remove-SmbShare'
          - 'Remove-FileShare'
    condition: selection
falsepositives:
    - Administrators or Power users may remove their shares via cmd line
level: medium

```
