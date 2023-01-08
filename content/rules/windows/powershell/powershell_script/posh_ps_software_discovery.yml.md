---
title: "Detected Windows Software Discovery"
aliases:
  - "/rule/2650dd1a-eb2a-412d-ac36-83f06c4f2282"
ruleid: 2650dd1a-eb2a-412d-ac36-83f06c4f2282

tags:
  - attack.discovery
  - attack.t1518



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable.

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518/T1518.md
* https://github.com/harleyQu1nn/AggressorScripts


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_software_discovery.yml))
```yaml
title: Detected Windows Software Discovery
id: 2650dd1a-eb2a-412d-ac36-83f06c4f2282
description: Adversaries may attempt to enumerate software for a variety of reasons, such as figuring out what security measures are present or if the compromised system has a version of software that is vulnerable.
status: experimental
author: Nikita Nazarov, oscd.community
date: 2020/10/16
modified: 2021/11/12
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1518/T1518.md
    - https://github.com/harleyQu1nn/AggressorScripts #AVQuery.cna
tags:
    - attack.discovery
    - attack.t1518
logsource:
    product: windows
    category: ps_script
    definition: 'Script block logging must be enabled'
detection:
    selection:
        ScriptBlockText|contains|all:    # Example: Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -Autosize
          - 'get-itemProperty'
          - '\software\'
          - 'select-object'
          - 'format-table'
    condition: selection
level: medium
falsepositives:
    - Legitimate administration activities

```
