---
title: "Powershell File and Directory Discovery"
aliases:
  - "/rule/d23f2ba5-9da0-4463-8908-8ee47f614bb9"
ruleid: d23f2ba5-9da0-4463-8908-8ee47f614bb9

tags:
  - attack.discovery
  - attack.t1083



status: experimental





date: Wed, 15 Dec 2021 19:36:16 +0100


---

Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.
Adversaries may use the information from [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) during automated discovery to shape follow-on behaviors,
including whether or not the adversary fully infects the target and/or attempts specific actions. 


<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_file_and_directory_discovery.yml))
```yaml
title: Powershell File and Directory Discovery
id: d23f2ba5-9da0-4463-8908-8ee47f614bb9
description: |
  Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.
  Adversaries may use the information from [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) during automated discovery to shape follow-on behaviors,
  including whether or not the adversary fully infects the target and/or attempts specific actions. 
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1083/T1083.md
status: experimental
author: frack113
date: 2021/12/15
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains: 
            - ls
            - get-childitem
            - gci
    recurse:
        ScriptBlockText|contains: '-recurse'
    condition: selection and recurse
falsepositives:
    - unknown
level: low
tags:
    - attack.discovery
    - attack.t1083
```