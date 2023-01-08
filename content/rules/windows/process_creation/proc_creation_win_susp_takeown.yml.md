---
title: "Suspicious Recursif Takeown"
aliases:
  - "/rule/554601fb-9b71-4bcc-abf4-21a611be4fde"
ruleid: 554601fb-9b71-4bcc-abf4-21a611be4fde

tags:
  - attack.defense_evasion
  - attack.t1222.001



status: experimental





date: Sun, 30 Jan 2022 12:03:32 +0100


---

Adversaries can interact with the DACLs using built-in Windows commands takeown which can grant adversaries higher permissions on specific files and folders

<!--more-->


## Known false-positives

* Scripts created by developers and admins
* Administrative activity



## References

* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/takeown
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222.001/T1222.001.md#atomic-test-1---take-ownership-using-takeown-utility


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_takeown.yml))
```yaml
title: Suspicious Recursif Takeown 
id: 554601fb-9b71-4bcc-abf4-21a611be4fde
status: experimental
description: Adversaries can interact with the DACLs using built-in Windows commands takeown which can grant adversaries higher permissions on specific files and folders
author: frack113
references:
  - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/takeown
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222.001/T1222.001.md#atomic-test-1---take-ownership-using-takeown-utility
date: 2022/01/30
logsource:
  category: process_creation
  product: windows
detection:
    selection:
        Image|endswith: '\takeown.exe'
        CommandLine|contains|all:
            - '/f '
            - '/r'
    condition: selection
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - Scripts created by developers and admins
  - Administrative activity
level: medium
tags:
  - attack.defense_evasion
  - attack.t1222.001

```
