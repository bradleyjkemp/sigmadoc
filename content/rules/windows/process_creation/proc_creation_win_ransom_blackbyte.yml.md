---
title: "BlackByte Ransomware Patterns"
aliases:
  - "/rule/999e8307-a775-4d5f-addc-4855632335be"
ruleid: 999e8307-a775-4d5f-addc-4855632335be



status: experimental





date: Fri, 25 Feb 2022 15:24:36 +0100


---

This command line patterns found in BlackByte Ransomware operations

<!--more-->


## Known false-positives

* Unknown



## References

* https://redcanary.com/blog/blackbyte-ransomware/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_ransom_blackbyte.yml))
```yaml
title: BlackByte Ransomware Patterns
id: 999e8307-a775-4d5f-addc-4855632335be
status: experimental
description: This command line patterns found in BlackByte Ransomware operations
author: Florian Roth
references:
  - https://redcanary.com/blog/blackbyte-ransomware/
date: 2022/02/25
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    Image|startswith: 'C:\Users\Public\'
    CommandLine|contains: ' -single '
  selection2:
    CommandLine|contains:
      - 'del C:\Windows\System32\Taskmgr.exe'
      - ';Set-Service -StartupType Disabled $'
      - 'powershell -command "$x =[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('
      - ' do start wordpad.exe /p '
  condition: 1 of selection*
fields:
  - ComputerName
  - User
  - CommandLine
falsepositives:
  - Unknown
level: high

```
