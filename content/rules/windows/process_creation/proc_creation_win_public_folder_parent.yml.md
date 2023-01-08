---
title: "Parent in Public Folder Suspicious Process"
aliases:
  - "/rule/69bd9b97-2be2-41b6-9816-fb08757a4d1a"
ruleid: 69bd9b97-2be2-41b6-9816-fb08757a4d1a



status: experimental





date: Fri, 25 Feb 2022 16:02:42 +0100


---

This rule detects suspicious processes with parent images located in the C:\Users\Public folder

<!--more-->


## Known false-positives

* Unknown



## References

* https://redcanary.com/blog/blackbyte-ransomware/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_public_folder_parent.yml))
```yaml
title: Parent in Public Folder Suspicious Process
id: 69bd9b97-2be2-41b6-9816-fb08757a4d1a
status: experimental
description: This rule detects suspicious processes with parent images located in the C:\Users\Public folder
author: Florian Roth
references:
  - https://redcanary.com/blog/blackbyte-ransomware/
date: 2022/02/25
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|startswith: 'C:\Users\Public\'
    CommandLine|contains: 
      - 'powershell'
      - 'cmd.exe /c '
      - 'cmd /c '
      - 'wscript.exe'
      - 'cscript.exe'
      - 'bitsadmin'
      - 'certutil'
      - 'mshta.exe'
  condition: selection
fields:
  - ComputerName
  - User
  - CommandLine
falsepositives:
  - Unknown
level: high

```
