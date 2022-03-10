---
title: "Dotnet.exe Exec Dll and Execute Unsigned Code LOLBIN"
aliases:
  - "/rule/d80d5c81-04ba-45b4-84e4-92eba40e0ad3"


tags:
  - attack.execution
  - attack.t1218



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

dotnet.exe will execute any DLL and execute unsigned code

<!--more-->


## Known false-positives

* System administrator Usage
* Penetration test



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Dotnet.yml
* https://twitter.com/_felamos/status/1204705548668555264
* https://bohops.com/2019/08/19/dotnet-core-a-vector-for-awl-bypass-defense-evasion/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_dotnet.yml))
```yaml
title: Dotnet.exe Exec Dll and Execute Unsigned Code LOLBIN
id: d80d5c81-04ba-45b4-84e4-92eba40e0ad3
status: test
description: dotnet.exe will execute any DLL and execute unsigned code
author: Beyu Denis, oscd.community
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Dotnet.yml
  - https://twitter.com/_felamos/status/1204705548668555264
  - https://bohops.com/2019/08/19/dotnet-core-a-vector-for-awl-bypass-defense-evasion/
date: 2020/10/18
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|endswith:
      - '.dll'
      - '.csproj'
    Image|endswith:
      - '\dotnet.exe'
  condition: selection
fields:
  - ComputerName
  - User
  - CommandLine
  - ParentCommandLine
falsepositives:
  - System administrator Usage
  - Penetration test
level: medium
tags:
  - attack.execution
  - attack.t1218

```
