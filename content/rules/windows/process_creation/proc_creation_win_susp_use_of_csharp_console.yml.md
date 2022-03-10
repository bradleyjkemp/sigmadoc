---
title: "Suspicious Use of CSharp Interactive Console"
aliases:
  - "/rule/a9e416a8-e613-4f8b-88b8-a7d1d1af2f61"


tags:
  - attack.execution
  - attack.t1127



status: test





date: Sun, 8 Mar 2020 19:06:10 +0900


---

Detects the execution of CSharp interactive console by PowerShell

<!--more-->


## Known false-positives

* Possible depending on environment. Pair with other factors such as net connections, command-line args, etc.



## References

* https://redcanary.com/blog/detecting-attacks-leveraging-the-net-framework/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_use_of_csharp_console.yml))
```yaml
title: Suspicious Use of CSharp Interactive Console
id: a9e416a8-e613-4f8b-88b8-a7d1d1af2f61
status: test
description: Detects the execution of CSharp interactive console by PowerShell
author: Michael R. (@nahamike01)
references:
  - https://redcanary.com/blog/detecting-attacks-leveraging-the-net-framework/
date: 2020/03/08
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\csi.exe'
    ParentImage|endswith: '\powershell.exe'
    OriginalFileName: 'csi.exe'
  condition: selection
falsepositives:
  - Possible depending on environment. Pair with other factors such as net connections, command-line args, etc.
level: high
tags:
  - attack.execution
  - attack.t1127

```