---
title: "Alternate PowerShell Hosts Pipe"
aliases:
  - "/rule/58cb02d5-78ce-4692-b3e1-dce850aae41a"
ruleid: 58cb02d5-78ce-4692-b3e1-dce850aae41a

tags:
  - attack.execution
  - attack.t1059.001



status: test





date: Thu, 24 Oct 2019 15:48:38 +0200


---

Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe

<!--more-->


## Known false-positives

* Programs using PowerShell directly without invocation of a dedicated interpreter.



## References

* https://threathunterplaybook.com/notebooks/windows/02_execution/WIN-190815181010.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/pipe_created/pipe_created_alternate_powershell_hosts_pipe.yml))
```yaml
title: Alternate PowerShell Hosts Pipe
id: 58cb02d5-78ce-4692-b3e1-dce850aae41a
status: test
description: Detects alternate PowerShell hosts potentially bypassing detections looking for powershell.exe
author: Roberto Rodriguez @Cyb3rWard0g, Tim Shelton
references:
  - https://threathunterplaybook.com/notebooks/windows/02_execution/WIN-190815181010.html
date: 2019/09/12
modified: 2022/02/16
logsource:
  product: windows
  category: pipe_created
detection:
  selection:
    PipeName|startswith: '\PSHost'
  filter1:
    Image|endswith:
      - '\powershell.exe'
      - '\powershell_ise.exe'
      - '\WINDOWS\System32\sdiagnhost.exe'
      - '\WINDOWS\System32\wsmprovhost.exe'
      - '\Windows\system32\dsac.exe'
      - '\Windows\system32\wbem\wmiprvse.exe'
      - '\ForefrontActiveDirectoryConnector.exe'
      - 'c:\windows\system32\inetsrv\w3wp.exe'   # this is sad :,( but it triggers FPs on Exchange servers
  filter2:
    Image: null
  filter3: # Microsoft SQL Server\130\Tools\
    Image|contains|all:
      - ':\Program Files'
      - '\Microsoft SQL Server\'
    Image|endswith: '\Tools\Binn\SQLPS.exe'
  filter4:
    Image|startswith: 
      - 'C:\Program Files\Citrix\'
      - 'C:\Program Files\Microsoft\Exchange Server\'
  condition: selection and not 1 of filter*
fields:
  - ComputerName
  - User
  - Image
  - PipeName
falsepositives:
  - Programs using PowerShell directly without invocation of a dedicated interpreter.
level: medium
tags:
  - attack.execution
  - attack.t1059.001

```
