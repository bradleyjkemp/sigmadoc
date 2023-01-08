---
title: "Always Install Elevated MSI Spawned Cmd And Powershell"
aliases:
  - "/rule/1e53dd56-8d83-4eb4-a43e-b790a05510aa"
ruleid: 1e53dd56-8d83-4eb4-a43e-b790a05510aa

tags:
  - attack.privilege_escalation
  - attack.t1548.002



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

This rule looks for Windows Installer service (msiexec.exe) spawned command line and/or powershell

<!--more-->


## Known false-positives

* Penetration test



## References

* https://image.slidesharecdn.com/kheirkhabarovoffzonefinal-181117201458/95/hunting-for-privilege-escalation-in-windows-environment-50-638.jpg


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_always_install_elevated_msi_spawned_cmd_powershell.yml))
```yaml
title: Always Install Elevated MSI Spawned Cmd And Powershell
id: 1e53dd56-8d83-4eb4-a43e-b790a05510aa
status: test
description: This rule looks for Windows Installer service (msiexec.exe) spawned command line and/or powershell
author: Teymur Kheirkhabarov (idea), Mangatas Tondang (rule), oscd.community
references:
  - https://image.slidesharecdn.com/kheirkhabarovoffzonefinal-181117201458/95/hunting-for-privilege-escalation-in-windows-environment-50-638.jpg
date: 2020/10/13
modified: 2021/11/27
logsource:
  product: windows
  category: process_creation
detection:
  image:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
  parent_image:
    ParentImage|contains|all:
      - '\Windows\Installer\'
      - 'msi'
    ParentImage|endswith:
      - 'tmp'
  condition: image and parent_image
fields:
  - Image
  - ParentImage
falsepositives:
  - Penetration test
level: medium
tags:
  - attack.privilege_escalation
  - attack.t1548.002

```
