---
title: "Windows Update Error"
aliases:
  - "/rule/13cfeb75-9e33-4d04-b0f7-ab8faaa95a59"
ruleid: 13cfeb75-9e33-4d04-b0f7-ab8faaa95a59

tags:
  - attack.impact
  - attack.resource_development
  - attack.t1584



status: experimental





date: Sat, 4 Dec 2021 13:02:12 +0100


---

Windows Update get some error Check if need a 0-days KB

<!--more-->


## Known false-positives

* unknown




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_susp_system_update_error.yml))
```yaml
title: Windows Update Error
id: 13cfeb75-9e33-4d04-b0f7-ab8faaa95a59
status: experimental
description: Windows Update get some error Check if need a 0-days KB
author: frack113
date: 2021/12/04
logsource:
  product: windows
  service: system
  definition: Other error are in Microsoft-Windows-WindowsUpdateClient/Operational
detection:
  selection:
    Provider_Name: Microsoft-Windows-WindowsUpdateClient
    EventID: 
        - 16 # Unable to Connect: Windows is unable to connect to the automatic updates service and therefore cannot download and install updates according to the set schedule
        - 20 # Installation Failure: Windows failed to install the following update with error
        - 24 # Uninstallation Failure: Windows failed to uninstall the following update with error
        - 213 # Revert Failure: Windows failed to revert the following update with error
        - 217 # Commit Failure: Windows failed to commit the following update with error
  condition: selection
falsepositives:
  - unknown
level: low
tags:
  - attack.impact
  - attack.resource_development
  - attack.t1584

```
