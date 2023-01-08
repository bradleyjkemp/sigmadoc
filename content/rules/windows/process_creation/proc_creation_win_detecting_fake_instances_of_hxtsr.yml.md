---
title: "Detecting Fake Instances Of Hxtsr.exe"
aliases:
  - "/rule/4e762605-34a8-406d-b72e-c1a089313320"
ruleid: 4e762605-34a8-406d-b72e-c1a089313320

tags:
  - attack.defense_evasion
  - attack.t1036



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

HxTsr.exe is a Microsoft compressed executable file called Microsoft Outlook Communications.HxTsr.exe is part of Outlook apps, because it resides in a hidden "WindowsApps" subfolder of "C:\Program Files". Its path includes a version number, e.g., "C:\Program Files\WindowsApps\microsoft.windowscommunicationsapps_17.7466.41167.0_x64__8wekyb3d8bbwe\HxTsr.exe". Any instances of hxtsr.exe not in this folder may be malware camouflaging itself as HxTsr.exe

<!--more-->


## Known false-positives

* unknown




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_detecting_fake_instances_of_hxtsr.yml))
```yaml
title: Detecting Fake Instances Of Hxtsr.exe
id: 4e762605-34a8-406d-b72e-c1a089313320
status: experimental
description: HxTsr.exe is a Microsoft compressed executable file called Microsoft Outlook Communications.HxTsr.exe is part of Outlook apps, because it resides in a hidden "WindowsApps" subfolder of "C:\Program Files". Its path includes a version number, e.g., "C:\Program Files\WindowsApps\microsoft.windowscommunicationsapps_17.7466.41167.0_x64__8wekyb3d8bbwe\HxTsr.exe". Any instances of hxtsr.exe not in this folder may be malware camouflaging itself as HxTsr.exe
author: Sreeman
date: 2020/04/17
modified: 2022/03/06
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image: hxtsr.exe
    filter:
        CurrentDirectory|startswith: 'C:\program files\windowsapps\microsoft.windowscommunicationsapps_'
        CurrentDirectory|endswith: '\hxtsr.exe'
    condition: selection and not filter
falsepositives:
    - unknown
level: medium
tags:
    - attack.defense_evasion
    - attack.t1036
```
