---
title: "Raw Disk Access Using Illegitimate Tools"
aliases:
  - "/rule/db809f10-56ce-4420-8c86-d6a7d793c79c"
ruleid: db809f10-56ce-4420-8c86-d6a7d793c79c

tags:
  - attack.defense_evasion
  - attack.t1006



status: test





date: Mon, 4 Nov 2019 04:26:34 +0300


---

Raw disk access using illegitimate tools, possible defence evasion

<!--more-->


## Known false-positives

* Legitimate Administrator using tool for raw access or ongoing forensic investigation



## References

* https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/raw_access_thread/sysmon_raw_disk_access_using_illegitimate_tools.yml))
```yaml
title: Raw Disk Access Using Illegitimate Tools
id: db809f10-56ce-4420-8c86-d6a7d793c79c
description: Raw disk access using illegitimate tools, possible defence evasion
author: Teymur Kheirkhabarov, oscd.community
status: test
date: 2019/10/22
modified: 2022/02/21
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
tags:
    - attack.defense_evasion
    - attack.t1006
logsource:
    product: windows
    category: raw_access_thread
detection:
    filter_1:
        Device|contains: floppy
    filter_2:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SystemApps\'
            - 'C:\Windows\WinSxS\'
            - 'C:\Windows\servicing\'
            - 'C:\Windows\CCM\'
            - 'C:\Windows\uus\'
            - 'C:\Windows\WinSxs\'
    filter_3:
        ProcessId: 4
    filter_specific:
        Image:
            - 'C:\Windows\UUS\amd64\MoUsoCoreWorker.exe'
            - 'C:\Windows\explorer.exe'
    filter_system:
        Image:
            - 'System'
            - 'Registry'
    filter_Keybase:
        Image|endswith: '\Keybase\upd.exe'
    filter_windefender:
        Image|startswith: 'C:\ProgramData\Microsoft\Windows Defender\Platform\'
        Image|endswith: '\MsMpEng.exe'
    filter_programfiles:  # this rule causes so many FPs that we have to do this
        Image|startswith:
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    filter_appdata:
        Image|contains|all:
            - 'C:\Users\'
            - '\AppData\'
            - '\Microsoft\'
    filter_startmenu_xphost:
        Image|startswith: 'C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost'
        Image|endswith: '\StartMenuExperienceHost.exe'
    condition: not 1 of filter_*
fields:
    - ComputerName
    - Image
    - ProcessID
    - Device
falsepositives:
    - Legitimate Administrator using tool for raw access or ongoing forensic investigation
level: low  # far too many false positives


```
