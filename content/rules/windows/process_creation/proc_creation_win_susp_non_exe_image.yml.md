---
title: "Execution of Suspicious File Type Extension"
aliases:
  - "/rule/c09dad97-1c78-4f71-b127-7edb2b8e491a"
ruleid: c09dad97-1c78-4f71-b127-7edb2b8e491a

tags:
  - attack.defense_evasion



status: experimental





date: Thu, 9 Dec 2021 14:08:29 +0100


---

Checks whether the image specified in a process creation event doesn't refer to an .exe file (caused by process ghosting or other unorthodox methods to start a process)

<!--more-->


## Known false-positives

* unknown



## References

* https://pentestlaboratories.com/2021/12/08/process-ghosting/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_non_exe_image.yml))
```yaml
title: Execution of Suspicious File Type Extension
id: c09dad97-1c78-4f71-b127-7edb2b8e491a
status: experimental
description: Checks whether the image specified in a process creation event doesn't refer to an .exe file (caused by process ghosting or other unorthodox methods to start a process)
author: Max Altgelt
date: 2021/12/09
modified: 2022/02/16
references:
    - https://pentestlaboratories.com/2021/12/08/process-ghosting/
tags:
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    known_image_extension:
        Image|endswith:
            - '.exe'
            - '.tmp' # sadly many installers use this extension
    filter_null:
        Image: null
    filter_image: # Windows utilities without extension
        Image:
            - 'Registry'
            - 'MemCompression'
    filter_empty:
        Image:
            - '-'
            - ''
    filter_starts:
        Image|startswith: 'C:\Windows\Installer\MSI'
    filter_pstarts:
        ParentImage|startswith:
            - 'C:\ProgramData\Avira\'
            - 'C:\Windows\System32\DriverStore\FileRepository\'
    filter_screensaver:
        Image|endswith: '.scr'
    filter_nvidia:
        Image|contains: 'NVIDIA\NvBackend\'
        Image|endswith: '.dat'
    filter_com:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
        Image|endswith: '.com'
    filter_winscp:
        Image|endswith: '\WinSCP.com'
    filter_vscode:
        Image|contains|all:
            - 'C:\Users\'
            - '\AppData\'
            - '.tmp'
            - 'CodeSetup'
    filter_libreoffice:
        Image|endswith: '\program\soffice.bin'
    filter_emc_networker:
        Image:
            - 'C:\Program Files\EMC NetWorker\Management\GST\apache\cgi-bin\update_jnlp.cgi'
            - 'C:\Program Files (x86)\EMC NetWorker\Management\GST\apache\cgi-bin\update_jnlp.cgi'
    filter_winpakpro:
        Image|startswith:
            - 'C:\Program Files (x86)\WINPAKPRO\'
            - 'C:\Program Files\WINPAKPRO\'
        Image|endswith: '.ngn'
    filter_myq_server:
        Image:
            - 'C:\Program Files (x86)\MyQ\Server\pcltool.dll'
            - 'C:\Program Files\MyQ\Server\pcltool.dll'
    filter_visualstudio:
        Image|startswith:
            - 'C:\Program Files\Microsoft Visual Studio\'
            - 'C:\Program Files (x86)\Microsoft Visual Studio'
        Image|endswith: '.com'
    filter_msi_rollbackfiles:
        Image|startswith: 'C:\Config.Msi\'
        Image|endswith:
            - '.rbf'
            - '.rbs'
    condition: not known_image_extension and not 1 of filter*
falsepositives:
    - unknown
level: high


```
