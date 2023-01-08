---
title: "AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl"
aliases:
  - "/rule/074e0ded-6ced-4ebd-8b4d-53f55908119d"
ruleid: 074e0ded-6ced-4ebd-8b4d-53f55908119d

tags:
  - attack.defense_evasion
  - attack.t1216



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects execution of attacker-controlled WsmPty.xsl or WsmTxt.xsl via winrm.vbs and copied cscript.exe (can be renamed)

<!--more-->


## Known false-positives

* Unlikely



## References

* https://posts.specterops.io/application-whitelisting-bypass-and-arbitrary-unsigned-code-execution-technique-in-winrm-vbs-c8c24fb40404


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_winrm_awl_bypass.yml))
```yaml
title: AWL Bypass with Winrm.vbs and Malicious WsmPty.xsl/WsmTxt.xsl
id: 074e0ded-6ced-4ebd-8b4d-53f55908119d
description: Detects execution of attacker-controlled WsmPty.xsl or WsmTxt.xsl via winrm.vbs and copied cscript.exe (can be renamed)
status: experimental
references:
    - https://posts.specterops.io/application-whitelisting-bypass-and-arbitrary-unsigned-code-execution-technique-in-winrm-vbs-c8c24fb40404
author: Julia Fomina, oscd.community
date: 2020/10/06
modified: 2021/09/19
tags:
    - attack.defense_evasion
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    contains_format_pretty_arg:       
        CommandLine|contains:
            - 'format:pretty'
            - 'format:"pretty"'
            - 'format:"text"'
            - 'format:text'
    image_from_system_folder:
        Image|startswith: 
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    contains_winrm:
        CommandLine|contains: 'winrm'
    condition: contains_winrm and (contains_format_pretty_arg and not image_from_system_folder)
level: medium
falsepositives:
    - Unlikely

```
