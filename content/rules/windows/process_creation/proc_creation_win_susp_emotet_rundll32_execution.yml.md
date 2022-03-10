---
title: "Emotet RunDLL32 Process Creation"
aliases:
  - "/rule/54e57ce3-0672-46eb-a402-2c0948d5e3e9"


tags:
  - attack.defense_evasion
  - attack.t1218.011



status: experimental





date: Fri, 25 Dec 2020 14:09:40 +0700


---

Detecting Emotet DLL loading by looking for rundll32.exe processes with command lines ending in ,RunDLL or ,Control_RunDLL

<!--more-->


## Known false-positives

* Unknown



## References

* https://paste.cryptolaemus.com/emotet/2020/12/22/emotet-malware-IoCs_12-22-20.html
* https://cyber.wtf/2021/11/15/guess-whos-back/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_emotet_rundll32_execution.yml))
```yaml
title: Emotet RunDLL32 Process Creation
id: 54e57ce3-0672-46eb-a402-2c0948d5e3e9
description: Detecting Emotet DLL loading by looking for rundll32.exe processes with command lines ending in ,RunDLL or ,Control_RunDLL
author: FPT.EagleEye 
status: experimental
date: 2020/12/25
modified: 2021/11/17
references:
    - https://paste.cryptolaemus.com/emotet/2020/12/22/emotet-malware-IoCs_12-22-20.html
    - https://cyber.wtf/2021/11/15/guess-whos-back/
tags:
    - attack.defense_evasion
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\rundll32.exe'
        CommandLine|endswith:
            - ',RunDLL'
            - ',Control_RunDLL'
            # - ',#1'  too generic - function load by ordinal is not Emotet specific
    filter_legitimate_dll:
        CommandLine|endswith:
          - '.dll,Control_RunDLL'
          - '.dll",Control_RunDLL'
          - '.dll'',Control_RunDLL'
    filter_ide:
        ParentImage|endswith:
            - '\tracker.exe' #When Visual Studio compile NodeJS program, it might use MSBuild to create tracker.exe and then, the tracker.exe fork rundll32.exe
    condition: selection and not filter_ide and not filter_legitimate_dll
falsepositives:
    - Unknown
level: critical

```
