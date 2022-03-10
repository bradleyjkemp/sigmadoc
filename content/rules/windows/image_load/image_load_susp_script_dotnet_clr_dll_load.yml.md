---
title: "CLR DLL Loaded Via Scripting Applications"
aliases:
  - "/rule/4508a70e-97ef-4300-b62b-ff27992990ea"


tags:
  - attack.execution
  - attack.privilege_escalation
  - attack.t1055



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects CLR DLL being loaded by an scripting applications

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/tyranid/DotNetToJScript
* https://thewover.github.io/Introducing-Donut/
* https://blog.menasec.net/2019/07/interesting-difr-traces-of-net-clr.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/image_load/image_load_susp_script_dotnet_clr_dll_load.yml))
```yaml
title: CLR DLL Loaded Via Scripting Applications
id: 4508a70e-97ef-4300-b62b-ff27992990ea
status: test
description: Detects CLR DLL being loaded by an scripting applications
author: omkar72, oscd.community
references:
  - https://github.com/tyranid/DotNetToJScript
  - https://thewover.github.io/Introducing-Donut/
  - https://blog.menasec.net/2019/07/interesting-difr-traces-of-net-clr.html
date: 2020/10/14
modified: 2021/11/27
logsource:
  category: image_load
  product: windows
detection:
  selection:
    Image|endswith:
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
    ImageLoaded|endswith:
      - '\clr.dll'
      - '\mscoree.dll'
      - '\mscorlib.dll'
  condition: selection
falsepositives:
  - unknown
level: high
tags:
  - attack.execution
  - attack.privilege_escalation
  - attack.t1055

```
