---
title: "Suspicious Shells Spawn by Java"
aliases:
  - "/rule/0d34ed8b-1c12-4ff2-828c-16fc860b766d"


tags:
  - attack.initial_access
  - attack.persistence
  - attack.privilege_escalation



status: experimental





date: Sat, 18 Dec 2021 06:39:14 +0100


---

Detects suspicious shell spawn from Java host process (e.g. log4j exploitation)

<!--more-->


## Known false-positives

* Legitimate calls to system binaries
* Company specific internal usage




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_shell_spawn_by_java.yml))
```yaml
title: Suspicious Shells Spawn by Java
id: 0d34ed8b-1c12-4ff2-828c-16fc860b766d
description: Detects suspicious shell spawn from Java host process (e.g. log4j exploitation)
status: experimental
author: Andreas Hunkeler (@Karneades), Florian Roth
date: 2021/12/17
modified: 2021/12/22
tags:
    - attack.initial_access
    - attack.persistence
    - attack.privilege_escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\java.exe'
        Image|endswith:
            - '\sh.exe'
            - '\bash.exe'
            - '\powershell.exe'
            - '\schtasks.exe'
            - '\certutil.exe'
            - '\whoami.exe'
            - '\bitsadmin.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\scrcons.exe'
            - '\regsvr32.exe'
            - '\hh.exe'
            - '\wmic.exe'        # https://app.any.run/tasks/c903e9c8-0350-440c-8688-3881b556b8e0/
            - '\mshta.exe'
            - '\rundll32.exe'
            - '\forfiles.exe'
            - '\scriptrunner.exe'
            - '\mftrace.exe'
            - '\AppVLP.exe'
            - '\curl.exe'
    condition: selection
falsepositives:
    - Legitimate calls to system binaries
    - Company specific internal usage
level: high

```
