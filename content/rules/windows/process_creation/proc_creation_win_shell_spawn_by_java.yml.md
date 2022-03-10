---
title: "Shells Spawn by Java"
aliases:
  - "/rule/dff1e1cc-d3fd-47c8-bfc2-aeb878a754c0"


tags:
  - attack.initial_access
  - attack.persistence
  - attack.privilege_escalation



status: experimental





date: Sat, 18 Dec 2021 06:39:14 +0100


---

Detects shell spawn from Java host process, which could a maintenance task or some kind of exploitation (e.g. log4j exploitation)

<!--more-->


## Known false-positives

* Legitimate calls to system binaries
* Company specific internal usage




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_shell_spawn_by_java.yml))
```yaml
title: Shells Spawn by Java
id: dff1e1cc-d3fd-47c8-bfc2-aeb878a754c0
description: Detects shell spawn from Java host process, which could a maintenance task or some kind of exploitation (e.g. log4j exploitation)
status: experimental
author: Andreas Hunkeler (@Karneades)
date: 2021/12/17
modified: 2022/01/12
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
            - '\cmd.exe'
    filter:
        ParentImage|contains: 'build'  # excluding CI build agents
        CommandLine|contains: 'build'  # excluding CI build agents
    condition: selection and not filter
falsepositives:
    - Legitimate calls to system binaries
    - Company specific internal usage
level: medium

```
