---
title: "Remote File Copy"
aliases:
  - "/rule/7a14080d-a048-4de8-ae58-604ce58a795b"
ruleid: 7a14080d-a048-4de8-ae58-604ce58a795b

tags:
  - attack.command_and_control
  - attack.lateral_movement
  - attack.t1105



status: stable





date: Thu, 18 Jun 2020 23:37:49 +0300


---

Detects the use of tools that copy files from or to remote systems

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://attack.mitre.org/techniques/T1105/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/builtin/lnx_file_copy.yml))
```yaml
title: Remote File Copy
id: 7a14080d-a048-4de8-ae58-604ce58a795b
status: stable
description: Detects the use of tools that copy files from or to remote systems
author: Ömer Günal
date: 2020/06/18
references:
    - https://attack.mitre.org/techniques/T1105/
logsource:
    product: linux
detection:
    tools:
        - 'scp '
        - 'rsync '
        - 'sftp '
    filter:
        - '@'
        - ':'
    condition: tools and filter
falsepositives:
    - Legitimate administration activities
level: low
tags:
    - attack.command_and_control
    - attack.lateral_movement
    - attack.t1105

```
