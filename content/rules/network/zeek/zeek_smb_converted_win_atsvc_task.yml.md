---
title: "Remote Task Creation via ATSVC Named Pipe - Zeek"
aliases:
  - "/rule/dde85b37-40cd-4a94-b00c-0b8794f956b5"
ruleid: dde85b37-40cd-4a94-b00c-0b8794f956b5

tags:
  - attack.lateral_movement
  - attack.persistence
  - car.2013-05-004
  - car.2015-04-001
  - attack.t1053.002



status: test





date: Sat, 2 May 2020 07:27:51 -0400


---

Detects remote task creation via at.exe or API interacting with ATSVC namedpipe

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/neo23x0/sigma/blob/d42e87edd741dd646db946f30964f331f92f50e6/rules/windows/builtin/win_atsvc_task.yml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/network/zeek/zeek_smb_converted_win_atsvc_task.yml))
```yaml
title: Remote Task Creation via ATSVC Named Pipe - Zeek
id: dde85b37-40cd-4a94-b00c-0b8794f956b5
status: test
description: Detects remote task creation via at.exe or API interacting with ATSVC namedpipe
author: 'Samir Bousseaden, @neu5rn'
references:
  - https://github.com/neo23x0/sigma/blob/d42e87edd741dd646db946f30964f331f92f50e6/rules/windows/builtin/win_atsvc_task.yml
date: 2020/04/03
modified: 2021/11/27
logsource:
  product: zeek
  service: smb_files
detection:
  selection:
    path: \\\*\IPC$
    name: atsvc
        #Accesses: '*WriteData*'
  condition: selection
falsepositives:
  - unknown
level: medium
tags:
  - attack.lateral_movement
  - attack.persistence
  - car.2013-05-004
  - car.2015-04-001
  - attack.t1053.002

```