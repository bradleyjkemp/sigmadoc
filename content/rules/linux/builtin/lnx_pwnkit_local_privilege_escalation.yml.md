---
title: "PwnKit Local Privilege Escalation"
aliases:
  - "/rule/0506a799-698b-43b4-85a1-ac4c84c720e9"
ruleid: 0506a799-698b-43b4-85a1-ac4c84c720e9

tags:
  - attack.privilege_escalation
  - attack.t1548.001



status: experimental





date: Sat, 29 Jan 2022 10:07:54 +0100


---

Detects potential PwnKit exploitation CVE-2021-4034 in auth logs

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/wdormann/status/1486161836961579020


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/builtin/lnx_pwnkit_local_privilege_escalation.yml))
```yaml
title: PwnKit Local Privilege Escalation
id: 0506a799-698b-43b4-85a1-ac4c84c720e9
status: experimental
description: Detects potential PwnKit exploitation CVE-2021-4034 in auth logs
author: Sreeman
date: 2022/01/26
references: 
  - https://twitter.com/wdormann/status/1486161836961579020
logsource: 
  product: linux
  service: auth
detection: 
  keyword: 
    - 'pkexec'
    - 'The value for environment variable XAUTHORITY contains suscipious content'
    - '[USER=root] [TTY=/dev/pts/0]'
  condition: all of keyword
falsepositives: 
  - Unknown
level: high
tags: 
  - attack.privilege_escalation
  - attack.t1548.001
```
