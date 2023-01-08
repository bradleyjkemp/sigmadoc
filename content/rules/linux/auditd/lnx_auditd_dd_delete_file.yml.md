---
title: "Overwriting the File with Dev Zero or Null"
aliases:
  - "/rule/37222991-11e9-4b6d-8bdf-60fbe48f753e"
ruleid: 37222991-11e9-4b6d-8bdf-60fbe48f753e

tags:
  - attack.impact
  - attack.t1485



status: stable





date: Wed, 23 Oct 2019 11:22:33 -0700


---

Detects overwriting (effectively wiping/deleting) of a file.

<!--more-->


## Known false-positives

* Appending null bytes to files.
* Legitimate overwrite of files.



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_dd_delete_file.yml))
```yaml
title: Overwriting the File with Dev Zero or Null
id: 37222991-11e9-4b6d-8bdf-60fbe48f753e
status: stable
description: Detects overwriting (effectively wiping/deleting) of a file.
author: Jakob Weinzettl, oscd.community
date: 2019/10/23
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'EXECVE'
        a0|contains: 'dd'   
        a1|contains:
            - 'if=/dev/null'    
            - 'if=/dev/zero'    
    condition: selection
falsepositives:
    - Appending null bytes to files.
    - Legitimate overwrite of files.
level: low

tags:
    - attack.impact
    - attack.t1485

```
