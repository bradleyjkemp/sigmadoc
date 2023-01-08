---
title: "SCM Database Handle Failure"
aliases:
  - "/rule/13addce7-47b2-4ca0-a98f-1de964d1d669"
ruleid: 13addce7-47b2-4ca0-a98f-1de964d1d669

tags:
  - attack.discovery
  - attack.t1010



status: experimental





date: Thu, 24 Oct 2019 02:40:11 +0200


---

Detects non-system users failing to get a handle of the SCM database.

<!--more-->


## Known false-positives

* Unknown



## References

* https://threathunterplaybook.com/notebooks/windows/07_discovery/WIN-190826010110.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_scm_database_handle_failure.yml))
```yaml
title: SCM Database Handle Failure
id: 13addce7-47b2-4ca0-a98f-1de964d1d669
description: Detects non-system users failing to get a handle of the SCM database.
status: experimental
date: 2019/08/12
modified: 2021/11/12
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://threathunterplaybook.com/notebooks/windows/07_discovery/WIN-190826010110.html
tags:
    - attack.discovery
    - attack.t1010
logsource:
    product: windows
    service: security
detection:
    selection: 
        EventID: 4656
        ObjectType: 'SC_MANAGER OBJECT'
        ObjectName: 'ServicesActive'
        #Keywords: 'Audit Failure' <-> in the ref 'Keywords':-9214364837600034816
    filter:
        SubjectLogonId: '0x3e4'
    condition: selection and not filter
falsepositives:
    - Unknown
level: critical

```
