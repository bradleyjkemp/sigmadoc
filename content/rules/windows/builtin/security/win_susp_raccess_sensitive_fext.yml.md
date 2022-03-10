---
title: "Suspicious Access to Sensitive File Extensions"
aliases:
  - "/rule/91c945bc-2ad1-4799-a591-4d00198a1215"


tags:
  - attack.collection
  - attack.t1039



status: experimental





date: Wed, 3 Apr 2019 13:22:42 +0200


---

Detects known sensitive file extensions accessed on a network share

<!--more-->


## Known false-positives

* Help Desk operator doing backup or re-imaging end user machine or pentest or backup software
* Users working with these data types or exchanging message files




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_susp_raccess_sensitive_fext.yml))
```yaml
title: Suspicious Access to Sensitive File Extensions
id: 91c945bc-2ad1-4799-a591-4d00198a1215
description: Detects known sensitive file extensions accessed on a network share
status: experimental
author: Samir Bousseaden
date: 2019/04/03
modified: 2021/08/09
tags:
    - attack.collection
    - attack.t1039
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5145
        RelativeTargetName|endswith:
            - '.pst'
            - '.ost'
            - '.msg'
            - '.nst'
            - '.oab'
            - '.edb'
            - '.nsf'
            - '.bak'
            - '.dmp'
            - '.kirbi'
            - '\groups.xml'
            - '.rdp'
    condition: selection
fields:
    - ComputerName
    - SubjectDomainName
    - SubjectUserName
    - RelativeTargetName
falsepositives:
    - Help Desk operator doing backup or re-imaging end user machine or pentest or backup software
    - Users working with these data types or exchanging message files
level: medium

```