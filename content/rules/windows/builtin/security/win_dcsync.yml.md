---
title: "Mimikatz DC Sync"
aliases:
  - "/rule/611eab06-a145-4dfa-a295-3ccc5c20f59a"


tags:
  - attack.credential_access
  - attack.s0002
  - attack.t1003.006



status: experimental





date: Sun, 3 Jun 2018 16:00:57 +0200


---

Detects Mimikatz DC sync security events

<!--more-->


## Known false-positives

* Valid DC Sync that is not covered by the filters; please report
* Local Domain Admin account used for Azure AD Connect



## References

* https://twitter.com/gentilkiwi/status/1003236624925413376
* https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_dcsync.yml))
```yaml
title: Mimikatz DC Sync
id: 611eab06-a145-4dfa-a295-3ccc5c20f59a
description: Detects Mimikatz DC sync security events
status: experimental
date: 2018/06/03
modified: 2021/08/09
author: Benjamin Delpy, Florian Roth, Scott Dermott
references:
    - https://twitter.com/gentilkiwi/status/1003236624925413376
    - https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2
tags:
    - attack.credential_access
    - attack.s0002
    - attack.t1003.006
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties|contains:
            - 'Replicating Directory Changes All'
            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    filter1:
        SubjectDomainName: 'Window Manager'
    filter2:
        SubjectUserName|startswith:
            - 'NT AUTHORITY'
            - 'MSOL_'
    filter3:
        SubjectUserName|endswith: '$'
    condition: selection and not 1 of filter*
falsepositives:
    - Valid DC Sync that is not covered by the filters; please report
    - Local Domain Admin account used for Azure AD Connect
level: high


```
