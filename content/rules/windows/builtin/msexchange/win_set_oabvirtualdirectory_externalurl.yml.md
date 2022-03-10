---
title: "Exchange Set OabVirtualDirectory ExternalUrl Property"
aliases:
  - "/rule/9db37458-4df2-46a5-95ab-307e7f29e675"


tags:
  - attack.persistence
  - attack.t1505.003



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Rule to detect an adversary setting OabVirtualDirectory External URL property to a script in Exchange Management log

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/OTR_Community/status/1371053369071132675


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/msexchange/win_set_oabvirtualdirectory_externalurl.yml))
```yaml
title: Exchange Set OabVirtualDirectory ExternalUrl Property
id: 9db37458-4df2-46a5-95ab-307e7f29e675
description: Rule to detect an adversary setting OabVirtualDirectory External URL property to a script in Exchange Management log
author: Jose Rodriguez @Cyb3rPandaH
status: experimental
date: 2021/03/15
modified: 2021/11/15
references:
    - https://twitter.com/OTR_Community/status/1371053369071132675
tags:
    - attack.persistence
    - attack.t1505.003
logsource:
    product: windows
    service: msexchange-management
detection:
    selection:
        - 'Set-OabVirtualDirectory'
        - 'ExternalUrl'
        - 'Page_Load'
        - 'script'
    condition: all of selection
falsepositives:
    - Unknown
level: high

```
