---
title: "Possible Exploitation of Exchange RCE CVE-2021-42321"
aliases:
  - "/rule/c92f1896-d1d2-43c3-92d5-7a5b35c217bb"


tags:
  - attack.lateral_movement
  - attack.t1210



status: experimental





date: Thu, 18 Nov 2021 17:27:09 +0100


---

Detects log entries that appear in exploitation attempts against MS Exchange RCE CVE-2021-42321

<!--more-->


## Known false-positives

* Unknown, please report false positives via https://github.com/SigmaHQ/sigma/issues



## References

* https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42321


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/msexchange/win_exchange_cve_2021_42321.yml))
```yaml
title: Possible Exploitation of Exchange RCE CVE-2021-42321
id: c92f1896-d1d2-43c3-92d5-7a5b35c217bb
status: experimental
description: Detects log entries that appear in exploitation attempts against MS Exchange RCE CVE-2021-42321
references:
    - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42321
author: 'Florian Roth, @testanull'
date: 2021/11/18
logsource:
    product: windows
    service: msexchange-management
detection:
    selection:
        EventID: 
            - 6
            - 8
    keywords:
        - 'Cmdlet failed. Cmdlet Get-App, '
        - 'Task Get-App throwing unhandled exception: System.InvalidCastException:'
    condition: selection and keywords
falsepositives:
    - Unknown, please report false positives via https://github.com/SigmaHQ/sigma/issues
level: critical
tags:
    - attack.lateral_movement
    - attack.t1210
```
