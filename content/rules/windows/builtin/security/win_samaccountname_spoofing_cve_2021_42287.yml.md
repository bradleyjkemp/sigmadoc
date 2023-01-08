---
title: "Suspicious Computer Account Name Change CVE-2021-42287"
aliases:
  - "/rule/45eb2ae2-9aa2-4c3a-99a5-6e5077655466"
ruleid: 45eb2ae2-9aa2-4c3a-99a5-6e5077655466



status: experimental





date: Wed, 22 Dec 2021 08:50:05 +0100


---

Detects the renaming of an existing computer account to a account name that doesn't contain a $ symbol as seen in attacks against CVE-2021-42287

<!--more-->


## Known false-positives

* Unknown



## References

* https://medium.com/@mvelazco/hunting-for-samaccountname-spoofing-cve-2021-42287-and-domain-controller-impersonation-f704513c8a45


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_samaccountname_spoofing_cve_2021_42287.yml))
```yaml
title: Suspicious Computer Account Name Change CVE-2021-42287
id: 45eb2ae2-9aa2-4c3a-99a5-6e5077655466
status: experimental
description: Detects the renaming of an existing computer account to a account name that doesn't contain a $ symbol as seen in attacks against CVE-2021-42287
references:
    - https://medium.com/@mvelazco/hunting-for-samaccountname-spoofing-cve-2021-42287-and-domain-controller-impersonation-f704513c8a45
author: Florian Roth
date: 2021/12/22
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4781 # rename user
        OldTargetUserName|contains: '$'
    filter:
        NewTargetUserName|contains: '$'
    condition: selection and not filter
fields:
    - EventID
    - SubjectUserName
falsepositives:
    - Unknown
level: critical

```
