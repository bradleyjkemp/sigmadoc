---
title: "Suspicious Word Cab File Write CVE-2021-40444"
aliases:
  - "/rule/60c0a111-787a-4e8a-9262-ee485f3ef9d5"


tags:
  - attack.resource_development
  - attack.t1587



status: experimental





date: Fri, 10 Sep 2021 18:13:09 +0200


---

Detects file creation patterns noticeable during the exploitation of CVE-2021-40444

<!--more-->


## Known false-positives

* unknown



## References

* https://twitter.com/RonnyTNL/status/1436334640617373699?s=20
* https://twitter.com/vanitasnk/status/1437329511142420483?s=21


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_winword_cve_2021_40444.yml))
```yaml
title: Suspicious Word Cab File Write CVE-2021-40444
id: 60c0a111-787a-4e8a-9262-ee485f3ef9d5
description: Detects file creation patterns noticeable during the exploitation of CVE-2021-40444
status: experimental
references:
    - https://twitter.com/RonnyTNL/status/1436334640617373699?s=20
    - https://twitter.com/vanitasnk/status/1437329511142420483?s=21
author: Florian Roth, Sittikorn S
date: 2021/09/10
modified: 2021/09/13
logsource:
    product: windows
    category: file_event
detection:
    selection:
        Image: '\winword.exe'
        TargetFilename|endswith: '.cab'
        TargetFilename|contains: '\Windows\INetCache'
    selection_inf:
        Image: '\winword.exe'
        TargetFilename|contains|all:
        - '\AppData\Local\Temp\'
        - '.inf'
    condition: selection or selection_inf
fields:
    - TargetFilename
falsepositives:
    - unknown
level: critical
tags:
    - attack.resource_development
    - attack.t1587

```
