---
title: "Suspicious Code Page Switch"
aliases:
  - "/rule/c7942406-33dd-4377-a564-0f62db0593a3"



date: Mon, 14 Oct 2019 17:45:25 +0200


---

Detects a code page switch in command line or batch scripts to a rare language

<!--more-->


## Known false-positives

* Administrative activity (adjust code pages according to your organisation's region)



## References

* https://docs.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
* https://twitter.com/cglyer/status/1183756892952248325


## Raw rule
```yaml
title: Suspicious Code Page Switch
id: c7942406-33dd-4377-a564-0f62db0593a3
status: experimental
description: Detects a code page switch in command line or batch scripts to a rare language
author: Florian Roth
date: 2019/10/14
references:
    - https://docs.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
    - https://twitter.com/cglyer/status/1183756892952248325
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: 
            - 'chcp* 936'  # Chinese
            # - 'chcp* 1256' # Arabic
            - 'chcp* 1258' # Vietnamese
            # - 'chcp* 855'  # Russian
            # - 'chcp* 866'  # Russian
            # - 'chcp* 864'  # Arabic
    condition: selection
fields:
    - ParentCommandLine
falsepositives:
    - "Administrative activity (adjust code pages according to your organisation's region)"
level: medium

```
