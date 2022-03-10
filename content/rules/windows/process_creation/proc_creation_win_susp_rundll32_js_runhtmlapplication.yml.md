---
title: "Rundll32 JS RunHTMLApplication Pattern"
aliases:
  - "/rule/9f06447a-a33a-4cbe-a94f-a3f43184a7a3"


tags:
  - attack.defense_evasion



status: experimental





date: Fri, 14 Jan 2022 12:30:16 +0100


---

Detects suspicious command line patterns used when rundll32 is used to run JavaScript code

<!--more-->


## Known false-positives

* unknown



## References

* http://hyp3rlinx.altervista.org/advisories/MICROSOFT_WINDOWS_DEFENDER_DETECTION_BYPASS.txt


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_rundll32_js_runhtmlapplication.yml))
```yaml
title: Rundll32 JS RunHTMLApplication Pattern
id: 9f06447a-a33a-4cbe-a94f-a3f43184a7a3
status: experimental
description: Detects suspicious command line patterns used when rundll32 is used to run JavaScript code
author: Florian Roth
date: 2022/01/14
references:
    - http://hyp3rlinx.altervista.org/advisories/MICROSOFT_WINDOWS_DEFENDER_DETECTION_BYPASS.txt
tags:
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains|all:
            - 'rundll32'
            - 'javascript'
            - '..\..\mshtml,RunHTMLApplication'
    selection2:
        CommandLine|contains:
            - ';document.write();GetObject("script'
    condition: 1 of selection*
falsepositives:
    - unknown
level: high


```
