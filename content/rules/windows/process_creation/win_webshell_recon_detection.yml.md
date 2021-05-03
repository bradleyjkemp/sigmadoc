---
title: "Webshell Recon Detection Via CommandLine & Processes"
aliases:
  - "/rule/f64e5c19-879c-4bae-b471-6d84c8339677"

tags:
  - attack.persistence
  - attack.t1505.003
  - attack.privilege_escalation
  - attack.t1100



date: Wed, 22 Jul 2020 09:05:50 +0100


---

Looking for processes spawned by web server components that indicate reconnaissance by popular public domain webshells for whether perl, python or wget are installed.

<!--more-->


## Known false-positives

* unknown




## Raw rule
```yaml
title: Webshell Recon Detection Via CommandLine & Processes
id: f64e5c19-879c-4bae-b471-6d84c8339677
status: experimental
description: Looking for processes spawned by web server components that indicate reconnaissance by popular public domain webshells for whether perl, python or wget are installed.
author: Cian Heasley
reference:
    - https://ragged-lab.blogspot.com/2020/07/webshells-automating-reconnaissance.html
date: 2020/07/22
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.privilege_escalation       # an old one
    - attack.t1100      # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|contains:
            - '*\apache*'
            - '*\tomcat*'
            - '*\w3wp.exe'
            - '*\php-cgi.exe'
            - '*\nginx.exe'
            - '*\httpd.exe'
        Image|endswith:
            - '*\cmd.exe'
        CommandLine|contains:
            - '*perl --help*'
            - '*python --help*'
            - '*wget --help*'
            - '*perl -h*'
    condition: selection
fields:
    - Image
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: high

```
