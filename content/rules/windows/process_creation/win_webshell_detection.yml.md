---
title: "Webshell Detection With Command Line Keywords"
aliases:
  - "/rule/bed2a484-9348-4143-8a8a-b801c979301c"

tags:
  - attack.persistence
  - attack.t1505.003
  - attack.privilege_escalation
  - attack.t1100



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects certain command line parameters often used during reconnaissance activity via web shells

<!--more-->


## Known false-positives

* unknown




## Raw rule
```yaml
title: Webshell Detection With Command Line Keywords
id: bed2a484-9348-4143-8a8a-b801c979301c
description: Detects certain command line parameters often used during reconnaissance activity via web shells
author: Florian Roth
reference:
    - https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-ii.html
date: 2017/01/01
modified: 2019/10/26
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
        ParentImage:
            - '*\apache*'
            - '*\tomcat*'
            - '*\w3wp.exe'
            - '*\php-cgi.exe'
            - '*\nginx.exe'
            - '*\httpd.exe'
        CommandLine:
            - '*whoami*'
            - '*net user *'
            - '*ping -n *'
            - '*systeminfo'
            - '*&cd&echo*'
            - '*cd /d*'  # https://www.computerhope.com/cdhlp.htm
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: high

```