---
title: "Suspicious Certutil Command"
aliases:
  - "/rule/e011a729-98a6-4139-b5c4-bf6f6dd8239a"

tags:
  - attack.defense_evasion
  - attack.t1140
  - attack.command_and_control
  - attack.t1105
  - attack.s0160
  - attack.g0007
  - attack.g0010
  - attack.g0045
  - attack.g0049
  - attack.g0075
  - attack.g0096



status: experimental



level: high



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a suspicious Microsoft certutil execution with sub commands like 'decode' sub command, which is sometimes used to decode malicious code with the built-in certutil utility

<!--more-->


## Known false-positives

* False positives depend on scripts and administrative tools used in the monitored environment



## References

* https://twitter.com/JohnLaTwC/status/835149808817991680
* https://twitter.com/subTee/status/888102593838362624
* https://twitter.com/subTee/status/888071631528235010
* https://blogs.technet.microsoft.com/pki/2006/11/30/basic-crl-checking-with-certutil/
* https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/
* https://twitter.com/egre55/status/1087685529016193025
* https://lolbas-project.github.io/lolbas/Binaries/Certutil/


## Raw rule
```yaml
title: Suspicious Certutil Command
id: e011a729-98a6-4139-b5c4-bf6f6dd8239a
status: experimental
description: Detects a suspicious Microsoft certutil execution with sub commands like 'decode' sub command, which is sometimes used to decode malicious code with
    the built-in certutil utility
author: Florian Roth, juju4, keepwatch
date: 2019/01/16
modified: 2020/09/05
references:
    - https://twitter.com/JohnLaTwC/status/835149808817991680
    - https://twitter.com/subTee/status/888102593838362624
    - https://twitter.com/subTee/status/888071631528235010
    - https://blogs.technet.microsoft.com/pki/2006/11/30/basic-crl-checking-with-certutil/
    - https://www.trustedsec.com/2017/07/new-tool-release-nps_payload/
    - https://twitter.com/egre55/status/1087685529016193025
    - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* -decode *'
            - '* /decode *'
            - '* -decodehex *'
            - '* /decodehex *'
            - '* -urlcache *'
            - '* /urlcache *'
            - '* -verifyctl *'
            - '* /verifyctl *'
            - '* -encode *'
            - '* /encode *'
            - '*certutil* -URL*'
            - '*certutil* /URL*'
            - '*certutil* -ping*'
            - '*certutil* /ping*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.defense_evasion
    - attack.t1140
    - attack.command_and_control
    - attack.t1105
    - attack.s0160
    - attack.g0007
    - attack.g0010
    - attack.g0045
    - attack.g0049
    - attack.g0075
    - attack.g0096        
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: high

```
