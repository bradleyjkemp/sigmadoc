---
title: "Windows Credential Editor"
aliases:
  - "/rule/7aa7009a-28b9-4344-8c1f-159489a390df"

tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.001
  - attack.s0005



date: Tue, 31 Dec 2019 09:27:38 +0100


---

Detects the use of Windows Credential Editor (WCE)

<!--more-->


## Known false-positives

* Another service that uses a single -s command line switch



## References

* https://www.ampliasecurity.com/research/windows-credentials-editor/


## Raw rule
```yaml
title: Windows Credential Editor
id: 7aa7009a-28b9-4344-8c1f-159489a390df
description: Detects the use of Windows Credential Editor (WCE)
author: Florian Roth
references:
    - https://www.ampliasecurity.com/research/windows-credentials-editor/
date: 2019/12/31
modified: 2020/08/26
tags:
    - attack.credential_access
    - attack.t1003 # an old one
    - attack.t1003.001
    - attack.s0005
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Imphash: 
          - a53a02b997935fd8eedcb5f7abab9b9f
          - e96a73c7bf33a464c510ede582318bf2
    selection2:
        CommandLine|endswith: '.exe -S'
        ParentImage|endswith: '\services.exe'
    condition: 1 of them
falsepositives:
    - 'Another service that uses a single -s command line switch'
level: critical
```