---
title: "Office Security Settings Changed"
aliases:
  - "/rule/a166f74e-bf44-409d-b9ba-ea4b2dd8b3cd"
ruleid: a166f74e-bf44-409d-b9ba-ea4b2dd8b3cd

tags:
  - attack.defense_evasion
  - attack.t1112



status: experimental





date: Wed, 3 Jun 2020 17:40:05 -0400


---

Detects registry changes to Office macro settings. The TrustRecords contain information on executed macro-enabled documents. (see references)

<!--more-->


## Known false-positives

* Valid Macros and/or internal documents



## References

* https://twitter.com/inversecos/status/1494174785621819397
* https://www.mcafee.com/blogs/other-blogs/mcafee-labs/zloader-with-a-new-infection-technique/
* https://securelist.com/scarcruft-surveilling-north-korean-defectors-and-human-rights-activists/105074/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_office_security.yml))
```yaml
title: Office Security Settings Changed
id: a166f74e-bf44-409d-b9ba-ea4b2dd8b3cd
status: experimental
description: Detects registry changes to Office macro settings. The TrustRecords contain information on executed macro-enabled documents. (see references)
author: Trent Liffick (@tliffick)
date: 2020/05/22
modified: 2022/01/10
references:
    - https://twitter.com/inversecos/status/1494174785621819397
    - https://www.mcafee.com/blogs/other-blogs/mcafee-labs/zloader-with-a-new-infection-technique/
    - https://securelist.com/scarcruft-surveilling-north-korean-defectors-and-human-rights-activists/105074/
tags:
    - attack.defense_evasion
    - attack.t1112
logsource:
    category: registry_event
    product: windows
detection:
    sec_settings:
        TargetObject|endswith:
            - '\Security\Trusted Documents\TrustRecords'
            - '\Security\AccessVBOM'
            - '\Security\VBAWarnings'
    condition: sec_settings
falsepositives:
    - Valid Macros and/or internal documents
level: high

```
