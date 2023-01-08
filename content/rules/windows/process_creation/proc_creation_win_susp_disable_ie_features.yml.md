---
title: "Disabled IE Security Features"
aliases:
  - "/rule/fb50eb7a-5ab1-43ae-bcc9-091818cb8424"
ruleid: fb50eb7a-5ab1-43ae-bcc9-091818cb8424

tags:
  - attack.defense_evasion
  - attack.t1562.001



status: test





date: Fri, 19 Jun 2020 09:37:10 +0200


---

Detects command lines that indicate unwanted modifications to registry keys that disable important Internet Explorer security features

<!--more-->


## Known false-positives

* Unknown, maybe some security software installer disables these features temporarily



## References

* https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_disable_ie_features.yml))
```yaml
title: Disabled IE Security Features
id: fb50eb7a-5ab1-43ae-bcc9-091818cb8424
status: test
description: Detects command lines that indicate unwanted modifications to registry keys that disable important Internet Explorer security features
author: Florian Roth
references:
  - https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/
date: 2020/06/19
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    CommandLine|contains|all:
      - ' -name IEHarden '
      - ' -value 0 '
  selection2:
    CommandLine|contains|all:
      - ' -name DEPOff '
      - ' -value 1 '
  selection3:
    CommandLine|contains|all:
      - ' -name DisableFirstRunCustomize '
      - ' -value 2 '
  condition: 1 of selection*
falsepositives:
  - Unknown, maybe some security software installer disables these features temporarily
level: high
tags:
  - attack.defense_evasion
  - attack.t1562.001

```
