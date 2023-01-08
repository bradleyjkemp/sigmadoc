---
title: "Possible SPN Enumeration"
aliases:
  - "/rule/1eeed653-dbc8-4187-ad0c-eeebb20e6599"
ruleid: 1eeed653-dbc8-4187-ad0c-eeebb20e6599

tags:
  - attack.credential_access
  - attack.t1558.003



status: test





---

Detects Service Principal Name Enumeration used for Kerberoasting

<!--more-->


## Known false-positives

* Administrator Activity



## References

* https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_spn_enum.yml))
```yaml
title: Possible SPN Enumeration
id: 1eeed653-dbc8-4187-ad0c-eeebb20e6599
status: test
description: Detects Service Principal Name Enumeration used for Kerberoasting
author: Markus Neis, keepwatch
references:
  - https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation
date: 2018/11/14
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection_image:
    Image|endswith: '\setspn.exe'
  selection_desc:
    Description|contains|all:
      - 'Query or reset the computer'
      - 'SPN attribute'
  cmd:
    CommandLine|contains: '-q'
  condition: (selection_image or selection_desc) and cmd
falsepositives:
  - Administrator Activity
level: medium
tags:
  - attack.credential_access
  - attack.t1558.003

```
