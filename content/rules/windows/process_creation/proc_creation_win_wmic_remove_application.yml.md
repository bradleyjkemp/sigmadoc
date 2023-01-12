---
title: "WMI Uninstall An Application"
aliases:
  - "/rule/b53317a0-8acf-4fd1-8de8-a5401e776b96"
ruleid: b53317a0-8acf-4fd1-8de8-a5401e776b96

tags:
  - attack.execution
  - attack.t1047



status: experimental





date: Fri, 28 Jan 2022 16:12:38 +0100


---

Uninstall an application with wmic

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md#atomic-test-10---application-uninstall-using-wmic


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_wmic_remove_application.yml))
```yaml
title: WMI Uninstall An Application 
id: b53317a0-8acf-4fd1-8de8-a5401e776b96
status: experimental
description: Uninstall an application with wmic
author: frac113
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md#atomic-test-10---application-uninstall-using-wmic
date: 2022/01/28
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: \WMIC.exe
    CommandLine|contains: call uninstall
  condition: selection
falsepositives:
  - Unknown
level: medium
tags:
  - attack.execution
  - attack.t1047

```