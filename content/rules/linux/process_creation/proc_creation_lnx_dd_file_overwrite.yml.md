---
title: "DD File Overwrite"
aliases:
  - "/rule/2953194b-e33c-4859-b9e8-05948c167447"


tags:
  - attack.impact
  - attack.t1485



status: experimental





date: Fri, 15 Oct 2021 15:28:15 -0400


---

Detects potential overwriting and deletion of a file using DD.

<!--more-->


## Known false-positives

* Any user deleting files that way.



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md#atomic-test-2---macoslinux---overwrite-file-with-dd


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_dd_file_overwrite.yml))
```yaml
title: DD File Overwrite
id: 2953194b-e33c-4859-b9e8-05948c167447
status: experimental
description: Detects potential overwriting and deletion of a file using DD.
date: 2021/10/15
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
tags:
    - attack.impact
    - attack.t1485
references:
   - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md#atomic-test-2---macoslinux---overwrite-file-with-dd
logsource:
   product: linux
   category: process_creation
detection:
   selection1:
      Image: '/bin/dd'
   selection2:   
      CommandLine|contains: 'of='
   selection3:
      CommandLine|contains:
         - 'if=/dev/zero'
         - 'if=/dev/null'
   condition: selection1 and selection2 and selection3
falsepositives:
   - Any user deleting files that way.
level: low
```
