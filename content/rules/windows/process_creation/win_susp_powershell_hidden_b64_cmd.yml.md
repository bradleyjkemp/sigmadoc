---
title: "Malicious Base64 Encoded PowerShell Keywords in Command Lines"
aliases:
  - "/rule/f26c6093-6f14-4b12-800f-0fcb46f5ffd0"

tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1086



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects base64 encoded strings used in hidden malicious PowerShell command lines

<!--more-->


## Known false-positives

* Penetration tests



## References

* http://www.leeholmes.com/blog/2017/09/21/searching-for-content-in-base-64-strings/


## Raw rule
```yaml
title: Malicious Base64 Encoded PowerShell Keywords in Command Lines
id: f26c6093-6f14-4b12-800f-0fcb46f5ffd0
status: experimental
description: Detects base64 encoded strings used in hidden malicious PowerShell command lines
references:
    - http://www.leeholmes.com/blog/2017/09/21/searching-for-content-in-base-64-strings/
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086      # an old one
author: John Lambert (rule)
date: 2019/01/16
logsource:
    category: process_creation
    product: windows
detection:
    encoded:
        Image: '*\powershell.exe'
        CommandLine: '* hidden *'
    selection:
        CommandLine:
            - '*AGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByA*'
            - '*aXRzYWRtaW4gL3RyYW5zZmVy*'
            - '*IAaQB0AHMAYQBkAG0AaQBuACAALwB0AHIAYQBuAHMAZgBlAHIA*'
            - '*JpdHNhZG1pbiAvdHJhbnNmZX*'
            - '*YgBpAHQAcwBhAGQAbQBpAG4AIAAvAHQAcgBhAG4AcwBmAGUAcg*'
            - '*Yml0c2FkbWluIC90cmFuc2Zlc*'
            - '*AGMAaAB1AG4AawBfAHMAaQB6AGUA*'
            - '*JABjAGgAdQBuAGsAXwBzAGkAegBlA*'
            - '*JGNodW5rX3Npem*'
            - '*QAYwBoAHUAbgBrAF8AcwBpAHoAZQ*'
            - '*RjaHVua19zaXpl*'
            - '*Y2h1bmtfc2l6Z*'
            - '*AE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4A*'
            - '*kATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8Abg*'
            - '*lPLkNvbXByZXNzaW9u*'
            - '*SQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuA*'
            - '*SU8uQ29tcHJlc3Npb2*'
            - '*Ty5Db21wcmVzc2lvb*'
            - '*AE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQ*'
            - '*kATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA*'
            - '*lPLk1lbW9yeVN0cmVhb*'
            - '*SQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0A*'
            - '*SU8uTWVtb3J5U3RyZWFt*'
            - '*Ty5NZW1vcnlTdHJlYW*'
            - '*4ARwBlAHQAQwBoAHUAbgBrA*'
            - '*5HZXRDaHVua*'
            - '*AEcAZQB0AEMAaAB1AG4Aaw*'
            - '*LgBHAGUAdABDAGgAdQBuAGsA*'
            - '*LkdldENodW5r*'
            - '*R2V0Q2h1bm*'
            - '*AEgAUgBFAEEARABfAEkATgBGAE8ANgA0A*'
            - '*QASABSAEUAQQBEAF8ASQBOAEYATwA2ADQA*'
            - '*RIUkVBRF9JTkZPNj*'
            - '*SFJFQURfSU5GTzY0*'
            - '*VABIAFIARQBBAEQAXwBJAE4ARgBPADYANA*'
            - '*VEhSRUFEX0lORk82N*'
            - '*AHIAZQBhAHQAZQBSAGUAbQBvAHQAZQBUAGgAcgBlAGEAZA*'
            - '*cmVhdGVSZW1vdGVUaHJlYW*'
            - '*MAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkA*'
            - '*NyZWF0ZVJlbW90ZVRocmVhZ*'
            - '*Q3JlYXRlUmVtb3RlVGhyZWFk*'
            - '*QwByAGUAYQB0AGUAUgBlAG0AbwB0AGUAVABoAHIAZQBhAGQA*'
            - '*0AZQBtAG0AbwB2AGUA*'
            - '*1lbW1vdm*'
            - '*AGUAbQBtAG8AdgBlA*'
            - '*bQBlAG0AbQBvAHYAZQ*'
            - '*bWVtbW92Z*'
            - '*ZW1tb3Zl*'
    condition: encoded and selection
falsepositives:
    - Penetration tests
level: high

```