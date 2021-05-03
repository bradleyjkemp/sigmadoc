---
title: "Renamed Binary"
aliases:
  - "/rule/36480ae1-a1cb-4eaa-a0d6-29801d7e9142"

tags:
  - attack.defense_evasion
  - attack.t1036
  - attack.t1036.003



date: Sat, 15 Jun 2019 20:19:35 +1000


---

Detects the execution of a renamed binary often used by attackers or malware leveraging new Sysmon OriginalFileName datapoint.

<!--more-->


## Known false-positives

* Custom applications use renamed binaries adding slight change to binary name. Typically this is easy to spot and add to whitelist



## References

* https://attack.mitre.org/techniques/T1036/
* https://mgreen27.github.io/posts/2019/05/12/BinaryRename.html
* https://mgreen27.github.io/posts/2019/05/29/BinaryRename2.html


## Raw rule
```yaml
title: Renamed Binary
id: 36480ae1-a1cb-4eaa-a0d6-29801d7e9142
status: experimental
description: Detects the execution of a renamed binary often used by attackers or malware leveraging new Sysmon OriginalFileName datapoint.
author: Matthew Green - @mgreen27, Ecco, James Pemberton / @4A616D6573, oscd.community (improvements), Andreas Hunkeler (@Karneades)
date: 2019/06/15
modified: 2020/09/06
references:
    - https://attack.mitre.org/techniques/T1036/
    - https://mgreen27.github.io/posts/2019/05/12/BinaryRename.html
    - https://mgreen27.github.io/posts/2019/05/29/BinaryRename2.html
tags:
    - attack.defense_evasion
    - attack.t1036 # an old one
    - attack.t1036.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName:
            - 'cmd.exe'
            - 'powershell.exe'
            - 'powershell_ise.exe'
            - 'psexec.exe'
            - 'psexec.c'  # old versions of psexec (2016 seen)
            - 'cscript.exe'
            - 'wscript.exe'
            - 'mshta.exe'
            - 'regsvr32.exe'
            - 'wmic.exe'
            - 'certutil.exe'
            - 'rundll32.exe'
            - 'cmstp.exe'
            - 'msiexec.exe'
            - '7z.exe'
            - 'winrar.exe'
            - 'wevtutil.exe'
            - 'net.exe'
            - 'net1.exe'
            - 'netsh.exe'
    filter:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\powershell_ise.exe'
            - '\psexec.exe'
            - '\psexec64.exe'
            - '\cscript.exe'
            - '\wscript.exe'
            - '\mshta.exe'
            - '\regsvr32.exe'
            - '\wmic.exe'
            - '\certutil.exe'
            - '\rundll32.exe'
            - '\cmstp.exe'
            - '\msiexec.exe'
            - '\7z.exe'
            - '\winrar.exe'
            - '\wevtutil.exe'
            - '\net.exe'
            - '\net1.exe'
            - '\netsh.exe'
    condition: selection and not filter
falsepositives:
    - Custom applications use renamed binaries adding slight change to binary name. Typically this is easy to spot and add to whitelist
level: medium

```