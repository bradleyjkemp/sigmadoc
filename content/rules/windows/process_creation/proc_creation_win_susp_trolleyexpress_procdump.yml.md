---
title: "Process Access via TrolleyExpress Exclusion"
aliases:
  - "/rule/4c0aaedc-154c-4427-ada0-d80ef9c9deb6"
ruleid: 4c0aaedc-154c-4427-ada0-d80ef9c9deb6

tags:
  - attack.defense_evasion
  - attack.t1218.011
  - attack.credential_access
  - attack.t1003.001



status: experimental





date: Thu, 10 Feb 2022 09:17:25 +0100


---

Detects a possible process memory dump that uses the white-listed Citrix TrolleyExpress.exe filename as a way to dump the lsass process memory

<!--more-->


## Known false-positives

* unknown



## References

* https://twitter.com/_xpn_/status/1491557187168178176
* https://www.youtube.com/watch?v=Ie831jF0bb0


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_trolleyexpress_procdump.yml))
```yaml
title: Process Access via TrolleyExpress Exclusion
id: 4c0aaedc-154c-4427-ada0-d80ef9c9deb6
status: experimental
description: Detects a possible process memory dump that uses the white-listed Citrix TrolleyExpress.exe filename as a way to dump the lsass process memory
author: Florian Roth
references:
  - https://twitter.com/_xpn_/status/1491557187168178176
  - https://www.youtube.com/watch?v=Ie831jF0bb0
date: 2022/02/10
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      # We assume that the lsass.exe process has a process ID that's between 700 and 999 and the dumper uses just the PID as parameter
      - '\TrolleyExpress 7'
      - '\TrolleyExpress 8'
      - '\TrolleyExpress 9'
      - '\TrolleyExpress.exe 7'
      - '\TrolleyExpress.exe 8'
      - '\TrolleyExpress.exe 9'
      # Common dumpers
      - '\TrolleyExpress.exe -ma '
  renamed:
    Image|endswith: '\TrolleyExpress.exe'
  filter_renamed:
    OriginalFileName|contains: 'CtxInstall'
  filter_empty:
    OriginalFileName: null
  condition: selection or ( renamed and not 1 of filter* )
fields:
  - CommandLine
  - ParentCommandLine
falsepositives:
  - unknown
level: high
tags:
  - attack.defense_evasion
  - attack.t1218.011
  - attack.credential_access
  - attack.t1003.001

```
