---
title: "Suspicious Screensaver Binary File Creation"
aliases:
  - "/rule/97aa2e88-555c-450d-85a6-229bcd87efb8"


tags:
  - attack.persistence
  - attack.t1546.002



status: experimental





date: Wed, 29 Dec 2021 17:47:43 +0100


---

Adversaries may establish persistence by executing malicious content triggered by user inactivity.
Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension


<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.002/T1546.002.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_creation_scr_binary_file.yml))
```yaml
title: Suspicious Screensaver Binary File Creation
id: 97aa2e88-555c-450d-85a6-229bcd87efb8
status: experimental
description: | 
  Adversaries may establish persistence by executing malicious content triggered by user inactivity.
  Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension
author: frack113
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.002/T1546.002.md
date: 2021/12/29
modified: 2022/01/10
logsource:
  product: windows
  category: file_event
detection:
  selection:
    TargetFilename|endswith: '.scr'
  filter:
    Image|endswith:
      - '\Kindle.exe'
      - '\Bin\ccSvcHst.exe' # Symantec Endpoint Protection
  condition: selection and not 1 of filter*
falsepositives:
  - Unknown
level: medium
tags:
  - attack.persistence
  - attack.t1546.002

```
