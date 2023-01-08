---
title: "Windows Defender Threat Detected"
aliases:
  - "/rule/57b649ef-ff42-4fb0-8bf6-62da243a1708"
ruleid: 57b649ef-ff42-4fb0-8bf6-62da243a1708

tags:
  - attack.execution
  - attack.t1059



status: stable





date: Sun, 28 Jun 2020 10:55:32 +0200


---

Detects all actions taken by Windows Defender malware detection engines

<!--more-->


## Known false-positives

* unlikely



## References

* https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/troubleshoot-windows-defender-antivirus


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/windefend/win_defender_threat.yml))
```yaml
title: Windows Defender Threat Detected
id: 57b649ef-ff42-4fb0-8bf6-62da243a1708
description: Detects all actions taken by Windows Defender malware detection engines
date: 2020/07/28
author: Ján Trenčanský
references:
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/troubleshoot-windows-defender-antivirus
status: stable
logsource:
    product: windows
    service: windefend
detection:
    selection:
        EventID:
            - 1006
            - 1116
            - 1015
            - 1117
    condition: selection
falsepositives:
    - unlikely
level: high
tags:
    - attack.execution
    - attack.t1059 
```
