---
title: "Reset to Default Configuration Windows Firewall with Advanced Security"
aliases:
  - "/rule/04b60639-39c0-412a-9fbe-e82499c881a3"




status: experimental





date: Sat, 19 Feb 2022 10:18:49 +0100


---

Windows Firewall has been reset to its default configuration.

<!--more-->




## References

* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd364427(v=ws.10)


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/firewall_as/win_firewall_as_reset.yml))
```yaml
title: Reset to Default Configuration Windows Firewall with Advanced Security
id: 04b60639-39c0-412a-9fbe-e82499c881a3
status: experimental
description: Windows Firewall has been reset to its default configuration.
author: frack113
date: 2022/02/19
references:
    - https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd364427(v=ws.10)
logsource:
    product: windows
    service: firewall-as
# EventID 49xx and 50xx are not used in the rule, please don't use Windows Server 2008 R2
detection:
    selection:
        EventID: 2032
    condition: selection
level: low

```
