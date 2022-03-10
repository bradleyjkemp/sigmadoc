---
title: "Failed to Load Policy in Windows Firewall with Advanced Security"
aliases:
  - "/rule/7ec15688-fd24-4177-ba43-1a950537ee39"




status: experimental





date: Sat, 19 Feb 2022 10:18:49 +0100


---

The Windows Firewall service failed to load Group Policy.

<!--more-->




## References

* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd364427(v=ws.10)


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/firewall_as/win_firewall_as_failed.yml))
```yaml
title: Failed to Load Policy in Windows Firewall with Advanced Security
id: 7ec15688-fd24-4177-ba43-1a950537ee39
status: experimental
description: The Windows Firewall service failed to load Group Policy.
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
        EventID: 2009
    condition: selection
level: low

```
