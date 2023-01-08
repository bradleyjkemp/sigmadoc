---
title: "Setting Change in Windows Firewall with Advanced Security"
aliases:
  - "/rule/00bb5bd5-1379-4fcf-a965-a5b6f7478064"
ruleid: 00bb5bd5-1379-4fcf-a965-a5b6f7478064



status: experimental





date: Sat, 19 Feb 2022 10:18:49 +0100


---

Setting have been change in Windows Firewall

<!--more-->




## References

* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd364427(v=ws.10)


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/firewall_as/win_firewall_as_setting_change.yml))
```yaml
title: Setting Change in Windows Firewall with Advanced Security
id: 00bb5bd5-1379-4fcf-a965-a5b6f7478064
status: experimental
description: Setting have been change in Windows Firewall
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
        EventID: 
            - 2002  # A Windows Firewall setting has changed.
            - 2003  # A Windows Firewall setting in the %1 profile has changed.
            - 2008  # Windows Firewall Group Policy settings have changed. The new settings have been applied
            - 2010  # Network profile changed on an interface.
    condition: selection
level: low

```
