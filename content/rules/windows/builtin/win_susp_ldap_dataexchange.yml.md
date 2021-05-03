---
title: "Suspicious LDAP-Attributes Used"
aliases:
  - "/rule/d00a9a72-2c09-4459-ad03-5e0a23351e36"

tags:
  - attack.t1071
  - attack.t1001.003
  - attack.command_and_control



date: Thu, 26 Mar 2020 15:13:36 +0100


---

Detects the usage of particular AttributeLDAPDisplayNames, which are known for data exchange via LDAP by the tool LDAPFragger and are additionally not commonly used in companies.

<!--more-->


## Known false-positives

* Companies, who may use these default LDAP-Attributes for personal information



## References

* https://medium.com/@ivecodoe/detecting-ldapfragger-a-newly-released-cobalt-strike-beacon-using-ldap-for-c2-communication-c274a7f00961
* https://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes/
* https://github.com/fox-it/LDAPFragger


## Raw rule
```yaml
title: Suspicious LDAP-Attributes Used
id: d00a9a72-2c09-4459-ad03-5e0a23351e36
description: Detects the usage of particular AttributeLDAPDisplayNames, which are known for data exchange via LDAP by the tool LDAPFragger and are additionally not commonly used in companies.
status: experimental
date: 2019/03/24
modified: 2020/08/23
author: xknow @xknow_infosec
references:
    - https://medium.com/@ivecodoe/detecting-ldapfragger-a-newly-released-cobalt-strike-beacon-using-ldap-for-c2-communication-c274a7f00961
    - https://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes/
    - https://github.com/fox-it/LDAPFragger
tags:
    - attack.t1071          # an old one
    - attack.t1001.003
    - attack.command_and_control
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5136
        AttributeValue: '*'
        AttributeLDAPDisplayName:
            - 'primaryInternationalISDNNumber'
            - 'otherFacsimileTelephoneNumber'
            - 'primaryTelexNumber'
    condition: selection
falsepositives:
    - Companies, who may use these default LDAP-Attributes for personal information
level: high

```
