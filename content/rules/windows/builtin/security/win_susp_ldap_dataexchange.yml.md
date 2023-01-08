---
title: "Suspicious LDAP-Attributes Used"
aliases:
  - "/rule/d00a9a72-2c09-4459-ad03-5e0a23351e36"
ruleid: d00a9a72-2c09-4459-ad03-5e0a23351e36

tags:
  - attack.t1001.003
  - attack.command_and_control



status: test





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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_susp_ldap_dataexchange.yml))
```yaml
title: Suspicious LDAP-Attributes Used
id: d00a9a72-2c09-4459-ad03-5e0a23351e36
status: test
description: Detects the usage of particular AttributeLDAPDisplayNames, which are known for data exchange via LDAP by the tool LDAPFragger and are additionally not commonly used in companies.
author: xknow @xknow_infosec
references:
  - https://medium.com/@ivecodoe/detecting-ldapfragger-a-newly-released-cobalt-strike-beacon-using-ldap-for-c2-communication-c274a7f00961
  - https://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes/
  - https://github.com/fox-it/LDAPFragger
date: 2019/03/24
modified: 2021/11/27
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
tags:
  - attack.t1001.003
  - attack.command_and_control

```
