---
title: "Run Once Task Configuration in Registry"
aliases:
  - "/rule/c74d7efc-8826-45d9-b8bb-f04fac9e4eff"


tags:
  - attack.defense_evasion
  - attack.t1112



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Rule to detect the configuration of Run Once registry key. Configured payload can be run by runonce.exe /AlternateShellStartup

<!--more-->


## Known false-positives

* Legitimate modification of the registry key by legitimate program



## References

* https://twitter.com/pabraeken/status/990717080805789697
* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Runonce.yml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_runonce_persistence.yml))
```yaml
title: Run Once Task Configuration in Registry
id: c74d7efc-8826-45d9-b8bb-f04fac9e4eff
status: test
description: Rule to detect the configuration of Run Once registry key. Configured payload can be run by runonce.exe /AlternateShellStartup
author: 'Avneet Singh @v3t0_, oscd.community'
references:
  - https://twitter.com/pabraeken/status/990717080805789697
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Runonce.yml
date: 2020/11/15
modified: 2022/02/15
logsource:
  product: windows
  category: registry_event
detection:
  selection:
    TargetObject|startswith: 'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components'
    TargetObject|endswith: '\StubPath'
  filter_chrome:
    Details|startswith: '"C:\Program Files\Google\Chrome\Application\'
    Details|endswith: '\Installer\chrmstp.exe" --configure-user-settings --verbose-logging --system-level'
  condition: selection and not 1 of filter_*
falsepositives:
  - Legitimate modification of the registry key by legitimate program
level: medium
tags:
  - attack.defense_evasion
  - attack.t1112

```
