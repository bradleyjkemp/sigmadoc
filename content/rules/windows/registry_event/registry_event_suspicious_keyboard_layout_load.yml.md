---
title: "Suspicious Keyboard Layout Load"
aliases:
  - "/rule/34aa0252-6039-40ff-951f-939fd6ce47d8"
ruleid: 34aa0252-6039-40ff-951f-939fd6ce47d8

tags:
  - attack.resource_development
  - attack.t1588.002



status: test





date: Mon, 14 Oct 2019 16:25:27 +0200


---

Detects the keyboard preload installation with a suspicious keyboard layout, e.g. Chinese, Iranian or Vietnamese layout load in user session on systems maintained by US staff only

<!--more-->


## Known false-positives

* Administrators or users that actually use the selected keyboard layouts (heavily depends on the organisation's user base)



## References

* https://renenyffenegger.ch/notes/Windows/registry/tree/HKEY_CURRENT_USER/Keyboard-Layout/Preload/index
* https://github.com/SwiftOnSecurity/sysmon-config/pull/92/files


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_suspicious_keyboard_layout_load.yml))
```yaml
title: Suspicious Keyboard Layout Load
id: 34aa0252-6039-40ff-951f-939fd6ce47d8
status: test
description: Detects the keyboard preload installation with a suspicious keyboard layout, e.g. Chinese, Iranian or Vietnamese layout load in user session on systems maintained by US staff only
author: Florian Roth
references:
  - https://renenyffenegger.ch/notes/Windows/registry/tree/HKEY_CURRENT_USER/Keyboard-Layout/Preload/index
  - https://github.com/SwiftOnSecurity/sysmon-config/pull/92/files
date: 2019/10/12
modified: 2022/01/13
logsource:
  category: registry_event
  product: windows
  definition: 'Requirements: Sysmon config that monitors \Keyboard Layout\Preload subkey of the HKLU hives - see https://github.com/SwiftOnSecurity/sysmon-config/pull/92/files'
detection:
  selection_registry:
    EventType: SetValue 
    TargetObject|contains:
      - '\Keyboard Layout\Preload\'
      - '\Keyboard Layout\Substitutes\'
    Details|contains:
      - 00000429        # Persian (Iran)
      - 00050429        # Persian (Iran)
      - 0000042a        # Vietnamese
  condition: selection_registry
falsepositives:
  - "Administrators or users that actually use the selected keyboard layouts (heavily depends on the organisation's user base)"
level: medium
tags:
  - attack.resource_development
  - attack.t1588.002

```
