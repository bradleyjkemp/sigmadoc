---
title: "Enabling COR Profiler Environment Variables"
aliases:
  - "/rule/ad89044a-8f49-4673-9a55-cbd88a1b374f"
ruleid: ad89044a-8f49-4673-9a55-cbd88a1b374f

tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1574.012



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

This rule detects cor_enable_profiling and cor_profiler environment variables being set and configured.

<!--more-->




## References

* https://twitter.com/jamieantisocial/status/1304520651248668673
* https://www.slideshare.net/JamieWilliams130/started-from-the-bottom-exploiting-data-sources-to-uncover-attck-behaviors
* https://www.sans.org/cyber-security-summit/archives


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_enabling_cor_profiler_env_variables.yml))
```yaml
title: Enabling COR Profiler Environment Variables
id: ad89044a-8f49-4673-9a55-cbd88a1b374f
status: test
description: This rule detects cor_enable_profiling and cor_profiler environment variables being set and configured.
author: Jose Rodriguez (@Cyb3rPandaH), OTR (Open Threat Research)
references:
  - https://twitter.com/jamieantisocial/status/1304520651248668673
  - https://www.slideshare.net/JamieWilliams130/started-from-the-bottom-exploiting-data-sources-to-uncover-attck-behaviors
  - https://www.sans.org/cyber-security-summit/archives
date: 2020/09/10
modified: 2021/11/27
logsource:
  category: registry_event
  product: windows
detection:
  selection:
    TargetObject|endswith:
      - '\COR_ENABLE_PROFILING'
      - '\COR_PROFILER'
  condition: selection
level: high
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1574.012

```
