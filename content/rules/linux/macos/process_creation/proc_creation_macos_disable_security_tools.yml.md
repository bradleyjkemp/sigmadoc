---
title: "Disable Security Tools"
aliases:
  - "/rule/ff39f1a6-84ac-476f-a1af-37fcdf53d7c0"
ruleid: ff39f1a6-84ac-476f-a1af-37fcdf53d7c0

tags:
  - attack.defense_evasion
  - attack.t1562.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects disabling security tools

<!--more-->


## Known false-positives

* Legitimate activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_disable_security_tools.yml))
```yaml
title: Disable Security Tools
id: ff39f1a6-84ac-476f-a1af-37fcdf53d7c0
status: test
description: Detects disabling security tools
author: Daniil Yugoslavskiy, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md
date: 2020/10/19
modified: 2021/11/27
logsource:
  category: process_creation
  product: macos
detection:
  launchctl_unload:
    Image: '/bin/launchctl'
    CommandLine|contains: 'unload'
  security_plists:
    CommandLine|contains:
      - 'com.objective-see.lulu.plist'                     # Objective-See firewall management utility
      - 'com.objective-see.blockblock.plist'               # Objective-See persistence locations watcher/blocker
      - 'com.google.santad.plist'                          # google santa
      - 'com.carbonblack.defense.daemon.plist'             # carbon black
      - 'com.carbonblack.daemon.plist'                     # carbon black
      - 'at.obdev.littlesnitchd.plist'                     # Objective Development Software firewall management utility
      - 'com.tenablesecurity.nessusagent.plist'            # Tenable Nessus
      - 'com.opendns.osx.RoamingClientConfigUpdater.plist' # OpenDNS Umbrella
      - 'com.crowdstrike.falcond.plist'                    # Crowdstrike Falcon
      - 'com.crowdstrike.userdaemon.plist'                 # Crowdstrike Falcon
      - 'osquery'                                          # facebook osquery
      - 'filebeat'                                         # elastic log file shipper
      - 'auditbeat'                                        # elastic auditing agent/log shipper
      - 'packetbeat'                                       # elastic network logger/shipper
      - 'td-agent'                                         # fluentd log shipper
  disable_gatekeeper:
    Image: '/usr/sbin/spctl'
    CommandLine|contains: 'disable'
  condition: (launchctl_unload and security_plists) or disable_gatekeeper
falsepositives:
  - Legitimate activities
level: medium
tags:
  - attack.defense_evasion
  - attack.t1562.001

```