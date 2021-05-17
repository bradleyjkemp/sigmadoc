---
title: "COMPlus_ETWEnabled Command Line Arguments"
aliases:
  - "/rule/41421f44-58f9-455d-838a-c398859841d4"

tags:
  - attack.defense_evasion
  - attack.t1562



status: experimental



level: critical



date: Sat, 6 Jun 2020 15:42:22 +0200


---

Potential adversaries stopping ETW providers recording loaded .NET assemblies.

<!--more-->


## Known false-positives

* unknown



## References

* https://twitter.com/_xpn_/status/1268712093928378368
* https://social.msdn.microsoft.com/Forums/vstudio/en-US/0878832e-39d7-4eaf-8e16-a729c4c40975/what-can-i-use-e13c0d23ccbc4e12931bd9cc2eee27e4-for?forum=clr
* https://github.com/dotnet/runtime/blob/ee2355c801d892f2894b0f7b14a20e6cc50e0e54/docs/design/coreclr/jit/viewing-jit-dumps.md#setting-configuration-variables
* https://github.com/dotnet/runtime/blob/f62e93416a1799aecc6b0947adad55a0d9870732/src/coreclr/src/inc/clrconfigvalues.h#L35-L38
* https://github.com/dotnet/runtime/blob/7abe42dc1123722ed385218268bb9fe04556e3d3/src/coreclr/src/inc/clrconfig.h#L33-L39
* https://github.com/dotnet/runtime/search?p=1&q=COMPlus_&unscoped_q=COMPlus_
* https://bunnyinside.com/?term=f71e8cb9c76a
* http://managed670.rssing.com/chan-5590147/all_p1.html
* https://github.com/dotnet/runtime/blob/4f9ae42d861fcb4be2fcd5d3d55d5f227d30e723/docs/coding-guidelines/clr-jit-coding-conventions.md#1412-disabling-code


## Raw rule
```yaml
title: COMPlus_ETWEnabled Command Line Arguments
id: 41421f44-58f9-455d-838a-c398859841d4
status: experimental
description: Potential adversaries stopping ETW providers recording loaded .NET assemblies.
references:
  - https://twitter.com/_xpn_/status/1268712093928378368
  - https://social.msdn.microsoft.com/Forums/vstudio/en-US/0878832e-39d7-4eaf-8e16-a729c4c40975/what-can-i-use-e13c0d23ccbc4e12931bd9cc2eee27e4-for?forum=clr
  - https://github.com/dotnet/runtime/blob/ee2355c801d892f2894b0f7b14a20e6cc50e0e54/docs/design/coreclr/jit/viewing-jit-dumps.md#setting-configuration-variables
  - https://github.com/dotnet/runtime/blob/f62e93416a1799aecc6b0947adad55a0d9870732/src/coreclr/src/inc/clrconfigvalues.h#L35-L38
  - https://github.com/dotnet/runtime/blob/7abe42dc1123722ed385218268bb9fe04556e3d3/src/coreclr/src/inc/clrconfig.h#L33-L39
  - https://github.com/dotnet/runtime/search?p=1&q=COMPlus_&unscoped_q=COMPlus_
  - https://bunnyinside.com/?term=f71e8cb9c76a
  - http://managed670.rssing.com/chan-5590147/all_p1.html
  - https://github.com/dotnet/runtime/blob/4f9ae42d861fcb4be2fcd5d3d55d5f227d30e723/docs/coding-guidelines/clr-jit-coding-conventions.md#1412-disabling-code
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020/05/02
modified: 2020/08/29
tags:
    - attack.defense_evasion
    - attack.t1562
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'COMPlus_ETWEnabled=0'
    condition: selection
falsepositives:
    - unknown
level: critical
```
