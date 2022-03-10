---
title: "Powershell Store File In Alternate Data Stream"
aliases:
  - "/rule/a699b30e-d010-46c8-bbd1-ee2e26765fe9"


tags:
  - attack.defense_evasion
  - attack.t1564.004



status: experimental





date: Thu, 2 Sep 2021 09:47:54 +0200


---

Storing files in Alternate Data Stream (ADS) similar to Astaroth malware.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.004/T1564.004.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_store_file_in_alternate_data_stream.yml))
```yaml
title: Powershell Store File In Alternate Data Stream
id: a699b30e-d010-46c8-bbd1-ee2e26765fe9
status: experimental
author: frack113
date: 2021/09/02
modified: 2021/10/16
description: Storing files in Alternate Data Stream (ADS) similar to Astaroth malware.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.004/T1564.004.md
tags:
    - attack.defense_evasion
    - attack.t1564.004
logsource:
    product: windows
    category: ps_script
    definition: EnableScriptBlockLogging must be set to enable
detection:
    selection_compspec:
        ScriptBlockText|contains|all: 
            - 'Start-Process'
            - '-FilePath "$env:comspec" '
            - '-ArgumentList '
            - '>'
    condition: selection_compspec
falsepositives:
    - Unknown
level: medium
```
