---
title: "Obfuscated Command Line Using Special Unicode Characters"
aliases:
  - "/rule/e0552b19-5a83-4222-b141-b36184bb8d79"


tags:
  - attack.defense_evasion
  - attack.t1027



status: experimental





date: Sat, 15 Jan 2022 17:04:03 +0100


---

Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit.

<!--more-->


## Known false-positives

* unknown



## References

* https://www.wietzebeukema.nl/blog/windows-command-line-obfuscation
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md#atomic-test-6---dlp-evasion-via-sensitive-data-in-vba-macro-over-http


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_char_in_cmd.yml))
```yaml
title: Obfuscated Command Line Using Special Unicode Characters
id: e0552b19-5a83-4222-b141-b36184bb8d79
status: experimental
description: Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. 
author: frack113
references:
    - https://www.wietzebeukema.nl/blog/windows-command-line-obfuscation
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md#atomic-test-6---dlp-evasion-via-sensitive-data-in-vba-macro-over-http
date: 2022/01/15
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        #find the sysmon event
        CommandLine|contains: 
            - 'â'
            - '€'
            - '£'
            - '¯'
            - '®'
            - 'µ'
            - '¶'
    condition: selection
falsepositives:
    - unknown
level: high
tags:
    - attack.defense_evasion
    - attack.t1027
```
