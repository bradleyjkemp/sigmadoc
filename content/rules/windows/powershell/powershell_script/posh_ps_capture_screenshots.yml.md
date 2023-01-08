---
title: "Windows Screen Capture with CopyFromScreen"
aliases:
  - "/rule/d4a11f63-2390-411c-9adf-d791fd152830"
ruleid: d4a11f63-2390-411c-9adf-d791fd152830

tags:
  - attack.collection
  - attack.t1113



status: experimental





date: Wed, 29 Dec 2021 17:47:43 +0100


---

Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation.
Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations


<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md#atomic-test-6---windows-screen-capture-copyfromscreen


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_capture_screenshots.yml))
```yaml
title: Windows Screen Capture with CopyFromScreen
id: d4a11f63-2390-411c-9adf-d791fd152830
status: experimental
description: |
  Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation.
  Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1113/T1113.md#atomic-test-6---windows-screen-capture-copyfromscreen
author: frack113
date: 2021/12/28
logsource:
    product: windows
    category: ps_script
detection:
    selection:
        ScriptBlockText|contains: '.CopyFromScreen'
    condition: selection
falsepositives:
  - Unknown
level: medium
tags:
  - attack.collection
  - attack.t1113

```
