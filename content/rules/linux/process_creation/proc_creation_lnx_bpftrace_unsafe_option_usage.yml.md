---
title: "BPFtrace Unsafe Option Usage"
aliases:
  - "/rule/f8341cb2-ee25-43fa-a975-d8a5a9714b39"


tags:
  - attack.execution
  - attack.t1059.004



status: experimental





date: Fri, 11 Feb 2022 12:08:53 +0100


---

Detects the usage of the unsafe bpftrace option

<!--more-->


## Known false-positives

* Legitimate usage of the unsafe option



## References

* https://embracethered.com/blog/posts/2021/offensive-bpf-bpftrace/
* https://bpftrace.org/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_bpftrace_unsafe_option_usage.yml))
```yaml
title: BPFtrace Unsafe Option Usage
id: f8341cb2-ee25-43fa-a975-d8a5a9714b39
status: experimental
description: Detects the usage of the unsafe bpftrace option
author: Andreas Hunkeler (@Karneades)
tags: 
  - attack.execution
  - attack.t1059.004
references:
  - https://embracethered.com/blog/posts/2021/offensive-bpf-bpftrace/
  - https://bpftrace.org/
date: 2022/02/11
logsource:
  category: process_creation
  product: linux
detection:
  selection1:
    Image|endswith:
      - 'bpftrace'
    CommandLine|contains:
      - '--unsafe'
  condition: selection1
falsepositives:
  - Legitimate usage of the unsafe option
level: medium

```
