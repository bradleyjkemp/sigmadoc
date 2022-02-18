---
title: "{{.Parsed.Title}}"
aliases:
  - "/rule/{{.Parsed.ID}}"

{{with .Parsed.Tags}}
tags:
{{range .}}  - {{.}}
{{end}}{{end}}

{{with .Parsed.Status}}
status: {{.}}
{{end}}

{{with .Parsed.AdditionalFields.level}}
level: {{.}}
{{end}}

{{with .Time}}
date: {{.}}
{{end}}
---

{{.Parsed.Description}}

<!--more-->

{{with .Parsed.AdditionalFields.falsepositives}}
## Known false-positives
{{range .}}
* {{.}}
{{- end}}
{{end}}

{{with .Parsed.References}}
## References
{{range .}}
* {{.}}
  {{- end}}
{{end}}

## Raw rule {{with .GitHubEditLink}}([edit]({{.}})){{end}}
```yaml
{{.Original}}
```
