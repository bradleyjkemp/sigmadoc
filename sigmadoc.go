package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"text/template"

	"github.com/bradleyjkemp/sigma-go"
)

var (
	rulesDirectory  = flag.String("rules-directory", ".", "Directory containing Sigma rules")
	outputDirectory = flag.String("output-directory", "content", "Directory to write converted markdown files to (usually your Hugo content directory)")
)

func main() {
	flag.Parse()
	errored := false
	err := filepath.Walk(*rulesDirectory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml" {
			return nil
		}

		if err := convertFile(path); err != nil {
			errored = true
			fmt.Printf("Failed to convert %s: %v\n", path, err)
		}
		return nil
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if errored {
		os.Exit(1)
	}
}

func convertFile(path string) error {
	ruleContents, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %v", path, err)
	}

	rule, err := sigma.ParseRule(ruleContents)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %v", path, err)
	}

	relPath, _ := filepath.Rel(*rulesDirectory, path)
	outPath := filepath.Join(*outputDirectory, "rules", relPath+".md")
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	section, err := os.Create(filepath.Join(filepath.Dir(outPath), "_index.md"))
	if err != nil {
		return fmt.Errorf("failed to create content section: %v", err)
	}

	err = sectionTemplate.Execute(section, map[string]interface{}{
		"Title": filepath.Base(filepath.Dir(outPath)),
	})
	if err != nil {
		return fmt.Errorf("failed to create content section: %v", err)
	}

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}

	return ruleTemplate.Execute(out, map[string]interface{}{
		"Parsed":   rule,
		"Original": string(ruleContents),
	})
}

var sectionTemplate = template.Must(template.New("sectionTemplate").Parse(`---
title: "{{.Title}}"
---
`))

var ruleTemplate = template.Must(template.New("ruleTemplate").Parse(`---
title: "{{.Parsed.Title}}"
aliases:
  - "/{{.ID}}"
{{with .Parsed.AdditionalFields.tags}}
tags:
{{range .}}  - {{.}}
{{end}}{{end}}
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

## Raw rule
` + "```yaml" + `
{{.Original}}
` + "```" + `
`))
