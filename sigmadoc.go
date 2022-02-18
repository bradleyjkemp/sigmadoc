package main

import (
	"embed"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"text/template"

	"github.com/bradleyjkemp/sigma-go"
)

var (
	rulesDirectory  = flag.String("rules-directory", ".", "Directory containing Sigma rules")
	outputDirectory = flag.String("output-directory", "content", "Directory to write converted markdown files to (usually your Hugo content directory)")
	gitHubRepoURL   = flag.String("github-repo", "", "(Optional) GitHub repository URL to include links to edit files.")
	gitHubBranch    = flag.String("github-branch", "main", "(Optional) GitHub branch that your rules are on.")
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
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", path, err)
	}

	switch sigma.InferFileType(contents) {
	case sigma.RuleFile:
		return convertRule(path, contents)

	case sigma.ConfigFile:
		return convertConfig(path, contents)

	default:
		return nil
	}
}

func convertRule(rulePath string, ruleContents []byte) error {
	rule, err := sigma.ParseRule(ruleContents)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", rulePath, err)
	}

	relPath, _ := filepath.Rel(*rulesDirectory, rulePath)
	outPath := filepath.Join(*outputDirectory, "rules", relPath+".md")
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	if err := createSectionFiles(outPath); err != nil {
		return fmt.Errorf("failed to create section files: %w", err)
	}

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}

	params := map[string]interface{}{
		"Parsed":   rule,
		"Time":     getFileCreation(rulePath),
		"Original": string(ruleContents),
	}

	if *gitHubRepoURL != "" {
		params["GitHubEditLink"] = *gitHubRepoURL + "/" + path.Join("edit", *gitHubBranch, relPath)
	}

	return templates.ExecuteTemplate(out, "rule.tmpl.md", params)

}

func convertConfig(configPath string, configContents []byte) error {
	config, err := sigma.ParseConfig(configContents)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", configPath, err)
	}

	relPath, _ := filepath.Rel(*rulesDirectory, configPath)
	outPath := filepath.Join(*outputDirectory, "configs", relPath+".md")
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	if err := createSectionFiles(outPath); err != nil {
		return fmt.Errorf("failed to create section files: %w", err)
	}

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}

	params := map[string]interface{}{
		"Parsed":   config,
		"Time":     getFileCreation(configPath),
		"Original": string(configContents),
	}

	if *gitHubRepoURL != "" {
		params["GitHubEditLink"] = *gitHubRepoURL + "/" + path.Join("edit", *gitHubBranch, relPath)
	}

	return templates.ExecuteTemplate(out, "config.tmpl.md", params)
}

func createSectionFiles(path string) error {
	for dir := filepath.Dir(path); strings.HasPrefix(filepath.Dir(dir), *outputDirectory); dir = filepath.Dir(dir) {
		section, err := os.Create(filepath.Join(dir, "_index.md"))
		if err != nil {
			return err
		}

		err = templates.ExecuteTemplate(section, "section.tmpl.md", map[string]interface{}{
			"Title": filepath.Base(dir),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

var (
	rulesDirIsGitOnce = sync.Once{}
	ruleDirIsGit      bool
)

func getFileCreation(path string) string {
	rulesDirIsGitOnce.Do(func() {
		gitCheck := exec.Command("git", "rev-parse")
		gitCheck.Dir = filepath.Dir(path)
		if gitCheck.Run() == nil {
			ruleDirIsGit = true
		}
	})

	if !ruleDirIsGit {
		// TODO: read creation time from sigma.Rule
		return ""
	}
	cmd := exec.Command("git", "log", "--diff-filter=A", "--follow", "--format=%aD", "-1", "--", filepath.Base(path))
	cmd.Dir = filepath.Dir(path)

	timestamp, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("failed to check timestamp", err, string(timestamp))
		// Oh well, this was best effort anyway
		return ""
	}
	return string(timestamp)
}

//go:embed *.tmpl.md
var templateFiles embed.FS
var templates = template.Must(template.ParseFS(templateFiles, "*"))
