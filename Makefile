generate:
	rm -rf content && go run github.com/bradleyjkemp/sigmadoc --rules-directory ./sigma/rules --output-directory content --github-repo https://github.com/SigmaHQ/sigma --github-branch master --repo-relative-path rules
