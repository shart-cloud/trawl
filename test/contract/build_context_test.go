/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// .dockerignore starts by excluding everything and re-including what the build
// needs. That is the right default, but it means a file the compiler requires
// is absent from the image build unless someone remembered to name it, and
// nothing about adding a //go:embed prompts anyone to.
//
// The observation schema was embedded and not re-included, so every Go image
// failed at compile time:
//
//	internal/observation/schema.go:40:12: pattern observation.schema.json:
//	no matching files found
//
// Locally the build works, because a local build reads the working tree. Only a
// container build sees the ignore rules, so nothing caught it until CI.

var embedDirective = regexp.MustCompile(`//go:embed\s+(.+)`)

// embeddedFiles returns every path a //go:embed names, relative to the repo.
func embeddedFiles(t *testing.T, root string) map[string]string {
	t.Helper()

	found := map[string]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Neither is part of the build context.
			if name := info.Name(); name == ".git" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // G304: walking the repository
		if err != nil {
			return err
		}
		for _, m := range embedDirective.FindAllStringSubmatch(string(data), -1) {
			for _, pattern := range strings.Fields(m[1]) {
				// Patterns are relative to the file's own directory.
				rel, err := filepath.Rel(root, filepath.Join(filepath.Dir(path), pattern))
				if err != nil {
					return err
				}
				found[filepath.ToSlash(rel)] = filepath.ToSlash(strings.TrimPrefix(path, root+"/"))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository: %v", err)
	}
	return found
}

func TestEveryEmbeddedFileSurvivesDockerignore(t *testing.T) {
	root := repoRoot(t)

	data, err := os.ReadFile(filepath.Join(root, ".dockerignore"))
	if err != nil {
		t.Fatalf("reading .dockerignore: %v", err)
	}

	// Only the re-include rules matter: the file excludes everything up front,
	// so a path reaches the build context exactly when some "!" rule names it.
	var reincludes []string
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "!") {
			reincludes = append(reincludes, strings.TrimPrefix(line, "!"))
		}
	}

	embeds := embeddedFiles(t, root)
	if len(embeds) == 0 {
		t.Fatal("found no //go:embed directives, so this test is checking nothing")
	}

	for file, source := range embeds {
		if _, err := os.Stat(filepath.Join(root, file)); err != nil {
			t.Errorf("%s embeds %s, which does not exist", source, file)
			continue
		}

		var covered bool
		for _, rule := range reincludes {
			if rule == file {
				covered = true
				break
			}
			// A glob such as !**/*.go covers the file if it matches the base
			// name under any directory.
			if ok, _ := filepath.Match(rule, file); ok {
				covered = true
				break
			}
			if strings.HasPrefix(rule, "**/") {
				if ok, _ := filepath.Match(strings.TrimPrefix(rule, "**/"), filepath.Base(file)); ok {
					covered = true
					break
				}
			}
		}
		if !covered {
			t.Errorf("%s embeds %s, but .dockerignore does not re-include it; "+
				"every container build of a package importing %s fails at compile time",
				source, file, filepath.Dir(source))
		}
	}
}
