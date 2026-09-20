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
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"testing"
)

func TestTheOptedInSC003GateCannotUseTheSkippableTapLookup(t *testing.T) {
	// Most capture specs may be inapplicable on an installation with no Active
	// tap. SC-003 is different: the operator opted into an hour-long release
	// gate whose subject includes availability. It once called productionTap,
	// which skipped before the test's later fatal check could run.
	path := filepath.Join("..", "e2e", "reference_load_test.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	var target *ast.FuncDecl
	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "TestReferenceLoadSC003LossStaysUnderOnePercent" {
			target = fn
			break
		}
	}
	if target == nil {
		t.Fatal("SC-003 acceptance test not found")
	}

	var required, skippable, durationOverride bool
	ast.Inspect(target.Body, func(node ast.Node) bool {
		literal, ok := node.(*ast.BasicLit)
		if ok && literal.Kind == token.STRING {
			value, err := strconv.Unquote(literal.Value)
			if err == nil && value == "TRAWL_E2E_LOAD_WINDOW" {
				durationOverride = true
			}
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch selector.Sel.Name {
		case "requiredProductionTap":
			required = true
		case "productionTap":
			skippable = true
		}
		return true
	})
	if !required || skippable {
		t.Fatalf("SC-003 lookup: required=%v skippable=%v; "+
			"the opted-in gate must use only requiredProductionTap", required, skippable)
	}
	if durationOverride {
		t.Fatal("SC-003 reads TRAWL_E2E_LOAD_WINDOW; the release criterion must always run for one hour")
	}
}
