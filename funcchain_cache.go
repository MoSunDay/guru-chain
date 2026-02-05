// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/tools/cmd/guru/serial"
	"golang.org/x/tools/go/loader"
)

// packageCacheMeta stores all function analysis results for a package
type packageCacheMeta struct {
	GitURL   string                       `json:"git_url"`
	CommitID string                       `json:"commit_id"`
	PkgPath  string                       `json:"pkg_path"`
	Funcs    map[string]*serial.FuncChain `json:"funcs"` // key: funcName
}

// funcChainCache manages caching of func-chain analysis results at package level
type funcChainCache struct {
	cacheDir string
}

// newFuncChainCache creates a new cache instance
func newFuncChainCache(cacheDir string) *funcChainCache {
	if cacheDir == "" {
		return nil
	}
	return &funcChainCache{
		cacheDir: cacheDir,
	}
}

// getGitRemoteURL returns the git remote origin URL for a directory
func getGitRemoteURL(dir string) string {
	cmd := exec.Command("git", "-C", dir, "remote", "get-url", "origin")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	url := strings.TrimSpace(string(out))
	// Normalize git URL: remove .git suffix, convert ssh to https format for consistency
	url = strings.TrimSuffix(url, ".git")
	if strings.HasPrefix(url, "git@") {
		// Convert git@github.com:user/repo to github.com/user/repo
		url = strings.TrimPrefix(url, "git@")
		url = strings.Replace(url, ":", "/", 1)
	}
	if strings.HasPrefix(url, "https://") {
		url = strings.TrimPrefix(url, "https://")
	}
	if strings.HasPrefix(url, "http://") {
		url = strings.TrimPrefix(url, "http://")
	}
	return url
}

// getGitCommitID returns the current git commit ID for a directory
func getGitCommitID(dir string) string {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// getPackageGitInfo returns git URL and commit ID for a package path
// For external packages in go mod cache, extracts version from path
func getPackageGitInfo(pkgPath string, filePath string) (gitURL, commitID string) {
	// Get the directory containing the file
	dir := filepath.Dir(filePath)

	// Check if this is in go mod cache (contains @version)
	if strings.Contains(filePath, "@") {
		// External package in module cache: /go/pkg/mod/github.com/user/repo@v1.2.3/...
		// Extract git URL and version from path
		parts := strings.Split(filePath, "@")
		if len(parts) >= 2 {
			// parts[0] might be like /Users/.../go/pkg/mod/github.com/user/repo
			modPath := parts[0]
			// Find the module path part (github.com/user/repo)
			if idx := strings.Index(modPath, "pkg/mod/"); idx != -1 {
				gitURL = modPath[idx+8:] // skip "pkg/mod/"
			}
			// parts[1] is version@... or version/subpath
			version := parts[1]
			if idx := strings.Index(version, "/"); idx != -1 {
				version = version[:idx]
			}
			commitID = version // Use version as commit ID for external deps
		}
		return gitURL, commitID
	}

	// Local package: get actual git info
	gitURL = getGitRemoteURL(dir)
	commitID = getGitCommitID(dir)
	return gitURL, commitID
}

// getCacheKey generates cache key: funcName (including receiver for methods)
func (c *funcChainCache) getCacheKey(funcDecl *ast.FuncDecl) string {
	funcName := funcDecl.Name.Name
	if funcDecl.Recv != nil && len(funcDecl.Recv.List) > 0 {
		recvType := exprToString(funcDecl.Recv.List[0].Type)
		funcName = fmt.Sprintf("(%s).%s", recvType, funcName)
	}
	return funcName
}

// getCachePath returns the full path to the cache meta.json file
// Format: <cache_dir>/<safe_git_url>/<commit_id>/<pkg_path>/meta.json
func (c *funcChainCache) getCachePath(gitURL, commitID, pkgPath string) string {
	// Sanitize components for filesystem
	safeGitURL := strings.ReplaceAll(gitURL, "/", "_")
	safeGitURL = strings.ReplaceAll(safeGitURL, ":", "_")
	safePkgPath := strings.ReplaceAll(pkgPath, "/", "_")
	return filepath.Join(c.cacheDir, safeGitURL, commitID, safePkgPath, "meta.json")
}

// loadPackageCache loads the entire package cache
func (c *funcChainCache) loadPackageCache(gitURL, commitID, pkgPath string) *packageCacheMeta {
	if c == nil || gitURL == "" || commitID == "" {
		return nil
	}
	path := c.getCachePath(gitURL, commitID, pkgPath)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var meta packageCacheMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil
	}
	return &meta
}

// load tries to load a cached result for a specific function
func (c *funcChainCache) load(gitURL, commitID, pkgPath, funcKey string) *serial.FuncChain {
	meta := c.loadPackageCache(gitURL, commitID, pkgPath)
	if meta == nil || meta.Funcs == nil {
		return nil
	}
	return meta.Funcs[funcKey]
}

// save stores a function result in the package cache
func (c *funcChainCache) save(gitURL, commitID, pkgPath, funcKey string, result *serial.FuncChain) error {
	if c == nil || gitURL == "" || commitID == "" {
		return nil
	}

	// Load existing cache or create new
	meta := c.loadPackageCache(gitURL, commitID, pkgPath)
	if meta == nil {
		meta = &packageCacheMeta{
			GitURL:   gitURL,
			CommitID: commitID,
			PkgPath:  pkgPath,
			Funcs:    make(map[string]*serial.FuncChain),
		}
	}

	// Add/update function result
	meta.Funcs[funcKey] = result

	// Write back
	path := c.getCachePath(gitURL, commitID, pkgPath)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// exprToString converts an ast.Expr to string representation
func exprToString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return "*" + exprToString(e.X)
	case *ast.SelectorExpr:
		return exprToString(e.X) + "." + e.Sel.Name
	default:
		return "unknown"
	}
}

// importQueryPackageForFuncChain is similar to importQueryPackage but loads all Go files
// in the directory when the package cannot be found in GOPATH. This ensures that
// function calls to functions in other files of the same package are properly resolved.
func importQueryPackageForFuncChain(pos string, conf *loader.Config) (string, error) {
	fqpos, err := fastQueryPos(conf.Build, pos)
	if err != nil {
		return "", err
	}
	filename := fqpos.fset.File(fqpos.start).Name()

	_, importPath, err := guessImportPath(filename, conf.Build)
	if err != nil {
		// Can't find GOPATH dir.
		// Load all Go files in the directory as a single package
		importPath = "command-line-arguments"
		dir := filepath.Dir(filename)

		// Find all Go files in the directory (excluding test files)
		goFiles, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			goFiles = []string{filename}
		}

		// Filter out test files
		var srcFiles []string
		for _, f := range goFiles {
			base := filepath.Base(f)
			if !strings.HasSuffix(base, "_test.go") {
				srcFiles = append(srcFiles, f)
			}
		}

		if len(srcFiles) == 0 {
			srcFiles = []string{filename}
		}

		conf.CreateFromFilenames(importPath, srcFiles...)
	} else {
		// Check that it's possible to load the queried package.
		cfg2 := *conf.Build
		cfg2.CgoEnabled = false
		bp, err := cfg2.Import(importPath, "", 0)
		if err != nil {
			return "", err
		}

		switch pkgContainsFile(bp, filename) {
		case 'T':
			conf.ImportWithTests(importPath)
		case 'X':
			conf.ImportWithTests(importPath)
			importPath += "_test"
		case 'G':
			conf.Import(importPath)
		default:
			return "", fmt.Errorf("package %q doesn't contain file %s",
				importPath, filename)
		}
	}

	conf.TypeCheckFuncBodies = func(p string) bool { return p == importPath }

	return importPath, nil
}
