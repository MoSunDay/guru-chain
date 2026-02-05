// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/printer"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/tools/cmd/guru/serial"
)

// funcChainCache manages caching of func-chain analysis results
type funcChainCache struct {
	cacheDir string
	repoRoot string
}

// newFuncChainCache creates a new cache instance
func newFuncChainCache(cacheDir string) *funcChainCache {
	if cacheDir == "" {
		return nil
	}
	repoRoot := getRepoRoot()
	return &funcChainCache{
		cacheDir: cacheDir,
		repoRoot: repoRoot,
	}
}

// getRepoRoot returns the git repository root or current directory
func getRepoRoot() string {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		wd, _ := os.Getwd()
		return wd
	}
	return strings.TrimSpace(string(out))
}

// getCacheKey generates a cache key based on repo + file + funcName + content MD5
func (c *funcChainCache) getCacheKey(fset *token.FileSet, funcDecl *ast.FuncDecl) string {
	// Get file path relative to repo root
	pos := fset.Position(funcDecl.Pos())
	relPath, err := filepath.Rel(c.repoRoot, pos.Filename)
	if err != nil {
		relPath = pos.Filename
	}

	// Get function name (including receiver for methods)
	funcName := funcDecl.Name.Name
	if funcDecl.Recv != nil && len(funcDecl.Recv.List) > 0 {
		recvType := exprToString(funcDecl.Recv.List[0].Type)
		funcName = fmt.Sprintf("(%s).%s", recvType, funcName)
	}

	// Calculate MD5 of function body
	bodyHash := ""
	if funcDecl.Body != nil {
		var buf strings.Builder
		printer.Fprint(&buf, fset, funcDecl.Body)
		hash := md5.Sum([]byte(buf.String()))
		bodyHash = hex.EncodeToString(hash[:])
	}

	// Build cache key
	repoName := filepath.Base(c.repoRoot)
	return fmt.Sprintf("%s/%s/%s/%s", repoName, relPath, funcName, bodyHash)
}

// getCachePath returns the full path to the cache file
func (c *funcChainCache) getCachePath(key string) string {
	// Sanitize the key for filesystem
	safeKey := strings.ReplaceAll(key, "/", "_")
	safeKey = strings.ReplaceAll(safeKey, "(", "_")
	safeKey = strings.ReplaceAll(safeKey, ")", "_")
	safeKey = strings.ReplaceAll(safeKey, "*", "ptr_")
	return filepath.Join(c.cacheDir, safeKey+".json")
}

// load tries to load a cached result
func (c *funcChainCache) load(key string) *serial.FuncChain {
	if c == nil {
		return nil
	}
	path := c.getCachePath(key)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var result serial.FuncChain
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	return &result
}

// save stores a result in the cache
func (c *funcChainCache) save(key string, result *serial.FuncChain) error {
	if c == nil {
		return nil
	}
	path := c.getCachePath(key)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(result, "", "  ")
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
