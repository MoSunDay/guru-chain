// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/tools/go/loader"
)

// funcChainConfig holds configuration for func-chain analysis
type funcChainConfig struct {
	maxDepth     int
	skipStdlib   bool
	localOnly    bool   // only analyze functions within the current module
	externalOnly bool   // only analyze functions outside the current module
	modulePath   string // current module path (e.g., "github.com/user/repo")
	cache        *funcChainCache
	lprog        *loader.Program
	visited      map[string]bool
}

// funcChain recursively analyzes the call chain of a function.
func funcChain(q *Query) error {
	// Parse position - check if it's a function name or byte offset
	pos, funcName, err := parseFuncChainPos(q.Pos)
	if err != nil {
		return err
	}

	lconf := loader.Config{Build: q.Build}
	allowErrors(&lconf)

	if _, err := importQueryPackageForFuncChain(pos, &lconf); err != nil {
		return err
	}

	lprog, err := lconf.Load()
	if err != nil {
		return err
	}

	// Find function declaration
	var funcDecl *ast.FuncDecl
	var info *loader.PackageInfo

	if funcName != "" {
		// Find by function name
		funcDecl, info = findFuncByName(lprog, pos, funcName)
		if funcDecl == nil {
			return fmt.Errorf("function %q not found in file", funcName)
		}
	} else {
		// Find by position
		qpos, err := parseQueryPos(lprog, pos, false)
		if err != nil {
			return err
		}
		info = qpos.info
		for _, node := range qpos.path {
			if fd, ok := node.(*ast.FuncDecl); ok {
				funcDecl = fd
				break
			}
		}
	}

	if funcDecl == nil {
		return fmt.Errorf("no function declaration found")
	}

	funcObj := info.Defs[funcDecl.Name]
	if funcObj == nil {
		return fmt.Errorf("cannot find function object for %s", funcDecl.Name.Name)
	}

	// Initialize cache
	cache := newFuncChainCache(*cacheDirFlag)

	// Check cache first
	if cache != nil {
		cacheKey := cache.getCacheKey(lprog.Fset, funcDecl)
		if cached := cache.load(cacheKey); cached != nil {
			// Return cached result as funcChainResult
			q.Output(lprog.Fset, serialToResult(cached))
			return nil
		}
	}

	// Get module path for local/external filtering
	var modulePath string
	if *localOnlyFlag || *externalOnlyFlag {
		// Extract directory from position
		filePath := pos
		if idx := strings.LastIndex(pos, ":#"); idx != -1 {
			filePath = pos[:idx]
		}
		if !filepath.IsAbs(filePath) {
			wd, _ := os.Getwd()
			filePath = filepath.Join(wd, filePath)
		}
		modulePath = getModulePath(filepath.Dir(filePath))
	}

	// Initialize config
	cfg := &funcChainConfig{
		maxDepth:     *depthFlag,
		skipStdlib:   *skipStdlibFlag,
		localOnly:    *localOnlyFlag,
		externalOnly: *externalOnlyFlag,
		modulePath:   modulePath,
		cache:        cache,
		lprog:        lprog,
		visited:      make(map[string]bool),
	}

	result := cfg.analyzeFuncChain(info, funcDecl, funcObj, 0)

	// Save to cache
	if cache != nil {
		cacheKey := cache.getCacheKey(lprog.Fset, funcDecl)
		serialResult := result.toSerial(lprog.Fset)
		cache.save(cacheKey, serialResult)
	}

	q.Output(lprog.Fset, result)
	return nil
}

// isStdlib checks if a package path is a standard library package
func isStdlib(pkgPath string) bool {
	// "command-line-arguments" is a special package name for files loaded directly
	// It should NOT be treated as stdlib
	if pkgPath == "command-line-arguments" {
		return false
	}
	// Empty package path is treated as stdlib (built-in)
	if pkgPath == "" {
		return true
	}
	// golang.org/x/... packages are treated as stdlib-like
	if strings.HasPrefix(pkgPath, "golang.org/x/") {
		return true
	}
	// Standard library packages don't have dots in their path
	return !strings.Contains(pkgPath, ".")
}

// getModulePath returns the module path from go.mod in the given directory or its parents
func getModulePath(dir string) string {
	// Try to find go.mod by walking up the directory tree
	for {
		goModPath := filepath.Join(dir, "go.mod")
		data, err := os.ReadFile(goModPath)
		if err == nil {
			// Parse module path from go.mod
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "module ") {
					return strings.TrimSpace(strings.TrimPrefix(line, "module "))
				}
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// isLocalPackage checks if a package path belongs to the current module
func isLocalPackage(pkgPath, modulePath string) bool {
	if modulePath == "" {
		return false
	}
	// "command-line-arguments" is a special package name used when loading files directly
	// It should be treated as a local package
	if pkgPath == "command-line-arguments" {
		return true
	}
	return pkgPath == modulePath || strings.HasPrefix(pkgPath, modulePath+"/")
}

// analyzeFuncChain recursively analyzes function calls within a function body
func (cfg *funcChainConfig) analyzeFuncChain(info *loader.PackageInfo, funcDecl *ast.FuncDecl, funcObj types.Object, depth int) *funcChainResult {
	funcKey := funcObj.Pkg().Path() + "." + funcObj.Name()
	if funcDecl.Recv != nil {
		// For methods, include the receiver type in the key
		if sig, ok := funcObj.Type().(*types.Signature); ok && sig.Recv() != nil {
			recvTypeName := getReceiverTypeName(sig.Recv().Type())
			funcKey = funcObj.Pkg().Path() + ".(" + recvTypeName + ")." + funcObj.Name()
		}
	}

	// Mark as visited
	cfg.visited[funcKey] = true

	funcType, ok := funcObj.Type().(*types.Signature)
	if !ok {
		return nil
	}

	result := &funcChainResult{
		Name:        funcObj.Name(),
		FullName:    funcKey,
		Params:      formatParams(funcType.Params()),
		Results:     formatResults(funcType.Results()),
		Pos:         funcObj.Pos(),
		Depth:       depth,
		CalledFuncs: make([]*funcChainResult, 0),
	}

	if funcDecl.Body == nil {
		return result
	}

	// Find all function calls in the body
	ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
		callExpr, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		calledFunc := cfg.extractCalledFunc(info, callExpr, depth+1)
		if calledFunc != nil {
			result.CalledFuncs = append(result.CalledFuncs, calledFunc)
		}
		return true
	})

	return result
}

// extractCalledFunc extracts information about a called function
func (cfg *funcChainConfig) extractCalledFunc(info *loader.PackageInfo, call *ast.CallExpr, depth int) *funcChainResult {
	var funcObj types.Object

	switch fun := call.Fun.(type) {
	case *ast.Ident:
		funcObj = info.Uses[fun]
	case *ast.SelectorExpr:
		funcObj = info.Uses[fun.Sel]
	default:
		return nil
	}

	if funcObj == nil {
		return nil
	}

	funcType, ok := funcObj.Type().(*types.Signature)
	if !ok {
		return nil
	}

	var funcKey string
	if funcObj.Pkg() != nil {
		funcKey = funcObj.Pkg().Path() + "." + funcObj.Name()
	} else {
		funcKey = funcObj.Name()
	}

	// Check skip stdlib - completely skip, don't include in output
	if cfg.skipStdlib && funcObj.Pkg() != nil && isStdlib(funcObj.Pkg().Path()) {
		return nil
	}

	// Check local-only: skip external packages - completely skip
	if cfg.localOnly && funcObj.Pkg() != nil {
		pkgPath := funcObj.Pkg().Path()
		if !isLocalPackage(pkgPath, cfg.modulePath) {
			return nil
		}
	}

	// Check external-only: skip local packages - completely skip
	if cfg.externalOnly && funcObj.Pkg() != nil {
		pkgPath := funcObj.Pkg().Path()
		if isLocalPackage(pkgPath, cfg.modulePath) {
			return nil
		}
	}

	// Check max depth
	if depth >= cfg.maxDepth {
		return &funcChainResult{
			Name:        funcObj.Name(),
			FullName:    funcKey,
			Params:      formatParams(funcType.Params()),
			Results:     formatResults(funcType.Results()),
			Pos:         funcObj.Pos(),
			DepthExceed: true,
		}
	}

	// Check if already visited (avoid cycles)
	if cfg.visited[funcKey] {
		return &funcChainResult{
			Name:     funcObj.Name(),
			FullName: funcKey,
			Params:   formatParams(funcType.Params()),
			Results:  formatResults(funcType.Results()),
			Pos:      funcObj.Pos(),
			Cyclic:   true,
		}
	}

	// Check if this is an interface method call
	if recvType, isIface := isInterfaceMethod(info, call); isIface {
		return cfg.handleInterfaceMethodCall(info, call, funcObj, funcType, funcKey, recvType, depth)
	}

	// Find function declaration for recursive analysis
	funcDecl := findFuncDecl(cfg.lprog, funcObj)
	if funcDecl != nil {
		pkgInfo := findPackageInfo(cfg.lprog, funcObj)
		if pkgInfo != nil {
			return cfg.analyzeFuncChain(pkgInfo, funcDecl, funcObj, depth)
		}
	}

	// External function (no source available)
	return &funcChainResult{
		Name:     funcObj.Name(),
		FullName: funcKey,
		Params:   formatParams(funcType.Params()),
		Results:  formatResults(funcType.Results()),
		Pos:      funcObj.Pos(),
	}
}

// handleInterfaceMethodCall handles method calls on interface types by finding all implementations
func (cfg *funcChainConfig) handleInterfaceMethodCall(
	info *loader.PackageInfo,
	call *ast.CallExpr,
	funcObj types.Object,
	funcType *types.Signature,
	funcKey string,
	ifaceType types.Type,
	depth int,
) *funcChainResult {
	methodName := funcObj.Name()
	methodPkg := funcObj.Pkg()

	// Create the base result for the interface method
	result := &funcChainResult{
		Name:        methodName,
		FullName:    funcKey,
		Params:      formatParams(funcType.Params()),
		Results:     formatResults(funcType.Results()),
		Pos:         funcObj.Pos(),
		IsInterface: true,
	}

	// Find all implementations
	implementations := cfg.findInterfaceImplementations(ifaceType)
	if len(implementations) == 0 {
		return result
	}

	// For each implementation, find and analyze the corresponding method
	var implResults []*funcChainResult
	for _, implType := range implementations {
		method := cfg.findMethodOnType(implType, methodName, methodPkg)
		if method == nil {
			continue
		}

		// Apply the same filtering as regular functions
		if method.Pkg() != nil {
			pkgPath := method.Pkg().Path()
			// Check skip stdlib
			if cfg.skipStdlib && isStdlib(pkgPath) {
				continue
			}
			// Check local-only
			if cfg.localOnly && !isLocalPackage(pkgPath, cfg.modulePath) {
				continue
			}
			// Check external-only
			if cfg.externalOnly && isLocalPackage(pkgPath, cfg.modulePath) {
				continue
			}
		}

		// Build the full name for the implementation method
		// Get the receiver type name from the method signature
		recvTypeName := getReceiverTypeName(implType)
		var implFullName string
		if method.Pkg() != nil {
			implFullName = method.Pkg().Path() + ".(" + recvTypeName + ")." + methodName
		} else {
			implFullName = "(" + recvTypeName + ")." + methodName
		}

		// Check max depth for implementation
		if depth >= cfg.maxDepth {
			implResults = append(implResults, &funcChainResult{
				Name:        methodName,
				FullName:    implFullName,
				Params:      formatParams(funcType.Params()),
				Results:     formatResults(funcType.Results()),
				Pos:         method.Pos(),
				DepthExceed: true,
			})
			continue
		}

		// Check if already visited (avoid cycles)
		if cfg.visited[implFullName] {
			implResults = append(implResults, &funcChainResult{
				Name:     methodName,
				FullName: implFullName,
				Params:   formatParams(funcType.Params()),
				Results:  formatResults(funcType.Results()),
				Pos:      method.Pos(),
				Cyclic:   true,
			})
			continue
		}

		// Find and analyze the method declaration
		funcDecl := findFuncDecl(cfg.lprog, method)
		if funcDecl != nil {
			pkgInfo := findPackageInfo(cfg.lprog, method)
			if pkgInfo != nil {
				implResult := cfg.analyzeFuncChain(pkgInfo, funcDecl, method, depth)
				if implResult != nil {
					implResults = append(implResults, implResult)
				}
				continue
			}
		}

		// External implementation (no source available)
		implResults = append(implResults, &funcChainResult{
			Name:     methodName,
			FullName: implFullName,
			Params:   formatParams(funcType.Params()),
			Results:  formatResults(funcType.Results()),
			Pos:      method.Pos(),
		})
	}

	result.Implementations = implResults
	return result
}

// findFuncDecl finds the function declaration for a given function object
func findFuncDecl(lprog *loader.Program, funcObj types.Object) *ast.FuncDecl {
	if !funcObj.Pos().IsValid() {
		return nil
	}

	// Find the file containing this function
	for _, info := range lprog.AllPackages {
		for _, file := range info.Files {
			for _, decl := range file.Decls {
				if fd, ok := decl.(*ast.FuncDecl); ok {
					if fd.Name.Pos() == funcObj.Pos() {
						return fd
					}
				}
			}
		}
	}
	return nil
}

// findPackageInfo finds the package info for a given function object
func findPackageInfo(lprog *loader.Program, funcObj types.Object) *loader.PackageInfo {
	if funcObj.Pkg() == nil {
		return nil
	}
	return lprog.AllPackages[funcObj.Pkg()]
}

// isInterfaceMethod checks if a method is called on an interface type
func isInterfaceMethod(info *loader.PackageInfo, call *ast.CallExpr) (recvType types.Type, isIface bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, false
	}

	// Get the type of the receiver expression (X in X.Method())
	tv, ok := info.Types[sel.X]
	if !ok {
		return nil, false
	}

	recvType = tv.Type
	return recvType, types.IsInterface(recvType)
}

// getReceiverTypeName returns a human-readable name for a receiver type
func getReceiverTypeName(t types.Type) string {
	// Handle pointer types
	if ptr, ok := t.(*types.Pointer); ok {
		return "*" + getReceiverTypeName(ptr.Elem())
	}
	// Handle named types
	if named, ok := t.(*types.Named); ok {
		obj := named.Obj()
		if obj.Pkg() != nil {
			return obj.Name()
		}
		return obj.Name()
	}
	// Fallback to string representation
	return t.String()
}

// findInterfaceImplementations finds all concrete types that implement the given interface
func (cfg *funcChainConfig) findInterfaceImplementations(ifaceType types.Type) []types.Type {
	var implementations []types.Type

	// Iterate over all named types in all loaded packages
	for _, info := range cfg.lprog.AllPackages {
		for _, obj := range info.Defs {
			tn, ok := obj.(*types.TypeName)
			if !ok {
				continue
			}
			named, ok := tn.Type().(*types.Named)
			if !ok {
				continue
			}
			// Skip interfaces
			if types.IsInterface(named) {
				continue
			}

			// Check if this type implements the interface
			if types.AssignableTo(named, ifaceType) {
				implementations = append(implementations, named)
			} else if pT := types.NewPointer(named); types.AssignableTo(pT, ifaceType) {
				implementations = append(implementations, pT)
			}
		}
	}

	return implementations
}

// findMethodOnType finds a method with the given name on the given type
func (cfg *funcChainConfig) findMethodOnType(t types.Type, methodName string, methodPkg *types.Package) *types.Func {
	mset := types.NewMethodSet(t)
	for i := 0; i < mset.Len(); i++ {
		sel := mset.At(i)
		fn, ok := sel.Obj().(*types.Func)
		if !ok {
			continue
		}
		// Match method name and package
		if fn.Name() == methodName {
			// For exported methods, package doesn't matter
			if fn.Exported() || fn.Pkg() == methodPkg {
				return fn
			}
		}
	}
	return nil
}

// formatParams formats the parameters of a function signature
func formatParams(params *types.Tuple) string {
	if params == nil || params.Len() == 0 {
		return "()"
	}
	var parts []string
	for i := 0; i < params.Len(); i++ {
		p := params.At(i)
		if p.Name() != "" {
			parts = append(parts, fmt.Sprintf("%s %s", p.Name(), p.Type().String()))
		} else {
			parts = append(parts, p.Type().String())
		}
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// formatResults formats the results of a function signature
func formatResults(results *types.Tuple) string {
	if results == nil || results.Len() == 0 {
		return ""
	}
	if results.Len() == 1 {
		r := results.At(0)
		if r.Name() == "" {
			return r.Type().String()
		}
		return fmt.Sprintf("(%s %s)", r.Name(), r.Type().String())
	}
	var parts []string
	for i := 0; i < results.Len(); i++ {
		r := results.At(i)
		if r.Name() != "" {
			parts = append(parts, fmt.Sprintf("%s %s", r.Name(), r.Type().String()))
		} else {
			parts = append(parts, r.Type().String())
		}
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// parseFuncChainPos parses a position string and returns the file position and optional function name
// Supports: "file.go:#123" (byte offset) or "file.go:FuncName" or "file.go:(*Type).MethodName"
func parseFuncChainPos(pos string) (string, string, error) {
	// Check if it matches the byte offset pattern: file.go:#123
	if idx := strings.LastIndex(pos, ":#"); idx != -1 {
		return pos, "", nil
	}

	// Check if it matches function name pattern: file.go:FuncName
	if idx := strings.LastIndex(pos, ":"); idx != -1 {
		filePart := pos[:idx]
		funcPart := pos[idx+1:]

		// Validate function name pattern (identifier or (*Type).Method)
		funcNamePattern := regexp.MustCompile(`^(\(\*?[A-Za-z_][A-Za-z0-9_]*\)\.)?[A-Za-z_][A-Za-z0-9_]*$`)
		if funcNamePattern.MatchString(funcPart) {
			// Return position pointing to start of file with function name
			return filePart + ":#1", funcPart, nil
		}
	}

	return pos, "", nil
}

// findFuncByName finds a function declaration by name in the specified file
func findFuncByName(lprog *loader.Program, pos string, funcName string) (*ast.FuncDecl, *loader.PackageInfo) {
	// Extract file path from position
	filePath := pos
	if idx := strings.LastIndex(pos, ":#"); idx != -1 {
		filePath = pos[:idx]
	}

	// Make file path absolute
	if !filepath.IsAbs(filePath) {
		// Try to find in loaded packages
		for _, info := range lprog.AllPackages {
			for _, file := range info.Files {
				fileName := lprog.Fset.Position(file.Pos()).Filename
				if strings.HasSuffix(fileName, filePath) || filepath.Base(fileName) == filepath.Base(filePath) {
					// Search for function in this file
					for _, decl := range file.Decls {
						if fd, ok := decl.(*ast.FuncDecl); ok {
							if matchFuncName(fd, funcName) {
								return fd, info
							}
						}
					}
				}
			}
		}
	}

	return nil, nil
}

// matchFuncName checks if a function declaration matches the given name
func matchFuncName(fd *ast.FuncDecl, name string) bool {
	// Simple function name match
	if fd.Name.Name == name {
		return true
	}

	// Method name match: (*Type).Method or (Type).Method
	if fd.Recv != nil && len(fd.Recv.List) > 0 {
		recvType := exprToString(fd.Recv.List[0].Type)
		methodName := fmt.Sprintf("(%s).%s", recvType, fd.Name.Name)
		if methodName == name {
			return true
		}
	}

	return false
}
