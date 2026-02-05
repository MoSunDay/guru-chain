// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"go/token"

	"golang.org/x/tools/cmd/guru/serial"
)

// funcChainResult represents the result of a func-chain query
type funcChainResult struct {
	Name            string             // function name
	FullName        string             // full qualified name (package.name)
	Params          string             // parameters
	Results         string             // return values
	Pos             token.Pos          // position of definition
	Depth           int                // call depth
	Cyclic          bool               // true if this is a cyclic reference
	DepthExceed     bool               // true if max depth exceeded
	Skipped         bool               // true if skipped (e.g., stdlib)
	IsInterface     bool               // true if this is an interface method call
	CalledFuncs     []*funcChainResult // called functions
	Implementations []*funcChainResult // interface implementations (when IsInterface is true)
}

func (r *funcChainResult) PrintPlain(printf printfFunc) {
	r.printPlainRecursive(printf, "", true)
}

func (r *funcChainResult) printPlainRecursive(printf printfFunc, indent string, isLast bool) {
	prefix := indent
	if indent != "" {
		if isLast {
			prefix += "└── "
		} else {
			prefix += "├── "
		}
	}

	suffix := ""
	if r.Cyclic {
		suffix = " [CYCLIC]"
	} else if r.DepthExceed {
		suffix = " [MAX_DEPTH]"
	} else if r.Skipped {
		suffix = " [SKIPPED]"
	} else if r.IsInterface {
		suffix = " [INTERFACE]"
	}

	printf(r.Pos, "%s%s%s -> %s%s", prefix, r.Name, r.Params, r.Results, suffix)

	nextIndent := indent
	if indent != "" {
		if isLast {
			nextIndent += "    "
		} else {
			nextIndent += "│   "
		}
	}

	// Print interface implementations
	if r.IsInterface && len(r.Implementations) > 0 {
		for i, impl := range r.Implementations {
			isImplLast := i == len(r.Implementations)-1 && len(r.CalledFuncs) == 0
			impl.printPlainRecursive(printf, nextIndent, isImplLast)
		}
	}

	for i, child := range r.CalledFuncs {
		isChildLast := i == len(r.CalledFuncs)-1
		child.printPlainRecursive(printf, nextIndent, isChildLast)
	}
}

func (r *funcChainResult) JSON(fset *token.FileSet) []byte {
	return toJSON(r.toSerial(fset))
}

func (r *funcChainResult) toSerial(fset *token.FileSet) *serial.FuncChain {
	pos := fset.Position(r.Pos)

	result := &serial.FuncChain{
		Name:        r.Name,
		FullName:    r.FullName,
		Params:      r.Params,
		Results:     r.Results,
		File:        pos.Filename,
		Line:        pos.Line,
		Cyclic:      r.Cyclic,
		DepthExceed: r.DepthExceed,
		Skipped:     r.Skipped,
		IsInterface: r.IsInterface,
	}

	for _, child := range r.CalledFuncs {
		result.CalledFuncs = append(result.CalledFuncs, child.toSerial(fset))
	}

	for _, impl := range r.Implementations {
		result.Implementations = append(result.Implementations, impl.toSerial(fset))
	}

	return result
}

// serialToResult converts a serial.FuncChain back to a funcChainResult (for cache loading)
func serialToResult(s *serial.FuncChain) *funcChainResult {
	result := &funcChainResult{
		Name:            s.Name,
		FullName:        s.FullName,
		Params:          s.Params,
		Results:         s.Results,
		Cyclic:          s.Cyclic,
		DepthExceed:     s.DepthExceed,
		Skipped:         s.Skipped,
		IsInterface:     s.IsInterface,
		CalledFuncs:     make([]*funcChainResult, 0, len(s.CalledFuncs)),
		Implementations: make([]*funcChainResult, 0, len(s.Implementations)),
	}

	for _, child := range s.CalledFuncs {
		result.CalledFuncs = append(result.CalledFuncs, serialToResult(child))
	}

	for _, impl := range s.Implementations {
		result.Implementations = append(result.Implementations, serialToResult(impl))
	}

	return result
}
