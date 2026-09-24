package analyze

import (
	"fmt"
	"go/token"
	"go/types"
	"runtime/debug"
	"slices"
	"sort"
	"strings"

	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/ssa"
)

const (
	maxSummaryFiles    = 500
	maxSummaryPackages = 64
)

type functionSummary struct {
	edges         map[string]map[string]bool
	references    map[string]map[string]bool
	packageOf     map[string]string
	methods       map[string]map[string]bool
	invokeKeys    map[string]map[string]bool
	addressTaken  map[string]map[string]bool
	dynamicKeys   map[string]map[string]bool
	invokedFields map[string]bool
	invokedParams map[string]map[int]bool
	targetIDs     map[string][]string
	targetSets    map[string]map[string]bool
}

type callbackSummary struct {
	invokedFields map[string]bool
	invokedParams map[string]map[int]bool
}

func sliceCandidates(source string, environment []string, meta *metadata, eligible map[string]bool, targets []symbolTarget) (map[string]bool, *callbackSummary, error) {
	summary := newFunctionSummary(targets)
	for _, batch := range summaryBatches(meta, summaryPackages(meta, eligible)) {
		if err := summary.addBatch(source, environment, batch); err != nil {
			return nil, nil, fmt.Errorf("build function summary: %w", err)
		}
		debug.FreeOSMemory()
	}

	entries := []string{meta.root.PkgPath + ".main", meta.root.PkgPath + ".init"}
	candidates := map[string]bool{meta.root.PkgPath: true}
	for _, target := range targets {
		candidates[target.packagePath] = true
		targetID := target.packagePath + "." + target.symbol
		for mode := range 3 {
			path := summary.shortestPath(entries, targetID, mode)
			if len(path) == 0 {
				continue
			}
			for _, id := range path {
				if eligible[summary.packageOf[id]] || mode == 2 && meta.packages[summary.packageOf[id]] != nil {
					candidates[summary.packageOf[id]] = true
				}
			}
			break
		}
	}
	paths := make([]string, 0, len(candidates))
	for path := range candidates {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return candidates, &callbackSummary{
		invokedFields: summary.invokedFields,
		invokedParams: summary.invokedParams,
	}, nil
}

func summaryPackages(meta *metadata, eligible map[string]bool) map[string]bool {
	result := make(map[string]bool, len(eligible))
	for path := range eligible {
		result[path] = true
		for _, imported := range meta.packages[path].imports {
			if meta.packages[imported] != nil {
				result[imported] = true
			}
		}
	}
	return result
}

func newFunctionSummary(targets []symbolTarget) *functionSummary {
	summary := &functionSummary{
		edges:         make(map[string]map[string]bool),
		references:    make(map[string]map[string]bool),
		packageOf:     make(map[string]string),
		methods:       make(map[string]map[string]bool),
		invokeKeys:    make(map[string]map[string]bool),
		addressTaken:  make(map[string]map[string]bool),
		dynamicKeys:   make(map[string]map[string]bool),
		invokedFields: make(map[string]bool),
		invokedParams: make(map[string]map[int]bool),
		targetIDs:     make(map[string][]string),
		targetSets:    make(map[string]map[string]bool),
	}
	for _, target := range targets {
		id := target.packagePath + "." + target.symbol
		summary.targetIDs[target.packagePath] = append(summary.targetIDs[target.packagePath], id)
		summary.targetSets[target.packagePath] = map[string]bool{target.packagePath: true}
		summary.packageOf[id] = target.packagePath
	}
	return summary
}

func summaryBatches(meta *metadata, candidates map[string]bool) []map[string]bool {
	paths := make([]string, 0, len(candidates))
	for path := range candidates {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	var batches []map[string]bool
	batch := make(map[string]bool)
	files := 0
	for _, path := range paths {
		weight := len(meta.packages[path].pkg.CompiledGoFiles)
		if weight == 0 {
			weight = 1
		}
		if len(batch) > 0 && (len(batch) >= maxSummaryPackages || files+weight > maxSummaryFiles) {
			batches = append(batches, batch)
			batch = make(map[string]bool)
			files = 0
		}
		batch[path] = true
		files += weight
	}
	if len(batch) > 0 {
		batches = append(batches, batch)
	}
	return batches
}

func (s *functionSummary) addBatch(source string, environment []string, candidates map[string]bool) error {
	built, err := buildSSA(source, candidates, environment)
	if err != nil {
		return err
	}
	graph := cha.CallGraph(built.program)
	for fn := range graph.Nodes {
		id, packagePath, ok := summaryFunction(fn)
		if !ok || !candidates[packagePath] {
			continue
		}
		s.packageOf[id] = packagePath
		if fn.Signature != nil && fn.Signature.Recv() != nil {
			key := methodSummaryKey(fn.Name(), fn.Signature)
			addStringSet(s.methods, key, id)
		}
		for _, block := range fn.Blocks {
			for _, instruction := range block.Instrs {
				s.addInstruction(id, fn, instruction)
			}
		}
	}
	return nil
}

func (s *functionSummary) addInstruction(caller string, fn *ssa.Function, instruction ssa.Instruction) {
	if closure, ok := instruction.(*ssa.MakeClosure); ok {
		if fn, ok := closure.Fn.(*ssa.Function); ok {
			s.addFunctionReference(caller, fn)
		}
	}
	var operands [10]*ssa.Value
	values := make([]ssa.Value, 0, len(operands))
	for _, operand := range instruction.Operands(operands[:0]) {
		if operand == nil || *operand == nil {
			continue
		}
		values = append(values, *operand)
		if fn, ok := (*operand).(*ssa.Function); ok {
			s.addFunctionReference(caller, fn)
		}
	}
	if value, ok := instruction.(ssa.Value); ok && strings.Contains(types.TypeString(value.Type(), packageQualifier), "unsafe.Pointer") {
		s.addTargetValueEdges(caller, values)
	}

	call, ok := instruction.(ssa.CallInstruction)
	if !ok {
		return
	}
	common := call.Common()
	if callee := common.StaticCallee(); callee != nil {
		s.addFunctionEdge(caller, callee)
		packagePath, _ := functionName(callee)
		if packagePath == "reflect" || packagePath == "unsafe" {
			s.addTargetValueEdges(caller, append([]ssa.Value{common.Value}, common.Args...))
		}
		return
	}
	if common.IsInvoke() && common.Method != nil {
		key := methodSummaryKey(common.Method.Name(), common.Signature())
		addStringSet(s.invokeKeys, caller, key)
		return
	}
	if _, ok := common.Value.(*ssa.Builtin); ok {
		return
	}
	for key := range calledFieldSummaryKeys(common.Value, make(map[ssa.Value]bool)) {
		s.invokedFields[key] = true
	}
	for index := range calledParameterIndexes(common.Value, fn.Params, make(map[ssa.Value]bool)) {
		addIntSet(s.invokedParams, caller, index)
	}
	key := signatureSummaryKey(common.Signature())
	addStringSet(s.dynamicKeys, caller, key)
}

func calledParameterIndexes(value ssa.Value, params []*ssa.Parameter, seen map[ssa.Value]bool) map[int]bool {
	indexes := make(map[int]bool)
	addCalledParameterIndexes(value, params, seen, indexes)
	return indexes
}

func addCalledParameterIndexes(value ssa.Value, params []*ssa.Parameter, seen map[ssa.Value]bool, indexes map[int]bool) {
	if value == nil || seen[value] {
		return
	}
	seen[value] = true
	switch value := value.(type) {
	case *ssa.Parameter:
		for index, param := range params {
			if value == param {
				indexes[index] = true
				return
			}
		}
	case *ssa.MakeInterface:
		addCalledParameterIndexes(value.X, params, seen, indexes)
	case *ssa.ChangeInterface:
		addCalledParameterIndexes(value.X, params, seen, indexes)
	case *ssa.ChangeType:
		addCalledParameterIndexes(value.X, params, seen, indexes)
	case *ssa.Convert:
		addCalledParameterIndexes(value.X, params, seen, indexes)
	case *ssa.Phi:
		for _, edge := range value.Edges {
			addCalledParameterIndexes(edge, params, seen, indexes)
		}
	}
}

func calledFieldSummaryKeys(value ssa.Value, seen map[ssa.Value]bool) map[string]bool {
	keys := make(map[string]bool)
	addCalledFieldSummaryKeys(value, seen, keys)
	return keys
}

func addCalledFieldSummaryKeys(value ssa.Value, seen map[ssa.Value]bool, keys map[string]bool) {
	if value == nil || seen[value] {
		return
	}
	seen[value] = true
	switch value := value.(type) {
	case *ssa.Field:
		if key := fieldValueSummaryKey(value.X, value.Field); key != "" {
			keys[key] = true
		}
	case *ssa.UnOp:
		if value.Op == token.MUL {
			if field, ok := value.X.(*ssa.FieldAddr); ok {
				if key := fieldSummaryKey(field); key != "" {
					keys[key] = true
				}
			}
		}
	case *ssa.MakeInterface:
		addCalledFieldSummaryKeys(value.X, seen, keys)
	case *ssa.ChangeInterface:
		addCalledFieldSummaryKeys(value.X, seen, keys)
	case *ssa.ChangeType:
		addCalledFieldSummaryKeys(value.X, seen, keys)
	case *ssa.Convert:
		addCalledFieldSummaryKeys(value.X, seen, keys)
	case *ssa.Phi:
		for _, edge := range value.Edges {
			addCalledFieldSummaryKeys(edge, seen, keys)
		}
	}
}

func fieldSummaryKey(field *ssa.FieldAddr) string {
	return fieldValueSummaryKey(field.X, field.Field)
}

func fieldValueSummaryKey(value ssa.Value, fieldIndex int) string {
	typeKey := namedTypeKey(value.Type(), nil)
	if typeKey == "" {
		return ""
	}
	valueType := types.Unalias(value.Type())
	if pointer, ok := valueType.(*types.Pointer); ok {
		valueType = types.Unalias(pointer.Elem())
	}
	named, ok := valueType.(*types.Named)
	if !ok {
		return ""
	}
	structure, ok := named.Underlying().(*types.Struct)
	if !ok || fieldIndex < 0 || fieldIndex >= structure.NumFields() {
		return ""
	}
	member := structure.Field(fieldIndex)
	if _, ok := types.Unalias(member.Type()).Underlying().(*types.Signature); !ok {
		return ""
	}
	return typeKey + "\x00" + member.Name()
}

func (s *functionSummary) addFunctionEdge(caller string, callee *ssa.Function) {
	id, packagePath, ok := summaryFunction(callee)
	if !ok {
		return
	}
	s.packageOf[id] = packagePath
	addStringEdge(s.edges, caller, id)
}

func (s *functionSummary) addFunctionReference(caller string, fn *ssa.Function) {
	id, packagePath, ok := summaryFunction(fn)
	if !ok {
		return
	}
	s.packageOf[id] = packagePath
	addStringEdge(s.references, caller, id)
	key := signatureSummaryKey(fn.Signature)
	addStringSet(s.addressTaken, key, id)
}

func (s *functionSummary) addTargetValueEdges(caller string, values []ssa.Value) {
	for packagePath, targetSet := range s.targetSets {
		for _, value := range values {
			if value != nil && valueContainsPackageType(value, targetSet) {
				for _, target := range s.targetIDs[packagePath] {
					addStringEdge(s.references, caller, target)
				}
				break
			}
		}
	}
}

func (s *functionSummary) shortestPath(starts []string, target string, mode int) []string {
	seen := make(map[string]bool)
	previous := make(map[string]string)
	queue := append([]string(nil), starts...)
	for _, start := range starts {
		seen[start] = true
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current == target {
			return reconstructSummaryPath(previous, current)
		}
		next := make(map[string]bool)
		for id := range s.edges[current] {
			next[id] = true
		}
		if mode >= 1 {
			for id := range s.references[current] {
				next[id] = true
			}
		}
		if mode >= 2 {
			for key := range s.invokeKeys[current] {
				for id := range s.methods[key] {
					next[id] = true
				}
			}
			for key := range s.dynamicKeys[current] {
				for id := range s.addressTaken[key] {
					next[id] = true
				}
			}
		}
		ids := make([]string, 0, len(next))
		for id := range next {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if seen[id] {
				continue
			}
			seen[id] = true
			previous[id] = current
			queue = append(queue, id)
		}
	}
	return nil
}

func reconstructSummaryPath(previous map[string]string, last string) []string {
	path := []string{last}
	for previous[last] != "" {
		last = previous[last]
		path = append(path, last)
	}
	slices.Reverse(path)
	return path
}

func summaryFunction(fn *ssa.Function) (string, string, bool) {
	packagePath, symbol := functionName(fn)
	if packagePath == "" || symbol == "" {
		return "", "", false
	}
	return packagePath + "." + symbol, packagePath, true
}

func methodSummaryKey(name string, signature *types.Signature) string {
	return name + "\x00" + signatureSummaryKey(signature)
}

func signatureSummaryKey(signature *types.Signature) string {
	if signature == nil {
		return ""
	}
	return types.TypeString(signature, packageQualifier)
}

func packageQualifier(pkg *types.Package) string {
	if pkg == nil {
		return ""
	}
	return pkg.Path()
}

func addStringEdge(graph map[string]map[string]bool, from, to string) {
	if graph[from] == nil {
		graph[from] = make(map[string]bool)
	}
	graph[from][to] = true
}

func addStringSet(index map[string]map[string]bool, key, value string) {
	if key == "" {
		return
	}
	if index[key] == nil {
		index[key] = make(map[string]bool)
	}
	index[key][value] = true
}

func addIntSet(index map[string]map[int]bool, key string, value int) {
	if key == "" {
		return
	}
	if index[key] == nil {
		index[key] = make(map[int]bool)
	}
	index[key][value] = true
}
