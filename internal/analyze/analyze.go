package analyze

import (
	"context"
	"errors"
	"fmt"
	"go/token"
	"go/types"
	"os/exec"
	"slices"
	"sort"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"

	"github.com/samuelvl/govulnreach/internal/advisory"
)

type Options struct {
	Source      string
	Package     string
	environment []string
}

type Product struct {
	Name    string
	Version string
}

type Dependency struct {
	Module  string
	Version string
}

type Finding struct {
	Level          string
	Module         string
	Version        string
	Package        string
	Symbol         string
	Outcome        string
	Detail         string
	DependencyPath []string
	CallPath       []string
}

type Result struct {
	Product       Product
	Dependencies  []Dependency
	Findings      []Finding
	Justification string
	Status        string
	Reachability  string
}

type packageInfo struct {
	pkg     *packages.Package
	imports []string
}

type metadata struct {
	root      *packages.Package
	packages  map[string]*packageInfo
	goVersion string
}

type symbolTarget struct {
	packagePath string
	symbol      string
	finding     int
}

const (
	_outcomeAbsent      = "absent"
	_outcomeFixed       = "fixed"
	_outcomeModule      = "module_present"
	_outcomePackage     = "package_reachable"
	_outcomeReachable   = "reachable"
	_outcomeUnreachable = "unreachable"
	_outcomeUnknown     = "unknown"
)

func Run(options Options, adv *advisory.Advisory) (*Result, error) {
	var err error
	if options.environment == nil {
		options.environment, err = analysisEnvironment(options.Source)
		if err != nil {
			return nil, err
		}
	}
	meta, err := loadMetadata(options)
	if err != nil {
		return nil, err
	}
	result := &Result{Product: product(meta.root)}
	targets := make([]symbolTarget, 0)
	targetPackages := make(map[string]bool)

	for _, affected := range adv.Affected {
		if affected.Module == "stdlib" && meta.goVersion == "" {
			meta.goVersion, err = loadGoVersion(options.Source, options.environment)
			if err != nil {
				return nil, err
			}
		}
		modulePackages := packagesForModule(meta, affected.Module)
		if len(modulePackages) == 0 {
			appendAbsentFindings(result, meta.root.PkgPath, affected)
			continue
		}

		version := moduleVersion(modulePackages[0].Module)
		if affected.Module == "stdlib" {
			version = meta.goVersion
		}
		versionKnown := version != ""
		affectedRangeKnown := versionKnown || len(affected.Ranges) == 0
		if versionKnown {
			vulnerable, rangeErr := affected.ContainsVersion(version)
			if rangeErr != nil {
				return nil, fmt.Errorf("module %s: %w", affected.Module, rangeErr)
			}
			if !vulnerable {
				result.Findings = append(result.Findings, Finding{
					Level: "module", Module: affected.Module, Version: version, Outcome: _outcomeFixed,
					Detail:         fmt.Sprintf("resolved module version %s is outside the affected range", version),
					DependencyPath: shortestModulePath(meta, modulePackages),
				})
				continue
			}
		}

		if len(affected.Imports) == 0 {
			for _, pkg := range modulePackages {
				outcome := _outcomeModule
				detail := "affected module is present but the advisory has no package or symbol information"
				if !affectedRangeKnown {
					outcome = _outcomeUnknown
					detail = "replacement module version is unknown and the advisory has no package or symbol information"
				}
				result.Findings = append(result.Findings, Finding{
					Level: "module", Module: affected.Module, Version: version, Package: pkg.PkgPath,
					Outcome: outcome, Detail: detail,
					DependencyPath: shortestPath(meta, pkg.PkgPath),
				})
			}
			continue
		}

		for _, affectedImport := range affected.Imports {
			pkg := meta.packages[affectedImport.Path]
			if pkg == nil || packageModule(pkg.pkg) != affected.Module {
				result.Findings = append(result.Findings, Finding{
					Level: "package", Module: affected.Module, Version: version, Package: affectedImport.Path,
					Outcome: _outcomeAbsent, Detail: "affected package is not present in the selected dependency graph",
					DependencyPath: []string{meta.root.PkgPath, "(absent) " + affectedImport.Path},
				})
				continue
			}
			path := shortestPath(meta, affectedImport.Path)
			if len(affectedImport.Symbols) == 0 {
				outcome := _outcomePackage
				detail := "affected package is present but the advisory has no symbols"
				if !affectedRangeKnown {
					outcome = _outcomeUnknown
					detail = "replacement module version is unknown and the advisory has no symbols"
				}
				result.Findings = append(result.Findings, Finding{
					Level: "package", Module: affected.Module, Version: version, Package: affectedImport.Path,
					Outcome: outcome, Detail: detail,
					DependencyPath: path,
				})
				continue
			}
			for _, symbol := range affectedImport.Symbols {
				finding := Finding{
					Level: "symbol", Module: affected.Module, Version: version, Package: affectedImport.Path,
					Symbol: symbol, DependencyPath: path,
				}
				result.Findings = append(result.Findings, finding)
				targets = append(targets, symbolTarget{
					packagePath: affectedImport.Path, symbol: symbol,
					finding: len(result.Findings) - 1,
				})
				targetPackages[affectedImport.Path] = true
			}
		}
	}

	if len(targets) > 0 {
		paths, dynamic, analyzeErr := analyzeSymbols(options, meta, targetPackages, targets)
		if analyzeErr != nil {
			return nil, analyzeErr
		}
		for _, target := range targets {
			finding := &result.Findings[target.finding]
			key := target.packagePath + "\x00" + target.symbol
			if path := paths[key]; len(path) > 0 {
				finding.Outcome = _outcomeReachable
				finding.Detail = "vulnerable symbol is statically reachable"
				finding.CallPath = path
				continue
			}
			if dynamic[target.packagePath] {
				finding.Outcome = _outcomeUnknown
				finding.Detail = "symbol reachability could not be disproved across a dynamic, reflection, or unsafe boundary"
				continue
			}
			finding.Outcome = _outcomeUnreachable
			finding.Detail = "vulnerable symbol is not statically reachable from the selected main package"
		}
	}

	result.Dependencies = dependencies(meta, result.Findings)
	finalize(result)
	sortResult(result)
	return result, nil
}

func appendAbsentFindings(result *Result, root string, affected advisory.Affected) {
	if len(affected.Imports) == 0 {
		result.Findings = append(result.Findings, Finding{
			Level: "module", Module: affected.Module, Outcome: _outcomeAbsent,
			Detail:         "affected module is not present in the selected main package dependency graph",
			DependencyPath: []string{root, "(absent) " + affected.Module},
		})
		return
	}
	for _, affectedImport := range affected.Imports {
		if len(affectedImport.Symbols) == 0 {
			result.Findings = append(result.Findings, Finding{
				Level: "package", Module: affected.Module, Package: affectedImport.Path, Outcome: _outcomeAbsent,
				Detail:         "affected package is not present in the selected dependency graph",
				DependencyPath: []string{root, "(absent) " + affectedImport.Path},
			})
			continue
		}
		for _, symbol := range affectedImport.Symbols {
			result.Findings = append(result.Findings, Finding{
				Level: "symbol", Module: affected.Module, Package: affectedImport.Path, Symbol: symbol,
				Outcome: _outcomeAbsent, Detail: "affected package is not present in the selected dependency graph",
				DependencyPath: []string{root, "(absent) " + affectedImport.Path},
			})
		}
	}
}

func loadMetadata(options Options) (*metadata, error) {
	mode := packages.NeedName | packages.NeedFiles | packages.NeedImports | packages.NeedDeps | packages.NeedModule
	loaded, err := packages.Load(&packages.Config{
		Mode: mode, Dir: options.Source, Tests: false, BuildFlags: []string{"-p=1"}, Env: options.environment,
	}, options.Package)
	if err != nil {
		return nil, fmt.Errorf("load package metadata: %w", err)
	}
	if err := packageErrors(loaded); err != nil {
		return nil, fmt.Errorf("load package metadata: %w", err)
	}
	if len(loaded) != 1 {
		return nil, fmt.Errorf("package pattern %q resolved to %d packages; want exactly one", options.Package, len(loaded))
	}
	if loaded[0].Name != "main" {
		return nil, fmt.Errorf("package pattern %q resolved to %s, not a main package", options.Package, loaded[0].PkgPath)
	}

	meta := &metadata{root: loaded[0], packages: make(map[string]*packageInfo)}
	packages.Visit(loaded, nil, func(pkg *packages.Package) {
		imports := make([]string, 0, len(pkg.Imports))
		for _, imported := range pkg.Imports {
			imports = append(imports, imported.PkgPath)
		}
		sort.Strings(imports)
		meta.packages[pkg.PkgPath] = &packageInfo{pkg: pkg, imports: imports}
	})
	return meta, nil
}

func packageErrors(pkgs []*packages.Package) error {
	var messages []string
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		for _, pkgErr := range pkg.Errors {
			messages = append(messages, pkgErr.Error())
		}
	})
	if len(messages) == 0 {
		return nil
	}
	sort.Strings(messages)
	return errors.New(strings.Join(messages, "; "))
}

func loadGoVersion(source string, environment []string) (string, error) {
	command := exec.CommandContext(context.Background(), "go", "env", "GOVERSION")
	command.Dir = source
	command.Env = environment
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("load Go version: %w: %s", err, strings.TrimSpace(string(output)))
	}
	version := strings.TrimSpace(string(output))
	if !strings.HasPrefix(version, "go") {
		return "", fmt.Errorf("load Go version: unexpected GOVERSION %q", version)
	}
	return "v" + strings.TrimPrefix(version, "go"), nil
}

func product(root *packages.Package) Product {
	name := root.PkgPath
	version := ""
	if root.Module != nil {
		name = root.Module.Path
		version = moduleVersion(root.Module)
	}
	return Product{Name: name, Version: version}
}

func packagesForModule(meta *metadata, modulePath string) []*packages.Package {
	result := make([]*packages.Package, 0)
	for _, info := range meta.packages {
		if packageModule(info.pkg) == modulePath {
			result = append(result, info.pkg)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].PkgPath < result[j].PkgPath })
	return result
}

func packageModule(pkg *packages.Package) string {
	if pkg.Module == nil {
		return "stdlib"
	}
	return pkg.Module.Path
}

func moduleVersion(module *packages.Module) string {
	if module == nil {
		return ""
	}
	if module.Replace == nil {
		return module.Version
	}
	if module.Replace.Path == module.Path && module.Replace.Version != "" {
		return module.Replace.Version
	}
	return ""
}

func shortestModulePath(meta *metadata, pkgs []*packages.Package) []string {
	var best []string
	for _, pkg := range pkgs {
		path := shortestPath(meta, pkg.PkgPath)
		if len(path) > 0 && (len(best) == 0 || len(path) < len(best) || len(path) == len(best) && strings.Join(path, "\x00") < strings.Join(best, "\x00")) {
			best = path
		}
	}
	return best
}

func shortestPath(meta *metadata, target string) []string {
	if meta.root.PkgPath == target {
		return []string{target}
	}
	queue := []string{meta.root.PkgPath}
	previous := map[string]string{meta.root.PkgPath: ""}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		info := meta.packages[current]
		if info == nil {
			continue
		}
		for _, next := range info.imports {
			if _, seen := previous[next]; seen {
				continue
			}
			previous[next] = current
			if next == target {
				return reconstructStrings(previous, target)
			}
			queue = append(queue, next)
		}
	}
	return nil
}

func reconstructStrings(previous map[string]string, last string) []string {
	path := []string{last}
	for previous[last] != "" {
		last = previous[last]
		path = append(path, last)
	}
	slices.Reverse(path)
	return path
}

func candidatePackages(meta *metadata, targets map[string]bool) map[string]bool {
	reverse := make(map[string][]string)
	for path, info := range meta.packages {
		for _, imported := range info.imports {
			reverse[imported] = append(reverse[imported], path)
		}
	}
	result := make(map[string]bool)
	queue := make([]string, 0, len(targets))
	for target := range targets {
		result[target] = true
		queue = append(queue, target)
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, importer := range reverse[current] {
			if result[importer] {
				continue
			}
			result[importer] = true
			queue = append(queue, importer)
		}
	}
	return result
}

type ssaProgram struct {
	program  *ssa.Program
	packages map[string]*ssa.Package
}

func analyzeSymbols(options Options, meta *metadata, targetPackages map[string]bool, targets []symbolTarget) (map[string][]string, map[string]bool, error) {
	eligible := candidatePackages(meta, targetPackages)
	candidates, callbacks, err := sliceCandidates(options.Source, options.environment, meta, eligible, targets)
	if err != nil {
		return nil, nil, err
	}
	built, err := buildSSA(options.Source, candidates, options.environment)
	if err != nil {
		return nil, nil, err
	}

	entries, err := entryFunctions(built, meta.root.PkgPath)
	if err != nil {
		return nil, nil, err
	}
	chaGraph := cha.CallGraph(built.program)
	addGlobalFunctionEdges(chaGraph)
	chaReachable, _ := reachableFunctions(chaGraph, entries)
	analysisFunctions := expandSummaryCallbacks(chaGraph, chaReachable, callbacks, targetPackages)
	refined := vta.CallGraph(analysisFunctions, chaGraph)
	addGlobalFunctionEdges(refined)
	refined = vta.CallGraph(analysisFunctions, refined)
	addGlobalFunctionEdges(refined)
	addSummaryCallbackEdges(refined, callbacks, targetPackages)
	reachable, previous := reachableFunctions(refined, entries)
	dynamic := unresolvedDynamic(reachable, refined, chaGraph, targetPackages)

	paths := make(map[string][]string)
	for fn := range reachable {
		pkgPath, symbol := functionName(fn)
		if !targetPackages[pkgPath] || symbol == "" {
			continue
		}
		key := pkgPath + "\x00" + symbol
		path := functionPath(previous, fn)
		if len(path) == 0 {
			continue
		}
		if old := paths[key]; len(old) == 0 || len(path) < len(old) || len(path) == len(old) && strings.Join(path, "\x00") < strings.Join(old, "\x00") {
			paths[key] = path
		}
	}
	addSummaryCallbackEdges(chaGraph, callbacks, targetPackages)
	chaReachable, chaPrevious := reachableFunctions(chaGraph, entries)
	interfaceTypes := interfaceBoundaryTypes(reachable, targetPackages)
	for fn := range chaReachable {
		if !interfaceTypes[receiverTypeKey(fn)] {
			continue
		}
		pkgPath, symbol := functionName(fn)
		if !targetPackages[pkgPath] || symbol == "" {
			continue
		}
		key := pkgPath + "\x00" + symbol
		path := functionPath(chaPrevious, fn)
		if old := paths[key]; len(path) > 0 && (len(old) == 0 || len(path) < len(old) || len(path) == len(old) && strings.Join(path, "\x00") < strings.Join(old, "\x00")) {
			paths[key] = path
		}
	}
	return paths, dynamic, nil
}

func interfaceBoundaryTypes(reachable map[*ssa.Function]bool, targets map[string]bool) map[string]bool {
	result := make(map[string]bool)
	for fn := range reachable {
		for _, block := range fn.Blocks {
			for _, instruction := range block.Instrs {
				call, ok := instruction.(ssa.CallInstruction)
				if !ok {
					continue
				}
				callee := call.Common().StaticCallee()
				if callee == nil || !acceptsInterface(callee.Signature) {
					continue
				}
				for _, argument := range call.Common().Args {
					if key := valueTypeKey(argument, targets); key != "" {
						result[key] = true
					}
				}
			}
		}
	}
	return result
}

func valueTypeKey(value ssa.Value, targets map[string]bool) string {
	valueType := value.Type()
	if makeInterface, ok := value.(*ssa.MakeInterface); ok {
		valueType = makeInterface.X.Type()
	}
	return namedTypeKey(valueType, targets)
}

func receiverTypeKey(fn *ssa.Function) string {
	if fn == nil || fn.Signature == nil || fn.Signature.Recv() == nil {
		return ""
	}
	return namedTypeKey(fn.Signature.Recv().Type(), nil)
}

func namedTypeKey(valueType types.Type, targets map[string]bool) string {
	valueType = types.Unalias(valueType)
	if pointer, ok := valueType.(*types.Pointer); ok {
		valueType = types.Unalias(pointer.Elem())
	}
	named, ok := valueType.(*types.Named)
	if !ok || named.Obj().Pkg() == nil || targets != nil && !targets[named.Obj().Pkg().Path()] {
		return ""
	}
	return named.Obj().Pkg().Path() + "\x00" + named.Obj().Name()
}

func buildSSA(source string, candidates map[string]bool, environment []string) (*ssaProgram, error) {
	patterns := make([]string, 0, len(candidates))
	for path := range candidates {
		patterns = append(patterns, path)
	}
	sort.Strings(patterns)
	fset := token.NewFileSet()
	mode := packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
		packages.NeedImports | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo |
		packages.NeedTypesSizes | packages.NeedModule
	loaded, err := packages.Load(&packages.Config{
		Mode: mode, Dir: source, Tests: false, Fset: fset, BuildFlags: []string{"-p=1"},
		Env: environment,
	}, patterns...)
	if err != nil {
		return nil, fmt.Errorf("load partial source: %w", err)
	}
	if err := packageErrors(loaded); err != nil {
		return nil, fmt.Errorf("load partial source: %w", err)
	}
	sourcePackages := make(map[string]*packages.Package, len(loaded))
	for _, pkg := range loaded {
		if candidates[pkg.PkgPath] {
			sourcePackages[pkg.PkgPath] = pkg
		}
	}
	if len(sourcePackages) != len(candidates) {
		return nil, fmt.Errorf("load partial source: resolved %d of %d candidate packages", len(sourcePackages), len(candidates))
	}

	program := ssa.NewProgram(fset, ssa.InstantiateGenerics)
	created := make(map[*types.Package]bool)
	sourceTypes := make(map[*types.Package]bool, len(sourcePackages))
	for _, pkg := range sourcePackages {
		sourceTypes[pkg.Types] = true
	}
	for _, path := range patterns {
		pkg := sourcePackages[path]
		for _, imported := range pkg.Types.Imports() {
			if sourceTypes[imported] || created[imported] {
				continue
			}
			program.CreatePackage(imported, nil, nil, true)
			created[imported] = true
		}
	}
	ssaPackages := make(map[string]*ssa.Package, len(sourcePackages))
	for _, path := range patterns {
		pkg := sourcePackages[path]
		ssaPackages[path] = program.CreatePackage(pkg.Types, pkg.Syntax, pkg.TypesInfo, true)
		created[pkg.Types] = true
	}
	program.Build()
	return &ssaProgram{program: program, packages: ssaPackages}, nil
}

func entryFunctions(program *ssaProgram, rootPath string) ([]*ssa.Function, error) {
	root := program.packages[rootPath]
	if root == nil {
		return nil, fmt.Errorf("partial SSA does not contain selected main package %s", rootPath)
	}
	mainFunction := root.Func("main")
	initFunction := root.Func("init")
	if mainFunction == nil || initFunction == nil {
		return nil, fmt.Errorf("selected package %s has no main or initialization function", rootPath)
	}
	return []*ssa.Function{mainFunction, initFunction}, nil
}

func reachableFunctions(graph *callgraph.Graph, entries []*ssa.Function) (map[*ssa.Function]bool, map[*ssa.Function]*ssa.Function) {
	reachable := make(map[*ssa.Function]bool)
	previous := make(map[*ssa.Function]*ssa.Function)
	queue := slices.Clone(entries)
	for _, entry := range entries {
		reachable[entry] = true
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		node := graph.Nodes[current]
		if node == nil {
			continue
		}
		edges := slices.Clone(node.Out)
		sort.Slice(edges, func(i, j int) bool { return functionID(edges[i].Callee.Func) < functionID(edges[j].Callee.Func) })
		for _, edge := range edges {
			next := edge.Callee.Func
			if next == nil || reachable[next] {
				continue
			}
			reachable[next] = true
			previous[next] = current
			queue = append(queue, next)
		}
	}
	return reachable, previous
}

func expandSummaryCallbacks(graph *callgraph.Graph, reachable map[*ssa.Function]bool, summary *callbackSummary, targets map[string]bool) map[*ssa.Function]bool {
	for {
		callbacks := storedCallbackFunctions(reachable, summary.invokedFields, targets)
		for callback := range passedCallbackFunctions(reachable, summary.invokedParams, targets) {
			callbacks[callback] = true
		}
		entries := make([]*ssa.Function, 0, len(callbacks))
		for callback := range callbacks {
			if !reachable[callback] {
				entries = append(entries, callback)
			}
		}
		if len(entries) == 0 {
			return reachable
		}
		callbackReachable, _ := reachableFunctions(graph, entries)
		for fn := range callbackReachable {
			reachable[fn] = true
		}
	}
}

func addSummaryCallbackEdges(graph *callgraph.Graph, summary *callbackSummary, targets map[string]bool) {
	addStoredCallbackEdges(graph, summary.invokedFields, targets)
	addPassedCallbackEdges(graph, summary.invokedParams, targets)
}

func addStoredCallbackEdges(graph *callgraph.Graph, invokedFields, targets map[string]bool) {
	type pendingEdge struct {
		caller *callgraph.Node
		callee *ssa.Function
	}
	var pending []pendingEdge
	for _, caller := range graph.Nodes {
		if caller.Func == nil {
			continue
		}
		for callback := range storedCallbacksInFunction(caller.Func, invokedFields, targets) {
			pending = append(pending, pendingEdge{caller: caller, callee: callback})
		}
	}
	for _, edge := range pending {
		duplicate := false
		for _, existing := range edge.caller.Out {
			if existing.Callee.Func == edge.callee {
				duplicate = true
				break
			}
		}
		if !duplicate {
			callgraph.AddEdge(edge.caller, nil, graph.CreateNode(edge.callee))
		}
	}
}

func addPassedCallbackEdges(graph *callgraph.Graph, invokedParams map[string]map[int]bool, targets map[string]bool) {
	type pendingEdge struct {
		caller *callgraph.Node
		callee *ssa.Function
	}
	var pending []pendingEdge
	for _, caller := range graph.Nodes {
		if caller.Func == nil {
			continue
		}
		for callback := range passedCallbacksInFunction(caller.Func, invokedParams, targets) {
			pending = append(pending, pendingEdge{caller: caller, callee: callback})
		}
	}
	for _, edge := range pending {
		duplicate := false
		for _, existing := range edge.caller.Out {
			if existing.Callee.Func == edge.callee {
				duplicate = true
				break
			}
		}
		if !duplicate {
			callgraph.AddEdge(edge.caller, nil, graph.CreateNode(edge.callee))
		}
	}
}

func storedCallbackFunctions(reachable map[*ssa.Function]bool, invokedFields, targets map[string]bool) map[*ssa.Function]bool {
	callbacks := make(map[*ssa.Function]bool)
	for fn := range reachable {
		for callback := range storedCallbacksInFunction(fn, invokedFields, targets) {
			callbacks[callback] = true
		}
	}
	return callbacks
}

func passedCallbackFunctions(reachable map[*ssa.Function]bool, invokedParams map[string]map[int]bool, targets map[string]bool) map[*ssa.Function]bool {
	callbacks := make(map[*ssa.Function]bool)
	for fn := range reachable {
		for callback := range passedCallbacksInFunction(fn, invokedParams, targets) {
			callbacks[callback] = true
		}
	}
	return callbacks
}

func passedCallbacksInFunction(fn *ssa.Function, invokedParams map[string]map[int]bool, targets map[string]bool) map[*ssa.Function]bool {
	callbacks := make(map[*ssa.Function]bool)
	for _, block := range fn.Blocks {
		for _, instruction := range block.Instrs {
			call, ok := instruction.(ssa.CallInstruction)
			if !ok {
				continue
			}
			callee := call.Common().StaticCallee()
			if callee == nil {
				continue
			}
			for index := range invokedParams[functionID(callee)] {
				if index < 0 || index >= len(call.Common().Args) {
					continue
				}
				values := make(map[*ssa.Function]bool)
				collectStoredCallbacks(call.Common().Args[index], make(map[ssa.Value]bool), values)
				for callback := range values {
					if callbackReachesTarget(callback, targets, make(map[*ssa.Function]bool)) {
						callbacks[callback] = true
					}
				}
			}
		}
	}
	return callbacks
}

func storedCallbacksInFunction(fn *ssa.Function, invokedFields, targets map[string]bool) map[*ssa.Function]bool {
	callbacks := make(map[*ssa.Function]bool)
	for _, block := range fn.Blocks {
		for _, instruction := range block.Instrs {
			store, ok := instruction.(*ssa.Store)
			if !ok {
				continue
			}
			field, ok := store.Addr.(*ssa.FieldAddr)
			if !ok || !invokedFields[fieldSummaryKey(field)] {
				continue
			}
			values := make(map[*ssa.Function]bool)
			collectStoredCallbacks(store.Val, make(map[ssa.Value]bool), values)
			for callback := range values {
				if callbackReachesTarget(callback, targets, make(map[*ssa.Function]bool)) {
					callbacks[callback] = true
				}
			}
		}
	}
	return callbacks
}

func collectStoredCallbacks(value ssa.Value, seen map[ssa.Value]bool, callbacks map[*ssa.Function]bool) {
	if value == nil || seen[value] {
		return
	}
	seen[value] = true
	switch value := value.(type) {
	case *ssa.Function:
		callbacks[value] = true
	case *ssa.MakeClosure:
		collectStoredCallbacks(value.Fn, seen, callbacks)
	case *ssa.MakeInterface:
		collectStoredCallbacks(value.X, seen, callbacks)
	case *ssa.ChangeInterface:
		collectStoredCallbacks(value.X, seen, callbacks)
	case *ssa.ChangeType:
		collectStoredCallbacks(value.X, seen, callbacks)
	case *ssa.Convert:
		collectStoredCallbacks(value.X, seen, callbacks)
	case *ssa.Phi:
		for _, edge := range value.Edges {
			collectStoredCallbacks(edge, seen, callbacks)
		}
	case *ssa.Call:
		callee := value.Common().StaticCallee()
		if callee == nil || seen[callee] {
			return
		}
		seen[callee] = true
		for _, block := range callee.Blocks {
			for _, instruction := range block.Instrs {
				returned, ok := instruction.(*ssa.Return)
				if !ok {
					continue
				}
				for _, result := range returned.Results {
					collectStoredCallbacks(result, seen, callbacks)
				}
			}
		}
	case *ssa.Extract:
		collectStoredCallbacks(value.Tuple, seen, callbacks)
	case *ssa.UnOp:
		if value.Op == token.MUL {
			for _, stored := range storedValues(value.X) {
				collectStoredCallbacks(stored, seen, callbacks)
			}
		}
	}
}

func addGlobalFunctionEdges(graph *callgraph.Graph) {
	type pendingEdge struct {
		caller *callgraph.Node
		site   ssa.CallInstruction
		callee *ssa.Function
	}
	var pending []pendingEdge
	for _, caller := range graph.Nodes {
		if caller.Func == nil {
			continue
		}
		for _, block := range caller.Func.Blocks {
			for _, instruction := range block.Instrs {
				call, ok := instruction.(ssa.CallInstruction)
				if !ok || call.Common().StaticCallee() != nil {
					continue
				}
				targets := make(map[*ssa.Function]bool)
				collectFunctionValues(call.Common().Value, make(map[ssa.Value]bool), targets)
				for target := range targets {
					pending = append(pending, pendingEdge{caller: caller, site: call, callee: target})
				}
			}
		}
	}
	for _, edge := range pending {
		duplicate := false
		for _, existing := range edge.caller.Out {
			if existing.Site == edge.site && existing.Callee.Func == edge.callee {
				duplicate = true
				break
			}
		}
		if !duplicate {
			callgraph.AddEdge(edge.caller, edge.site, graph.CreateNode(edge.callee))
		}
	}
}

func collectFunctionValues(value ssa.Value, seen map[ssa.Value]bool, result map[*ssa.Function]bool) {
	if value == nil || seen[value] {
		return
	}
	seen[value] = true
	switch value := value.(type) {
	case *ssa.Function:
		result[value] = true
	case *ssa.MakeClosure:
		collectFunctionValues(value.Fn, seen, result)
	case *ssa.MakeInterface:
		collectFunctionValues(value.X, seen, result)
	case *ssa.ChangeInterface:
		collectFunctionValues(value.X, seen, result)
	case *ssa.ChangeType:
		collectFunctionValues(value.X, seen, result)
	case *ssa.Convert:
		collectFunctionValues(value.X, seen, result)
	case *ssa.Phi:
		for _, edge := range value.Edges {
			collectFunctionValues(edge, seen, result)
		}
	case *ssa.UnOp:
		if value.Op == token.MUL {
			for _, stored := range storedValues(value.X) {
				collectFunctionValues(stored, seen, result)
			}
		}
	}
}

func valueContainsPackageType(value ssa.Value, targets map[string]bool) bool {
	if containsPackageType(value.Type(), targets, make(map[types.Type]bool)) {
		return true
	}
	makeInterface, ok := value.(*ssa.MakeInterface)
	return ok && containsPackageType(makeInterface.X.Type(), targets, make(map[types.Type]bool))
}

func callbackReachesTarget(value ssa.Value, targets map[string]bool, seen map[*ssa.Function]bool) bool {
	return valueReachesTarget(value, targets, seen, make(map[ssa.Value]bool))
}

func valueReachesTarget(value ssa.Value, targets map[string]bool, seenFunctions map[*ssa.Function]bool, seenValues map[ssa.Value]bool) bool {
	if value == nil || seenValues[value] {
		return false
	}
	seenValues[value] = true

	var fn *ssa.Function
	switch value := value.(type) {
	case *ssa.Function:
		fn = value
	case *ssa.MakeClosure:
		return valueReachesTarget(value.Fn, targets, seenFunctions, seenValues)
	case *ssa.MakeInterface:
		return valueReachesTarget(value.X, targets, seenFunctions, seenValues)
	case *ssa.ChangeInterface:
		return valueReachesTarget(value.X, targets, seenFunctions, seenValues)
	case *ssa.ChangeType:
		return valueReachesTarget(value.X, targets, seenFunctions, seenValues)
	case *ssa.Convert:
		return valueReachesTarget(value.X, targets, seenFunctions, seenValues)
	case *ssa.Phi:
		for _, edge := range value.Edges {
			if valueReachesTarget(edge, targets, seenFunctions, seenValues) {
				return true
			}
		}
		return false
	case *ssa.Call:
		callee := value.Common().StaticCallee()
		if callee != nil {
			return returnedValueReachesTarget(callee, targets, seenFunctions, seenValues)
		}
	case *ssa.Extract:
		return valueReachesTarget(value.Tuple, targets, seenFunctions, seenValues)
	case *ssa.UnOp:
		if value.Op == token.MUL {
			return storedValueReachesTarget(value.X, targets, seenFunctions, seenValues)
		}
	}
	if fn == nil || seenFunctions[fn] {
		return false
	}
	seenFunctions[fn] = true
	pkgPath, _ := functionName(fn)
	if targets[pkgPath] {
		return true
	}
	for _, block := range fn.Blocks {
		for _, instruction := range block.Instrs {
			call, ok := instruction.(ssa.CallInstruction)
			if !ok {
				continue
			}
			callee := call.Common().StaticCallee()
			if callee != nil && valueReachesTarget(callee, targets, seenFunctions, seenValues) {
				return true
			}
			if callee == nil && valueReachesTarget(call.Common().Value, targets, seenFunctions, seenValues) {
				return true
			}
		}
	}
	return false
}

func returnedValueReachesTarget(fn *ssa.Function, targets map[string]bool, seenFunctions map[*ssa.Function]bool, seenValues map[ssa.Value]bool) bool {
	for _, block := range fn.Blocks {
		for _, instruction := range block.Instrs {
			returned, ok := instruction.(*ssa.Return)
			if !ok {
				continue
			}
			for _, result := range returned.Results {
				if valueReachesTarget(result, targets, seenFunctions, seenValues) {
					return true
				}
			}
		}
	}
	return false
}

func storedValueReachesTarget(address ssa.Value, targets map[string]bool, seenFunctions map[*ssa.Function]bool, seenValues map[ssa.Value]bool) bool {
	for _, value := range storedValues(address) {
		if valueReachesTarget(value, targets, seenFunctions, seenValues) {
			return true
		}
	}
	return false
}

func storedValues(address ssa.Value) []ssa.Value {
	var values []ssa.Value
	references := address.Referrers()
	if references != nil {
		for _, reference := range *references {
			store, ok := reference.(*ssa.Store)
			if !ok || store.Addr != address {
				continue
			}
			values = append(values, store.Val)
		}
	}
	global, ok := address.(*ssa.Global)
	if !ok {
		return values
	}
	initializer := global.Pkg.Func("init")
	if initializer == nil {
		return values
	}
	for _, block := range initializer.Blocks {
		for _, instruction := range block.Instrs {
			store, ok := instruction.(*ssa.Store)
			if !ok || store.Addr != global {
				continue
			}
			values = append(values, store.Val)
		}
	}
	return values
}

func containsPackageType(valueType types.Type, targets map[string]bool, seen map[types.Type]bool) bool {
	if valueType == nil || seen[valueType] {
		return false
	}
	seen[valueType] = true
	switch valueType := types.Unalias(valueType).(type) {
	case *types.Named:
		return valueType.Obj().Pkg() != nil && targets[valueType.Obj().Pkg().Path()]
	case *types.Pointer:
		return containsPackageType(valueType.Elem(), targets, seen)
	case *types.Slice:
		return containsPackageType(valueType.Elem(), targets, seen)
	case *types.Array:
		return containsPackageType(valueType.Elem(), targets, seen)
	case *types.Map:
		return containsPackageType(valueType.Key(), targets, seen) || containsPackageType(valueType.Elem(), targets, seen)
	case *types.Chan:
		return containsPackageType(valueType.Elem(), targets, seen)
	}
	return false
}

func acceptsInterface(signature *types.Signature) bool {
	if signature == nil {
		return false
	}
	for i := range signature.Params().Len() {
		if _, ok := types.Unalias(signature.Params().At(i).Type()).Underlying().(*types.Interface); ok {
			return true
		}
	}
	return false
}

func unresolvedDynamic(reachable map[*ssa.Function]bool, graph, chaGraph *callgraph.Graph, targets map[string]bool) map[string]bool {
	result := make(map[string]bool)
	reflectTargets := make(map[string]bool)
	reflectInvoke := false
	for fn := range reachable {
		for _, block := range fn.Blocks {
			for _, instruction := range block.Instrs {
				if value, ok := instruction.(ssa.Value); ok && strings.Contains(types.TypeString(value.Type(), nil), "unsafe.Pointer") {
					operands := instruction.Operands(nil)
					values := make([]ssa.Value, 0, len(operands))
					for _, operand := range operands {
						if operand != nil && *operand != nil {
							values = append(values, *operand)
						}
					}
					addValueTargets(result, values, targets)
				}
				call, ok := instruction.(ssa.CallInstruction)
				if !ok {
					continue
				}
				callee := call.Common().StaticCallee()
				if callee != nil {
					pkgPath, symbol := functionName(callee)
					switch pkgPath {
					case "reflect":
						reflectInvoke = reflectInvoke || symbol == "Value.Call" || symbol == "Value.CallSlice"
						addCallTargets(reflectTargets, call, targets)
					case "unsafe":
						addCallTargets(result, call, targets)
					}
					continue
				}
				if _, ok := call.Common().Value.(*ssa.Builtin); ok {
					continue
				}
				resolved := false
				if node := graph.Nodes[fn]; node != nil {
					for _, edge := range node.Out {
						if edge.Site == call {
							resolved = true
							break
						}
					}
				}
				if resolved {
					continue
				}
				addCallTargets(result, call, targets)
				if node := chaGraph.Nodes[fn]; node != nil {
					for _, edge := range node.Out {
						if edge.Site != call {
							continue
						}
						pkgPath, _ := functionName(edge.Callee.Func)
						if targets[pkgPath] {
							result[pkgPath] = true
						}
					}
				}
			}
		}
	}
	if reflectInvoke {
		for target := range reflectTargets {
			result[target] = true
		}
	}
	return result
}

func addCallTargets(result map[string]bool, call ssa.CallInstruction, targets map[string]bool) {
	values := append([]ssa.Value{call.Common().Value}, call.Common().Args...)
	addValueTargets(result, values, targets)
}

func addValueTargets(result map[string]bool, values []ssa.Value, targets map[string]bool) {
	for target := range targets {
		targetSet := map[string]bool{target: true}
		for _, value := range values {
			if value != nil && (valueContainsPackageType(value, targetSet) || callbackReachesTarget(value, targetSet, make(map[*ssa.Function]bool))) {
				result[target] = true
				break
			}
		}
	}
}

func functionName(fn *ssa.Function) (string, string) {
	if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return "", ""
	}
	pkgPath := fn.Pkg.Pkg.Path()
	if fn.Signature == nil || fn.Signature.Recv() == nil {
		return pkgPath, fn.Name()
	}
	receiver := types.Unalias(fn.Signature.Recv().Type())
	if pointer, ok := receiver.(*types.Pointer); ok {
		receiver = types.Unalias(pointer.Elem())
	}
	named, ok := receiver.(*types.Named)
	if !ok {
		return pkgPath, fn.Name()
	}
	return pkgPath, named.Obj().Name() + "." + fn.Name()
}

func functionID(fn *ssa.Function) string {
	pkgPath, symbol := functionName(fn)
	if pkgPath == "" {
		return fmt.Sprint(fn)
	}
	return pkgPath + "." + symbol
}

func functionPath(previous map[*ssa.Function]*ssa.Function, last *ssa.Function) []string {
	path := []string{functionID(last)}
	for previous[last] != nil {
		last = previous[last]
		path = append(path, functionID(last))
	}
	slices.Reverse(path)
	return path
}

func dependencies(meta *metadata, findings []Finding) []Dependency {
	seen := make(map[string]Dependency)
	rootModule := ""
	if meta.root.Module != nil {
		rootModule = meta.root.Module.Path
	}
	for _, finding := range findings {
		for _, pkgPath := range finding.DependencyPath {
			info := meta.packages[pkgPath]
			if info == nil {
				continue
			}
			if info.pkg.Module == nil {
				seen["stdlib"] = Dependency{Module: "stdlib", Version: meta.goVersion}
				continue
			}
			if info.pkg.Module.Path == rootModule {
				continue
			}
			module := info.pkg.Module
			seen[module.Path] = Dependency{Module: module.Path, Version: moduleVersion(module)}
		}
	}
	result := make([]Dependency, 0, len(seen))
	for _, dependency := range seen {
		result = append(result, dependency)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Module == result[j].Module {
			return result[i].Version < result[j].Version
		}
		return result[i].Module < result[j].Module
	})
	return result
}

func finalize(result *Result) {
	level := "module"
	reachable := false
	unknown := false
	unreachable := false
	absent := true
	fixed := false
	moduleReachable := false
	packageReachable := false
	for _, finding := range result.Findings {
		if finding.Level == "symbol" {
			level = "symbol"
		} else if finding.Level == "package" && level == "module" {
			level = "package"
		}
		switch finding.Outcome {
		case _outcomeReachable:
			reachable = true
			absent = false
		case _outcomeUnknown:
			unknown = true
			absent = false
		case _outcomeModule:
			moduleReachable = true
			absent = false
		case _outcomePackage:
			packageReachable = true
			absent = false
		case _outcomeUnreachable:
			unreachable = true
			absent = false
		case _outcomeFixed:
			fixed = true
			absent = false
		}
	}
	if reachable {
		result.Status = "affected"
		result.Reachability = "reachable"
	} else if packageReachable || moduleReachable {
		result.Status = "affected"
		if packageReachable {
			result.Reachability = "package_reachable"
		} else {
			result.Reachability = "module_reachable"
		}
	} else if unknown {
		result.Status = "under_investigation"
		result.Reachability = "unknown"
	} else {
		result.Status = "not_affected"
		result.Reachability = "unreachable"
		switch {
		case unreachable:
			result.Justification = "code_not_reachable"
		case absent:
			result.Justification = "code_not_present"
		case fixed:
			result.Reachability = "not_applicable"
		}
	}
	for i := range result.Findings {
		if result.Findings[i].Detail == "" {
			result.Findings[i].Detail = "analysis completed at " + level + " level"
		}
	}
}

func sortResult(result *Result) {
	sort.Slice(result.Findings, func(i, j int) bool {
		a, b := result.Findings[i], result.Findings[j]
		return a.Module+"\x00"+a.Package+"\x00"+a.Symbol < b.Module+"\x00"+b.Package+"\x00"+b.Symbol
	})
}
