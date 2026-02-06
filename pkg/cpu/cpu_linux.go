// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package cpu

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/jaypipes/ghw/pkg/linuxpath"
	"github.com/jaypipes/ghw/pkg/option"
	"github.com/jaypipes/ghw/pkg/util"
)

var (
	regexForCpulCore = regexp.MustCompile("^cpu([0-9]+)$")
	onlineFile       = "online"
)

func (i *Info) load(opts *option.Options) error {
	i.Processors = processorsGet(opts)
	var totCores uint32
	var totThreads uint32
	for _, p := range i.Processors {
		totCores += p.TotalCores
		totThreads += p.TotalHardwareThreads
	}
	i.TotalCores = totCores
	i.TotalHardwareThreads = totThreads
	// TODO(jaypipes): Remove TotalThreads before v1.0
	i.TotalThreads = totThreads
	return nil
}

func processorsGet(opts *option.Options) []*Processor {
	paths := linuxpath.New(opts)

	// Check raw file for s390x indicators
	if isS390xLayout(paths.ProcCpuinfo) {
		return parseS390xCPUInfo(opts)
	}

	// Otherwise fall back to logicalProcessors parsing
	lps := logicalProcessorsFromProcCPUInfo(opts)
	// keyed by processor ID (physical_package_id)
	procs := map[int]*Processor{}

	// /sys/devices/system/cpu pseudodir contains N number of pseudodirs with
	// information about the logical processors on the host. These logical
	// processor pseudodirs are of the pattern /sys/devices/system/cpu/cpu{N}
	fnames, err := os.ReadDir(paths.SysDevicesSystemCPU)
	if err != nil {
		opts.Warn("failed to read /sys/devices/system/cpu: %s", err)
		return []*Processor{}
	}
	for _, fname := range fnames {
		matches := regexForCpulCore.FindStringSubmatch(fname.Name())
		if len(matches) < 2 {
			continue
		}

		lpID, err := strconv.Atoi(matches[1])
		if err != nil {
			opts.Warn("failed to find numeric logical processor ID: %s", err)
			continue
		}

		onlineFilePath := filepath.Join(paths.SysDevicesSystemCPU, fmt.Sprintf("cpu%d", lpID), onlineFile)
		if _, err := os.Stat(onlineFilePath); err == nil {
			if util.SafeIntFromFile(opts, onlineFilePath) == 0 {
				continue
			}
		} else if errors.Is(err, os.ErrNotExist) {
			// Assume the CPU is online if the online state file doesn't exist
			// (as is the case with older snapshots)
		}
		procID := processorIDFromLogicalProcessorID(opts, lpID)
		proc, found := procs[procID]
		if !found {
			proc = &Processor{ID: procID}
			lp, ok := lps[lpID]
			if !ok {
				opts.Warn(
					"failed to find attributes for logical processor %d",
					lpID,
				)
				continue
			}

			// Assumes /proc/cpuinfo is in order of logical processor id, then
			// lps[lpID] describes logical processor `lpID`.
			// Once got a more robust way of fetching the following info,
			// can we drop /proc/cpuinfo.
			if len(lp.Attrs["flags"]) != 0 { // x86
				proc.Capabilities = strings.Split(lp.Attrs["flags"], " ")
			} else if len(lp.Attrs["Features"]) != 0 { // ARM64
				proc.Capabilities = strings.Split(lp.Attrs["Features"], " ")
			}
			// Model detection
			if len(lp.Attrs["model name"]) != 0 {
				proc.Model = lp.Attrs["model name"]
			} else if len(lp.Attrs["Processor"]) != 0 { // ARM
				proc.Model = lp.Attrs["Processor"]
			} else if len(lp.Attrs["cpu model"]) != 0 { // MIPS, ARM
				proc.Model = lp.Attrs["cpu model"]
			} else if len(lp.Attrs["Model Name"]) != 0 { // LoongArch
				proc.Model = lp.Attrs["Model Name"]
			} else if len(lp.Attrs["uarch"]) != 0 { // SiFive
				proc.Model = lp.Attrs["uarch"]
			}
			// Vendor detection
			if len(lp.Attrs["vendor_id"]) != 0 {
				proc.Vendor = lp.Attrs["vendor_id"]
			} else if len(lp.Attrs["isa"]) != 0 { // RISCV64
				proc.Vendor = lp.Attrs["isa"]
			} else if lp.Attrs["CPU implementer"] == "0x41" { // ARM
				proc.Vendor = "ARM"
			}
			procs[procID] = proc
		}

		coreID := coreIDFromLogicalProcessorID(opts, lpID)
		core := proc.CoreByID(coreID)
		if core == nil {
			core = &ProcessorCore{
				ID:                   coreID,
				TotalHardwareThreads: 1,
				// TODO(jaypipes): Remove NumThreads before v1.0
				NumThreads: 1,
			}
			proc.Cores = append(proc.Cores, core)
			proc.TotalCores++
			proc.NumCores++
		} else {
			core.TotalHardwareThreads++
			core.NumThreads++
		}
		proc.TotalHardwareThreads++
		proc.NumThreads++
		core.LogicalProcessors = append(core.LogicalProcessors, lpID)
	}
	res := []*Processor{}
	for _, p := range procs {
		for _, c := range p.Cores {
			sort.Ints(c.LogicalProcessors)
		}
		res = append(res, p)
	}
	return res
}

// isS390xLayout checks if /proc/cpuinfo is in s390x format.
// s390x often places vendor/model in global sections.
func isS390xLayout(cpuinfoPath string) bool {
	f, err := os.Open(cpuinfoPath)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	sawVendor := false
	sawNum := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// check for real s390x identifiers
		if strings.HasPrefix(line, "vendor_id") && strings.Contains(line, "IBM/S390") {
			sawVendor = true
		}
		if strings.HasPrefix(line, "# processors") {
			sawNum = true
		}
		// if we have seen both, it's s390x
		if sawVendor && sawNum {
			return true
		}
	}
	return false
}

// Example /proc/cpuinfo output on an s390x system:
//
// [root@ logs]# cat /proc/cpuinfo
// vendor_id       : IBM/S390
// # processors    : 38
// bogomips per cpu: 28901.00
// max thread id   : 1
// features        : esan3 zarch stfle msa ldisp eimm dfp edat etf3eh highgprs te vx vxd vxe gs vxe2 vxp sort dflt vxp2 nnpa pcimio sie
// facilities      : 0 1 2 3 4 6 7 8 9 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 30 31 32 33 34 35 36 37 38 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 57 58 59 60 61 64 65 66 67 68 69 70 71 72 73 75 76 77 78 80 81 82 84 85 86 87 129 130 131 132 133 134 135 138 139 141 142 144 145 146 148 149 150 151 152 153 155 156 158 165 170 192 193 194 196 197 198 199 200 201
// cache0          : level=1 type=Data scope=Private size=128K line_size=256 associativity=8
// cache1          : level=1 type=Instruction scope=Private size=128K line_size=256 associativity=8
// cache2          : level=2 type=Unified scope=Private size=36864K line_size=256 associativity=18
// cache3          : level=3 type=Unified scope=Shared size=368640K line_size=256 associativity=180
// processor 0: version = 00,  identification = 271F08,  machine = 9175
// processor 1: version = 00,  identification = 271F08,  machine = 9175
// processor 2: version = 00,  identification = 271F08,  machine = 9175
// ...
// processor 37: version = 00,  identification = 271F08,  machine = 9175
//
// cpu number      : 0
// physical id     : 2
// core id         : 0
// book id         : 2
// drawer id       : 2
// dedicated       : 0
// address         : 0
// siblings        : 12
// cpu cores       : 6
// version         : 00
// identification  : 271F08
// machine         : 9175
// cpu MHz dynamic : 5508
// cpu MHz static  : 5508
//
// cpu number      : 1
// physical id     : 2
// core id         : 0
// book id         : 2
// drawer id       : 2
// dedicated       : 0
// address         : 1
// siblings        : 12
// cpu cores       : 6
// version         : 00
// identification  : 271F08
// machine         : 9175
// cpu MHz dynamic : 5508
// cpu MHz static  : 5508
//
// cpu number      : 2
// .
// .
//

// parseS390xCPUInfo reads /proc/cpuinfo and constructs Processor info for s390x systems.
func parseS390xCPUInfo(opts *option.Options) []*Processor {
	paths := linuxpath.New(opts)
	file, err := os.Open(paths.ProcCpuinfo)
	if err != nil {
		return []*Processor{}
	}
	defer file.Close()

	var globalVendor, globalModel string
	// Map of physical_id -> Processor pointer
	procsMap := make(map[int]*Processor)

	// Temporary storage for block attributes
	currentAttrs := make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			// When we hit a blank line, process the block we just finished
			if cpuStr, ok := currentAttrs["cpu number"]; ok {
				cpuNum, _ := strconv.Atoi(cpuStr)
				physID, _ := strconv.Atoi(currentAttrs["physical id"])
				coreID, _ := strconv.Atoi(currentAttrs["core id"])

				// 1. Get or Create the Physical Processor
				p, exists := procsMap[physID]
				if !exists {
					p = &Processor{
						ID:     physID,
						Vendor: globalVendor,
						Model:  globalModel,
						Cores:  make([]*ProcessorCore, 0),
					}
					procsMap[physID] = p
				}

				// 2. Get or Create the Core within that Processor
				core := p.CoreByID(coreID)
				if core == nil {
					core = &ProcessorCore{
						ID:                coreID,
						LogicalProcessors: []int{},
					}
					p.Cores = append(p.Cores, core)
					p.TotalCores++
					p.NumCores++ // Older ghw compat
				}

				// 3. Add the logical processor to the core and update counts
				core.LogicalProcessors = append(core.LogicalProcessors, cpuNum)
				core.TotalHardwareThreads++
				core.NumThreads++ // Older ghw compat

				p.TotalHardwareThreads++
				p.NumThreads++ // Older ghw compat
			}
			currentAttrs = make(map[string]string)
			continue
		}

		// Capture global identifiers found at the top/bottom of the file
		if strings.HasPrefix(line, "vendor_id") {
			globalVendor = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		} else if strings.HasPrefix(line, "machine") {
			globalModel = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
		}

		// Store attributes for the current "cpu number" block
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			currentAttrs[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	// Convert map to slice and sort for stable output
	res := make([]*Processor, 0, len(procsMap))
	for _, p := range procsMap {
		// Fill in model/vendor if they were only found at the end of the file
		if p.Model == "" {
			p.Model = globalModel
		}
		if p.Vendor == "" {
			p.Vendor = globalVendor
		}
		res = append(res, p)
	}

	sort.Slice(res, func(i, j int) bool {
		return res[i].ID < res[j].ID
	})

	return res
}

// processorIDFromLogicalProcessorID returns the processor physical package ID
// for the supplied logical processor ID
func processorIDFromLogicalProcessorID(opts *option.Options, lpID int) int {
	paths := linuxpath.New(opts)
	// Fetch CPU ID
	path := filepath.Join(
		paths.SysDevicesSystemCPU,
		fmt.Sprintf("cpu%d", lpID),
		"topology", "physical_package_id",
	)
	return util.SafeIntFromFile(opts, path)
}

// coreIDFromLogicalProcessorID returns the core ID for the supplied logical
// processor ID
func coreIDFromLogicalProcessorID(opts *option.Options, lpID int) int {
	paths := linuxpath.New(opts)
	// Fetch CPU ID
	path := filepath.Join(
		paths.SysDevicesSystemCPU,
		fmt.Sprintf("cpu%d", lpID),
		"topology", "core_id",
	)
	return util.SafeIntFromFile(opts, path)
}

func CoresForNode(opts *option.Options, nodeID int) ([]*ProcessorCore, error) {
	// The /sys/devices/system/node/nodeX directory contains a subdirectory
	// called 'cpuX' for each logical processor assigned to the node. Each of
	// those subdirectories contains a topology subdirectory which has a
	// core_id file that indicates the 0-based identifier of the physical core
	// the logical processor (hardware thread) is on.
	paths := linuxpath.New(opts)
	path := filepath.Join(
		paths.SysDevicesSystemNode,
		fmt.Sprintf("node%d", nodeID),
	)
	cores := make([]*ProcessorCore, 0)

	findCoreByID := func(coreID int) *ProcessorCore {
		for _, c := range cores {
			if c.ID == coreID {
				return c
			}
		}

		c := &ProcessorCore{
			ID:                coreID,
			LogicalProcessors: []int{},
		}
		cores = append(cores, c)
		return c
	}

	files, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		filename := file.Name()
		if !strings.HasPrefix(filename, "cpu") {
			continue
		}
		if filename == "cpumap" || filename == "cpulist" {
			// There are two files in the node directory that start with 'cpu'
			// but are not subdirectories ('cpulist' and 'cpumap'). Ignore
			// these files.
			continue
		}
		// Grab the logical processor ID by cutting the integer from the
		// /sys/devices/system/node/nodeX/cpuX filename
		cpuPath := filepath.Join(path, filename)
		procID, err := strconv.Atoi(filename[3:])
		if err != nil {
			opts.Warn(
				"failed to determine procID from %s. Expected integer after 3rd char.",
				filename,
			)
			continue
		}
		onlineFilePath := filepath.Join(cpuPath, onlineFile)
		if _, err := os.Stat(onlineFilePath); err == nil {
			if util.SafeIntFromFile(opts, onlineFilePath) == 0 {
				continue
			}
		} else if errors.Is(err, os.ErrNotExist) {
			// Assume the CPU is online if the online state file doesn't exist
			// (as is the case with older snapshots)
		}
		coreIDPath := filepath.Join(cpuPath, "topology", "core_id")
		coreID := util.SafeIntFromFile(opts, coreIDPath)
		core := findCoreByID(coreID)
		core.LogicalProcessors = append(
			core.LogicalProcessors,
			procID,
		)
	}

	for _, c := range cores {
		c.TotalHardwareThreads = uint32(len(c.LogicalProcessors))
		// TODO(jaypipes): Remove NumThreads before v1.0
		c.NumThreads = c.TotalHardwareThreads
	}

	return cores, nil
}

// logicalProcessor contains information about a single logical processor
// on the host.
type logicalProcessor struct {
	// This is the logical processor ID assigned by the host. In /proc/cpuinfo,
	// this is the zero-based index of the logical processor as it appears in
	// the /proc/cpuinfo file and matches the "processor" attribute. In
	// /sys/devices/system/cpu/cpu{N} pseudodir entries, this is the N value.
	ID int
	// The entire collection of string attribute name/value pairs for the
	// logical processor.
	Attrs map[string]string
}

// logicalProcessorsFromProcCPUInfo reads the `/proc/cpuinfo` pseudofile and
// returns a map, keyed by logical processor ID, of logical processor structs.
//
// `/proc/cpuinfo` files look like the following:
//
// ```
// processor	: 0
// vendor_id	: AuthenticAMD
// cpu family	: 23
// model		: 8
// model name	: AMD Ryzen 7 2700X Eight-Core Processor
// stepping	: 2
// microcode	: 0x800820d
// cpu MHz		: 2200.000
// cache size	: 512 KB
// physical id	: 0
// siblings	: 16
// core id		: 0
// cpu cores	: 8
// apicid		: 0
// initial apicid	: 0
// fpu		: yes
// fpu_exception	: yes
// cpuid level	: 13
// wp		: yes
// flags		: fpu vme de pse tsc msr pae mce <snip...>
// bugs		: sysret_ss_attrs null_seg spectre_v1 spectre_v2 spec_store_bypass retbleed smt_rsb
// bogomips	: 7386.41
// TLB size	: 2560 4K pages
// clflush size	: 64
// cache_alignment	: 64
// address sizes	: 43 bits physical, 48 bits virtual
// power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]
//
// processor	: 1
// vendor_id	: AuthenticAMD
// cpu family	: 23
// model		: 8
// model name	: AMD Ryzen 7 2700X Eight-Core Processor
// stepping	: 2
// microcode	: 0x800820d
// cpu MHz		: 1885.364
// cache size	: 512 KB
// physical id	: 0
// siblings	: 16
// core id		: 1
// cpu cores	: 8
// apicid		: 2
// initial apicid	: 2
// fpu		: yes
// fpu_exception	: yes
// cpuid level	: 13
// wp		: yes
// flags		: fpu vme de pse tsc msr pae mce <snip...>
// bugs		: sysret_ss_attrs null_seg spectre_v1 spectre_v2 spec_store_bypass retbleed smt_rsb
// bogomips	: 7386.41
// TLB size	: 2560 4K pages
// clflush size	: 64
// cache_alignment	: 64
// address sizes	: 43 bits physical, 48 bits virtual
// power management: ts ttp tm hwpstate cpb eff_freq_ro [13] [14]
// ```
//
// with blank line-separated blocks of colon-delimited attribute name/value
// pairs for a specific logical processor on the host.
func logicalProcessorsFromProcCPUInfo(
	opts *option.Options,
) map[int]*logicalProcessor {
	paths := linuxpath.New(opts)
	r, err := os.Open(paths.ProcCpuinfo)
	if err != nil {
		return nil
	}
	defer util.SafeClose(r)

	lps := map[int]*logicalProcessor{}

	// A map of attributes describing the logical processor
	lpAttrs := map[string]string{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			// Output of /proc/cpuinfo has a blank newline to separate logical
			// processors, so here we collect up all the attributes we've
			// collected for this logical processor block
			lpIDstr, ok := lpAttrs["processor"]
			if !ok {
				opts.Warn("expected to find 'processor' key in /proc/cpuinfo attributes")
				continue
			}
			lpID, _ := strconv.Atoi(lpIDstr)
			lp := &logicalProcessor{
				ID:    lpID,
				Attrs: lpAttrs,
			}
			lps[lpID] = lp
			// Reset the current set of processor attributes...
			lpAttrs = map[string]string{}
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		lpAttrs[key] = value
	}
	return lps
}
