package wirego

/*
	!DO NOT EDIT THIS FILE!

	If you plan to create a golang plugin for Wireshark,
	you're looking at the wrong file.
	Take your chance with "example/wirego_example.go".

	You probably don't want to look at this file actually.
	Trust me.
*/

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	zmq "github.com/go-zeromq/zmq4"
)

// Stores the dissection results for a given packet
type DissectResultFlattenEntry struct {
	Protocol string                      // Protocol column for Wireshark
	Info     string                      // Info column for Wireshark
	fields   []DissectResultFieldFlatten // List of fields for Wireshark
}

// Stores a given field from a dissection result
type DissectResultFieldFlatten struct {
	parentIdx     int     // Index of parent field (for nested fields)
	wiregoFieldId FieldId // Field id (Wirego)
	offset        int     // Field Offset in packet
	length        int     // Field length
}

// Just a simple holder for the Wirego package
type Wirego struct {
	logs               *slog.Logger
	listener           WiregoInterface                    // Listener (implemented by end user)
	resultsCacheEnable bool                               // Is the cache enabled?
	resultsCache       map[int]*DissectResultFlattenEntry // The dissectionresults cache
	wiregoFieldIds     map[int]bool                       // A set of all defined fields id (for quick access)

	//ZMQ
	zqmEndpoint string          // The ZMQ endpoint defined by end user
	zmqContext  context.Context // ZMQ context
	zmqSocket   zmq.Socket      // The opened ZMQ socket

	//Fetched from plugin for quicked access
	pluginName                       string            // The plugin name to be displayed on Wireshark
	pluginFilter                     string            // The plugin filter used to filter traffic on Wireshark
	pluginDetectionHeuristicsParents []string          // Detection heuristic parents (if any)
	pluginDetectionFilters           []DetectionFilter // Detection filters (if any)
	pluginFields                     []WiresharkField  // List of plugin custom fields
}

// We use a static "object" here
var wg Wirego

// New creates a new instance of Wirego. zqmEndpoint desfined the endpoint to be used when Listen is called.
// The "listener" is the end-used implementation of the Wirego's interface
func New(zqmEndpoint string, verbose bool, listener WiregoInterface) (*Wirego, error) {
	var err error

	wg.logs = slog.New(slog.NewTextHandler(os.Stdout, nil))
	if verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	} else {
		slog.SetLogLoggerLevel(slog.LevelInfo)
	}

	wg.listener = listener
	wg.zqmEndpoint = zqmEndpoint
	wg.resultsCacheEnable = true

	//Prepare maps
	wg.wiregoFieldIds = make(map[int]bool)
	wg.resultsCache = make(map[int]*DissectResultFlattenEntry)

	//Preload all "static" values
	wg.pluginName = wg.listener.GetName()
	wg.pluginFilter = wg.listener.GetFilter()
	wg.pluginDetectionHeuristicsParents = wg.listener.GetDetectionHeuristicsParents()
	wg.pluginDetectionFilters = wg.listener.GetDetectionFilters()
	wg.pluginFields = wg.listener.GetFields()

	//Checks fields for duplicates
	for _, f := range wg.pluginFields {
		_, duplicate := wg.wiregoFieldIds[int(f.WiregoFieldId)]
		if duplicate {
			return nil, fmt.Errorf("failed to add wirego fields, duplicated WiregoFieldId: %d", f.WiregoFieldId)
		}
		wg.wiregoFieldIds[int(f.WiregoFieldId)] = true
	}

	//Be a bit verbose to ease plugin development
	slog.Info("Setting up Wirego...")
	slog.Info("Plugin will appear in Wireshark as '" + wg.pluginName + "' with filter '" + wg.pluginFilter + "'")
	slog.Info("Custom fields registered: %d", len(wg.pluginFields))
	if len(wg.pluginDetectionHeuristicsParents) != 0 {
		slog.Info("Heuristics function will be called hen parent matches " + strings.Join(wg.pluginDetectionHeuristicsParents, " or "))
	}
	if len(wg.pluginDetectionFilters) != 0 {
		var str []string
		for _, f := range wg.pluginDetectionFilters {
			str = append(str, f.String())
		}
		slog.Info("Dissect will be called when filters following matches: " + strings.Join(str, " or "))
	}

	//Setup ZMQ
	err = wg.zmqSetup()
	if err != nil {
		return nil, err
	}
	return &wg, nil
}

// ResultsCacheEnable enables or disables the results cache. By default, the results cache is enabled.
// If re-analyzing a packet makes sense for your protocol, disable this feature.
func (wg *Wirego) ResultsCacheEnable(enable bool) {
	wg.resultsCacheEnable = enable
}

// addFieldsRecursive unrolls a fields result tree to flatten version, in order to store it to the cache
func (wg *Wirego) addFieldsRecursive(flatten *DissectResultFlattenEntry, parentIdx int, field *DissectField) {
	flatten.fields = append(flatten.fields, DissectResultFieldFlatten{parentIdx: parentIdx, wiregoFieldId: field.WiregoFieldId, offset: field.Offset, length: field.Length})
	newParentIdx := len(flatten.fields) - 1

	for _, sub := range field.SubFields {
		wg.addFieldsRecursive(flatten, newParentIdx, &sub)
	}
}

func (f DetectionFilter) String() string {
	if f.FilterType == DetectionFilterTypeInt {
		return fmt.Sprintf("%s=%d", f.Name, f.ValueInt)
	} else {
		return fmt.Sprintf("%s=%s", f.Name, f.ValueString)
	}
}
