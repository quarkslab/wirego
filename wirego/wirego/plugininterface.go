package wirego

// WiregoInterface is implemented by the actual wirego plugin
type WiregoInterface interface {
	GetName() string
	GetFilter() string
	Setup() error
	GetFields() []WiresharkField
	GetDetectionFilters() []DetectionFilter
	GetDetectionHeuristicsParents() []string
	DetectionHeuristic(packetNumber int, src string, dst string, stack string, packet []byte) bool
	DissectPacket(packetNumber int, src string, dst string, stack string, packet []byte) *DissectResult
}

// Display modes
type DisplayMode int

const (
	DisplayModeNone        DisplayMode = 0x01
	DisplayModeDecimal     DisplayMode = 0x02
	DisplayModeHexadecimal DisplayMode = 0x03
)

// Fields types
type ValueType int

const (
	ValueTypeNone ValueType = 0x01
	ValueTypeBool ValueType = 0x02

	ValueTypeUInt8 ValueType = 0x03
	ValueTypeInt8  ValueType = 0x04

	ValueTypeUInt16 ValueType = 0x05
	ValueTypeInt16  ValueType = 0x06

	ValueTypeUInt32 ValueType = 0x07
	ValueTypeInt32  ValueType = 0x08

	ValueTypeCString ValueType = 0x09
	ValueTypeString  ValueType = 0x10
)

// A field descriptor, to be provided by the actual plugin
type FieldId int
type WiresharkField struct {
	WiregoFieldId FieldId
	Name          string
	Filter        string
	ValueType     ValueType
	DisplayMode   DisplayMode
}

type DetectionFilterType int

const (
	DetectionFilterTypeInt    DetectionFilterType = iota
	DetectionFilterTypeString DetectionFilterType = iota
)

// A detection filter provides a wireshark filter use to match traffic to be sent to the dissector
type DetectionFilter struct {
	FilterType  DetectionFilterType
	Name        string
	ValueInt    int
	ValueString string
}

// A field, as returned by the dissector
type DissectField struct {
	WiregoFieldId FieldId
	Offset        int
	Length        int
	SubFields     []DissectField
}

// A dissector result is a protocol name, an info string and a list of extracted fields
type DissectResult struct {
	Protocol string
	Info     string
	Fields   []DissectField
}
