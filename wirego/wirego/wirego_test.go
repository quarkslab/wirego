package wirego

import "testing"

type FakeListener struct {
	getNameCount            int
	getFilterCount          int
	setupCount              int
	getFieldsCount          int
	getDissectorFilterCount int
	dissectCount            int
}

func (l *FakeListener) GetName() string {
	l.getNameCount++
	return ""
}

func (l *FakeListener) GetFilter() string {
	l.getFilterCount++
	return ""
}
func (l *FakeListener) Setup() error {
	l.setupCount++
	return nil
}
func (l *FakeListener) GetFields() []WiresharkField {
	l.getFieldsCount++
	var f []WiresharkField
	return f
}
func (l *FakeListener) GetDissectorFilter() []DissectorFilter {
	l.getDissectorFilterCount++
	var f []DissectorFilter
	return f
}
func (l *FakeListener) DissectPacket(src string, dst string, stack string, packet []byte) *DissectResult {
	var res DissectResult
	l.dissectCount++
	return &res
}

func TestNew(t *testing.T) {
	var fake FakeListener
	Register(&fake)
	if wirego_setup() != 0 {
		t.Fatal("wirego_setup succeeds")
	}

	if fake.setupCount == 0 {
		t.Fatal("Setup is called when plugin is loaded")
	}
}
