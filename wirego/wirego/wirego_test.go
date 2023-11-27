package wirego

import (
	"errors"
	"testing"
)

type FakeListener struct {
	setupCount  int
	setupReturn error

	getNameCount            int
	getNameReturn           string
	getFilterCount          int
	getFieldsCount          int
	getDissectorFilterCount int
	dissectCount            int
}

func (l *FakeListener) GetName() string {
	l.getNameCount++
	return l.getNameReturn
}

func (l *FakeListener) GetFilter() string {
	l.getFilterCount++
	return ""
}
func (l *FakeListener) Setup() error {
	l.setupCount++
	return l.setupReturn
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

func (fake *FakeListener) Reset() {
	fake.setupCount = 0
	fake.setupReturn = nil
	fake.getNameCount = 0
	fake.getNameReturn = ""
	fake.getFilterCount = 0
	fake.getFieldsCount = 0
	fake.getDissectorFilterCount = 0
	fake.dissectCount = 0
}

func TestSetup(t *testing.T) {
	var fake FakeListener
	fake.Reset()

	//Standard setup
	Register(&fake)
	if wirego_setup() != 0 {
		t.Fatal("wirego_setup succeeds")
	}
	if fake.setupCount != 1 {
		t.Fatal("Setup is called when plugin is loaded")
	}

	//Setup failure
	fake.Reset()
	fake.setupReturn = errors.New("failure") //setup will return an error
	Register(&fake)
	if wirego_setup() == 0 {
		t.Fatal("wirego_setup fails if plugin setup fails")
	}
	if fake.setupCount != 1 {
		t.Fatal("Setup is called when plugin is loaded")
	}

}

func TestVersion(t *testing.T) {
	if wirego_version_major() != WIREGO_VERSION_MAJOR {
		t.Fatal("version major is fine")
	}
	if wirego_version_minor() != WIREGO_VERSION_MINOR {
		t.Fatal("version minor is fine")
	}
}

func TestName(t *testing.T) {
	var fake FakeListener
	fake.Reset()

	fake.getNameReturn = "Test"
	Register(&fake)
	name := wirego_plugin_name()
	if name == nil {
		t.Fatal("wirego_plugin_name returns plugin name")
	}

	if (*name) != 'T' { //FIXME : do some dirty tricks
		t.Fatal("wirego_plugin_name looks fine")
	}

}
