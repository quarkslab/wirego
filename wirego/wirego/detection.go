package wirego

import "C"

//export wirego_detect_int
func wirego_detect_int(matchValue *C.int, idx C.int) *C.char {
	if wg.listener == nil {
		return nil
	}

	cnt := 0
	for _, f := range wg.pluginDetectionFilters {
		if f.FilterType == DetectionFilterTypeInt {
			if cnt == int(idx) {
				*matchValue = C.int(f.ValueInt)
				name := C.CString(f.Name)
				return name
			}
			cnt++
		}
	}

	*matchValue = 0
	return nil
}

//export wirego_detect_string
func wirego_detect_string(matchValue **C.char, idx C.int) *C.char {
	if wg.listener == nil {
		return nil
	}

	cnt := 0
	for _, f := range wg.pluginDetectionFilters {
		if f.FilterType == DetectionFilterTypeString {
			if cnt == int(idx) {

				*matchValue = C.CString(f.ValueString)
				name := C.CString(f.Name)
				return name
			}
			cnt++
		}
	}

	*matchValue = nil
	return nil
}

//export wirego_detect_heuristic
func wirego_detect_heuristic(idx C.int) *C.char {
	if wg.listener == nil {
		return nil
	}

	if idx >= C.int(len(wg.pluginDetectionHeuristicsParents)) {
		return nil
	}

	return C.CString(wg.pluginDetectionHeuristicsParents[idx])
}
