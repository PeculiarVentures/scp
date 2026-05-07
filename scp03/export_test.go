package scp03

// ClassifyInitUpdateSWForTest exposes classifyInitUpdateSW to the
// scp03_test package for unit-testing the diagnostic table without
// promoting the helper to the public API. Tests can pin the
// classifications for known SWs without creating a fake card that
// returns each one.
func ClassifyInitUpdateSWForTest(sw1, sw2 byte) (string, bool) {
	return classifyInitUpdateSW(sw1, sw2)
}
