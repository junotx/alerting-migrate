package main

type ruleError struct {
	err error
}

func (e ruleError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}
