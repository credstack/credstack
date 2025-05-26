package internal

import "regexp"

/*
MatchRegex - Simple function for matching regular expressions. The parameter 're' is a pointer to a Regexp struct
as we don't want to re-compile these on every call to MatchRegex
*/
func MatchRegex(target string, re *regexp.Regexp) bool {
	if re.MatchString(target) {
		return true
	}

	return false
}
