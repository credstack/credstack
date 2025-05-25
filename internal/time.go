package internal

import "time"

/*
UnixTimestamp - Returns a UNIX timestamp representing the current date/time
*/
func UnixTimestamp() int64 {
	return time.Now().Unix()
}

/*
StringTimestamp - Returns a string representing a human-readable timestamp. Most commonly used in log file names
*/
func StringTimestamp() string {
	return time.Now().Format("20060102T150405")
}
