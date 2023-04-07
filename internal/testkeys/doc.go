// So every test run will use a different key.
// If your system runs out of entropy, tests might fail.
// If using a VM, please ensure to attach viorng device to
// prevent entropy exhaustion.
package testkeys

//go:generate go run generate.go -output .
