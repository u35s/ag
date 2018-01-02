package main

import (
	"bytes"
	"fmt"
	"strconv"
)

type IP uint32

func ParseIP(b []byte) IP {
	return IP(IP(b[0])<<24 + IP(b[1])<<16 + IP(b[2])<<8 + IP(b[3]))
}

func (ip IP) String() string {
	var bf bytes.Buffer
	for i := 1; i <= 4; i++ {
		bf.WriteString(strconv.Itoa(int((ip >> ((4 - uint(i)) * 8)) & 0xff)))
		if i != 4 {
			bf.WriteByte('.')
		}
	}
	return bf.String()
}

func BitShow(n int) string {
	var ext string = "B"
	if n >= 1024 {
		n /= 1024
		ext = "Kb"
	}
	if n >= 1024 {
		n /= 1024
		ext = "Mb"
	}
	if n >= 1024 {
		n /= 1024
		ext = "Gb"
	}
	return fmt.Sprintf("%v %v", n, ext)
}
