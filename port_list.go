package gonmap

import (
	"regexp"
	"strconv"
	"strings"

	arrayutil "github.com/qiwentaidi/utils/array"
)

var portRangeRegx = regexp.MustCompile("^(\\d+)(?:-(\\d+))?$")
var portGroupRegx = regexp.MustCompile("^(\\d+(?:-\\d+)?)(?:,\\d+(?:-\\d+)?)*$")

func parsePortList(express string) []int {
	var list = []int{}
	if !portGroupRegx.MatchString(express) {
		panic("port expression string invalid")
	}
	for _, expr := range strings.Split(express, ",") {
		rArr := portRangeRegx.FindStringSubmatch(expr)
		var startPort, endPort int
		startPort, _ = strconv.Atoi(rArr[1])
		if rArr[2] != "" {
			endPort, _ = strconv.Atoi(rArr[2])
		} else {
			endPort = startPort
		}
		for num := startPort; num <= endPort; num++ {
			list = append(list, num)
		}
	}
	list = arrayutil.RemoveDuplicates(list)
	return list
}
