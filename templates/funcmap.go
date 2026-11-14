package templates

import (
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"strconv"
	"strings"
	"time"
)

var tashkentLoc = func() *time.Location {
	if loc, err := time.LoadLocation("Asia/Tashkent"); err == nil {
		return loc
	}
	return time.FixedZone("UZT", 5*3600)
}()

var FuncMap = template.FuncMap{
	"sub":    func(a, b float64) float64 { return a - b },
	"add":    func(x, y float64) float64 { return x + y },
	"subInt": func(a, b int) int { return a - b },
	"addInt": func(x, y int) int { return x + y },
	"upper":  strings.ToUpper,
	"multiply": func(a, b float64) float64 {
		result := a * b
		return math.Round(result*100) / 100
	},
	"formatDate": func(t time.Time) string {
		return t.In(tashkentLoc).Format("02.01.2006 15:04")
	},
	"join": func(intSlice []int64, sep string) string {
		strSlice := make([]string, len(intSlice))
		for i, num := range intSlice {
			strSlice[i] = strconv.FormatInt(num, 10)
		}
		return strings.Join(strSlice, sep)
	},
	"contains": func(slice []string, item string) bool {
		for _, s := range slice {
			if s == item {
				return true
			}
		}
		return false
	},
	// json converts any value to JSON string (safe for embedding in <script> tags)
	"json": func(v interface{}) template.JS {
		b, err := json.Marshal(v)
		if err != nil {
			return template.JS("{}")
		}
		return template.JS(b)
	},
	"printf": fmt.Sprintf,
	"icon":   fluentIcon,
}
