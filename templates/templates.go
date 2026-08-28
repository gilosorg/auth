package templates

import (
	"fmt"
	"html/template"
	"path/filepath"
)

func ParseTemplates() (*template.Template, error) {
	// Parse templates
	dirs := []string{
		"templates/*.html",
		"templates/*/*.html",
		"templates/*/*/*.html",
	}
	files := []string{}
	for _, dir := range dirs {
		ff, err := filepath.Glob(dir)
		if err != nil {
			return nil, fmt.Errorf("Error finding template files: %v", err)
		}
		files = append(files, ff...)
	}

	// Use html/template instead of text/template
	tmpls, err := template.New("").Funcs(FuncMap).ParseFiles(files...)
	if err != nil {
		return nil, fmt.Errorf("Error parsing templates: %v", err)
	}

	return tmpls, nil
}
