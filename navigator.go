package main

type heatmap struct {
	Domain     string            `json:"domain"`
	Name       string            `json:"name"`
	Gradient   attackGradient    `json:"gradient"`
	Versions   attackVersions    `json:"versions"`
	Techniques []attackTechnique `json:"techniques"`
}

type attackGradient struct {
	Colors   []string `json:"colors"`
	MaxValue int      `json:"maxValue"`
	MinValue int      `json:"minValue"`
}

type attackVersions struct {
	Attack    string `json:"attack"`
	Navigator string `json:"navigator"`
	Layer     string `json:"layer"`
}

type attackTechnique struct {
	ID      string       `json:"techniqueID"`
	Score   int          `json:"score"`
	Comment string       `json:"comment"`
	Links   []attackLink `json:"links"`
}

type attackLink struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}
