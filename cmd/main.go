package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"node-config/build"
	"node-config/export"
	"node-config/parse"
	"node-config/profile"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "parse":
		cmdParse(os.Args[2:])
	case "build":
		cmdBuild(os.Args[2:])
	case "export":
		cmdExport(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `node-config - proxy link parser and sing-box config builder

Usage:
  node-config parse [-f file]
  node-config build -p profile.json [-s settings.json]
  node-config export -p profile.json
`)
}

func cmdParse(args []string) {
	fs := flag.NewFlagSet("parse", flag.ExitOnError)
	file := fs.String("f", "", "input file (stdin if empty)")
	_ = fs.Parse(args)

	text, err := readInput(*file)
	if err != nil {
		fatal(err)
	}
	result, err := parse.ParseText(text, parse.Options{})
	if err != nil {
		fatal(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	fatal(enc.Encode(result))
}

func cmdBuild(args []string) {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	profileFile := fs.String("p", "", "profile json file")
	settingsFile := fs.String("s", "", "settings json file (optional)")
	_ = fs.Parse(args)
	if *profileFile == "" {
		fatal(fmt.Errorf("missing -p profile file"))
	}

	var p profile.Profile
	fatal(readJSON(*profileFile, &p))

	settings := profile.DefaultSettings()
	if *settingsFile != "" {
		fatal(readJSON(*settingsFile, &settings))
	}

	result, err := build.Build(build.Input{Profile: p, Settings: settings})
	if err != nil {
		fatal(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	fatal(enc.Encode(result))
}

func cmdExport(args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	profileFile := fs.String("p", "", "profile json file")
	_ = fs.Parse(args)
	if *profileFile == "" {
		fatal(fmt.Errorf("missing -p profile file"))
	}
	var p profile.Profile
	fatal(readJSON(*profileFile, &p))
	link, err := export.ToShareLink(p)
	if err != nil {
		fatal(err)
	}
	fmt.Println(link)
}

func readInput(file string) (string, error) {
	if file == "" {
		b, err := io.ReadAll(os.Stdin)
		return string(b), err
	}
	b, err := os.ReadFile(file)
	return string(b), err
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
