// Command report renders a Ginkgo JUnit file as one self-contained HTML page,
// the human half of the artifact CI attaches to every e2e run.
//
// Specs are grouped by the trailing Ginkgo label of their container - every
// suite in tests/e2e-go carries one. Setup nodes such as [BeforeSuite] appear
// only when they failed: green plumbing is noise, red plumbing is the story.
package main

import (
	"encoding/xml"
	"fmt"
	"html/template"
	"os"
	"regexp"
	"strings"
)

type junitFile struct {
	Suites []struct {
		Timestamp string     `xml:"timestamp,attr"`
		Cases     []testCase `xml:"testcase"`
	} `xml:"testsuite"`
}

type testCase struct {
	Name    string   `xml:"name,attr"`
	Time    float64  `xml:"time,attr"`
	Failure *outcome `xml:"failure"`
	Error   *outcome `xml:"error"`
	Skipped *outcome `xml:"skipped"`
}

type outcome struct {
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

// The three states a spec renders in; the template's CSS classes carry the
// same names.
const (
	statePass = "pass"
	stateFail = "fail"
	stateSkip = "skip"
)

type spec struct {
	Name    string
	State   string // statePass, stateFail, stateSkip
	Seconds float64
	Detail  string
	BarPct  float64
}

type group struct {
	Label   string
	Title   string
	Specs   []spec
	Seconds float64
}

type report struct {
	Timestamp string
	Passed    int
	Failed    int
	Skipped   int
	Seconds   float64
	Verdict   string
	Groups    []group
}

var trailingLabel = regexp.MustCompile(`\s\[([A-Za-z0-9_-]+)\]$`)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: report <junit.xml> <out.html>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var file junitFile
	if err := xml.Unmarshal(raw, &file); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	rep := build(file)
	out, err := os.Create(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := page.Execute(out, rep); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := out.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func build(file junitFile) report {
	rep := report{}
	groups := map[string]*group{}
	var order []string
	longest := 0.0

	for _, suite := range file.Suites {
		if rep.Timestamp == "" {
			rep.Timestamp = suite.Timestamp
		}
		for _, c := range suite.Cases {
			s := spec{Name: c.Name, Seconds: c.Time, State: statePass}
			switch {
			case c.Failure != nil:
				s.State, s.Detail = stateFail, detail(c.Failure)
			case c.Error != nil:
				s.State, s.Detail = stateFail, detail(c.Error)
			case c.Skipped != nil:
				s.State, s.Detail = stateSkip, detail(c.Skipped)
			}

			label := "other"
			if rest, ok := strings.CutPrefix(s.Name, "[It] "); ok {
				s.Name = rest
			} else {
				// A setup or reporting node. Only a red one carries news.
				if s.State != stateFail {
					continue
				}
				label = "setup"
			}
			if m := trailingLabel.FindStringSubmatch(s.Name); m != nil {
				label = m[1]
				s.Name = strings.TrimSuffix(s.Name, m[0])
			}

			switch s.State {
			case stateFail:
				rep.Failed++
			case stateSkip:
				rep.Skipped++
			default:
				rep.Passed++
			}
			rep.Seconds += s.Seconds
			if s.Seconds > longest {
				longest = s.Seconds
			}

			g, ok := groups[label]
			if !ok {
				g = &group{Label: label}
				groups[label] = g
				order = append(order, label)
			}
			g.Specs = append(g.Specs, s)
			g.Seconds += s.Seconds
		}
	}

	rep.Groups = make([]group, 0, len(order))
	for _, label := range order {
		g := *groups[label]
		// Every spec of one container repeats the container's text; the
		// shared prefix reads once as the section title instead.
		g.Title = g.Label
		if prefix := commonWordPrefix(g.Specs); strings.Count(prefix, " ") >= 1 {
			g.Title = strings.TrimSpace(prefix)
			for i := range g.Specs {
				g.Specs[i].Name = strings.TrimPrefix(g.Specs[i].Name, prefix)
			}
		}
		rep.Groups = append(rep.Groups, g)
	}

	for gi := range rep.Groups {
		for si := range rep.Groups[gi].Specs {
			if longest > 0 {
				pct := rep.Groups[gi].Specs[si].Seconds / longest * 100
				if pct < 0.6 {
					pct = 0.6
				}
				rep.Groups[gi].Specs[si].BarPct = pct
			}
		}
	}

	total := rep.Passed + rep.Failed + rep.Skipped
	switch {
	case rep.Failed > 0:
		rep.Verdict = fmt.Sprintf("%d of %d specs failed", rep.Failed, total)
	case rep.Skipped > 0:
		rep.Verdict = fmt.Sprintf("%d specs passed, %d skipped", rep.Passed, rep.Skipped)
	default:
		rep.Verdict = fmt.Sprintf("all %d specs passed", total)
	}
	return rep
}

// commonWordPrefix returns the whole-word prefix every spec name shares;
// empty when the group holds fewer than two specs.
func commonWordPrefix(specs []spec) string {
	if len(specs) < 2 {
		return ""
	}
	words := strings.Split(specs[0].Name, " ")
	shared := len(words)
	for _, s := range specs[1:] {
		theirs := strings.Split(s.Name, " ")
		if len(theirs) < shared {
			shared = len(theirs)
		}
		for i := 0; i < shared; i++ {
			if words[i] != theirs[i] {
				shared = i
				break
			}
		}
	}
	if shared == 0 {
		return ""
	}
	return strings.Join(words[:shared], " ") + " "
}

func detail(o *outcome) string {
	msg := strings.TrimSpace(o.Message)
	body := strings.TrimSpace(o.Body)
	switch {
	case msg == "":
		return body
	case body == "":
		return msg
	default:
		return msg + "\n\n" + body
	}
}

var page = template.Must(template.New("report").Funcs(template.FuncMap{
	"count": func(n int) string {
		if n == 1 {
			return "1 spec"
		}
		return fmt.Sprintf("%d specs", n)
	},
	"duration": func(s float64) string {
		switch {
		case s < 0.001:
			return "<1 ms"
		case s < 1:
			return fmt.Sprintf("%.0f ms", s*1000)
		default:
			return fmt.Sprintf("%.1f s", s)
		}
	},
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ratelimit e2e report</title>
<style>
  :root {
    --paper: #F6F8F5; --ink: #1C2420; --muted: #5C6B62; --line: #E1E7E1;
    --pass: #1F7A4D; --fail: #B4382E; --skip: #7B8794;
    --bar: #BFD8C9; --bar-bg: #E7EFE9; --detail-bg: #F1E9E6;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --paper: #121815; --ink: #E7EDE8; --muted: #94A49B; --line: #26322A;
      --pass: #4FC98C; --fail: #E5756B; --skip: #8C99A6;
      --bar: #2E4A3A; --bar-bg: #1C2620; --detail-bg: #2A211E;
    }
  }
  body {
    background: var(--paper); color: var(--ink); margin: 0; padding: 40px 20px 64px;
    font: 15px/1.55 -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  }
  .wrap { max-width: 860px; margin: 0 auto; }
  h1 { font-size: 26px; margin: 0; letter-spacing: -.01em; }
  .stamp { color: var(--muted); font-size: 13px; margin: 4px 0 0; }
  .verdict { font-size: 19px; font-weight: 600; margin: 18px 0 0; }
  .verdict.pass { color: var(--pass); }
  .verdict.fail { color: var(--fail); }
  .totals { color: var(--muted); font-size: 13.5px; margin: 4px 0 0; font-variant-numeric: tabular-nums; }
  h2 { font-size: 17px; margin: 0; }
  .suite { margin-top: 36px; }
  .suite-head {
    display: flex; justify-content: space-between; align-items: baseline; gap: 12px;
    border-bottom: 2px solid var(--ink); padding-bottom: 8px;
  }
  .suite-meta {
    font-family: ui-monospace, "SF Mono", Consolas, monospace; font-size: 12px;
    color: var(--muted); white-space: nowrap;
  }
  ul { list-style: none; margin: 0; padding: 0; }
  li { border-bottom: 1px solid var(--line); padding: 8px 2px; }
  .row { display: grid; grid-template-columns: 14px 1fr 76px 120px; gap: 12px; align-items: center; }
  .dot { width: 9px; height: 9px; border-radius: 50%; justify-self: center; }
  .dot.pass { background: var(--pass); }
  .dot.fail { background: var(--fail); }
  .dot.skip { background: transparent; border: 2px solid var(--skip); box-sizing: border-box; }
  .time {
    font-family: ui-monospace, "SF Mono", Consolas, monospace; font-size: 12px; color: var(--muted);
    text-align: right; white-space: nowrap; font-variant-numeric: tabular-nums;
  }
  .bar { height: 5px; background: var(--bar-bg); border-radius: 3px; overflow: hidden; }
  .bar i { display: block; height: 100%; background: var(--bar); }
  .fail-name { color: var(--fail); font-weight: 600; }
  pre {
    margin: 8px 0 2px 26px; padding: 10px 12px; background: var(--detail-bg);
    border-radius: 6px; font-size: 12px; line-height: 1.5; overflow-x: auto; white-space: pre-wrap;
  }
  @media (max-width: 620px) { .row { grid-template-columns: 12px 1fr 70px; } .bar { display: none; } }
</style>
</head>
<body>
<div class="wrap">
  <h1>ratelimit e2e</h1>
  <p class="stamp">{{.Timestamp}}</p>
  <p class="verdict {{if .Failed}}fail{{else}}pass{{end}}">{{.Verdict}}</p>
  <p class="totals">{{.Passed}} passed &middot; {{.Failed}} failed &middot;
    {{.Skipped}} skipped &middot; {{duration .Seconds}} in specs</p>
  {{range .Groups}}
  <section class="suite">
    <div class="suite-head">
      <h2>{{.Title}}</h2>
      <span class="suite-meta">{{.Label}} &middot; {{count (len .Specs)}} &middot; {{duration .Seconds}}</span>
    </div>
    <ul>
      {{range .Specs}}
      <li>
        <div class="row">
          <span class="dot {{.State}}"></span>
          <span {{if eq .State "fail"}}class="fail-name"{{end}}>{{.Name}}</span>
          <span class="time">{{duration .Seconds}}</span>
          <span class="bar"><i style="width: {{printf "%.1f" .BarPct}}%"></i></span>
        </div>
        {{if .Detail}}<pre>{{.Detail}}</pre>{{end}}
      </li>
      {{end}}
    </ul>
  </section>
  {{end}}
</div>
</body>
</html>
`))
