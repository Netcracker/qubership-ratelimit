package main

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// outcome classifies one sample by what the rate limit did with it.
type outcome uint8

const (
	// admitted is a response that carries x-ratelimit-remaining and is not
	// a 429: the service decided the request and charged its counters.
	admitted outcome = iota
	// refused is a 429, which only the rate limit filter returns here.
	refused
	// undecided is an HTTP response without x-ratelimit-remaining, such as
	// when the filter's call to the service timed out or failed and the
	// filter let the request through. The service may still have charged
	// the counters for it.
	undecided
	// failed is a sample without an HTTP response, such as a connection
	// reset or a client timeout. The request may or may not have been
	// decided and charged.
	failed
)

// sample is one row of a JMeter CSV results file.
type sample struct {
	start   int64 // milliseconds since the epoch
	elapsed int64 // milliseconds, rounded down by JMeter
	label   string
	code    string // the HTTP status, or JMeter's text for a sample without a response
	user    string
	group   string
	kind    string
	lag     int64 // milliseconds the generator sent the request after its scheduled moment
	outcome outcome
}

// end returns the latest moment the sample can have ended: JMeter rounds
// the elapsed time down to a whole millisecond.
func (s sample) end() int64 { return s.start + s.elapsed + 1 }

// jtlColumns locates the columns readJTL reads. The first four are
// JMeter's own; the others are the sample variables of the plan, which
// sample_variables in tests/load/jmeter/loadtest.properties appends.
type jtlColumns struct {
	timeStamp, elapsed, label, responseCode, user, group, kind, remaining, lag int
}

func locateColumns(header []string) (jtlColumns, int, error) {
	at := map[string]int{}
	for i, name := range header {
		at[name] = i
	}
	var c jtlColumns
	width := 0
	for _, col := range []struct {
		name string
		dst  *int
	}{
		{"timeStamp", &c.timeStamp}, {"elapsed", &c.elapsed}, {"label", &c.label},
		{"responseCode", &c.responseCode}, {"user", &c.user}, {"group", &c.group},
		{"kind", &c.kind}, {"remaining", &c.remaining}, {"lag", &c.lag},
	} {
		i, ok := at[col.name]
		if !ok {
			return c, 0, fmt.Errorf("the results have no %s column; header is %v", col.name, header)
		}
		*col.dst = i
		width = max(width, i+1)
	}
	return c, width, nil
}

// readJTL calls fn for every sample of a JMeter CSV results file whose kind
// variable is set, which every sample of the plan's two thread groups has; a
// row without it, from a sampler someone added to the plan, is skipped. The
// file has to carry its header row, and its timeStamp has to be the start of
// the sample (sampleresult.timestamp.start).
func readJTL(r io.Reader, fn func(sample)) error {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	cr.ReuseRecord = true
	header, err := cr.Read()
	if err != nil {
		return fmt.Errorf("reading the header row: %w", err)
	}
	col, width, err := locateColumns(header)
	if err != nil {
		return err
	}
	for line := 2; ; line++ {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		if len(rec) < width {
			return fmt.Errorf("line %d has %d fields; want at least %d", line, len(rec), width)
		}
		kind := rec[col.kind]
		if kind == "" {
			continue
		}
		start, err := strconv.ParseInt(rec[col.timeStamp], 10, 64)
		if err != nil {
			return fmt.Errorf("line %d: timeStamp %q is not milliseconds since the epoch", line, rec[col.timeStamp])
		}
		elapsed, err := strconv.ParseInt(rec[col.elapsed], 10, 64)
		if err != nil {
			return fmt.Errorf("line %d: elapsed %q is not a number", line, rec[col.elapsed])
		}
		lag, err := strconv.ParseInt(rec[col.lag], 10, 64)
		if err != nil {
			return fmt.Errorf("line %d: lag %q is not a number", line, rec[col.lag])
		}
		fn(sample{
			start:   start,
			elapsed: elapsed,
			label:   rec[col.label],
			code:    rec[col.responseCode],
			user:    rec[col.user],
			group:   rec[col.group],
			kind:    kind,
			lag:     lag,
			outcome: classify(rec[col.responseCode], rec[col.remaining]),
		})
	}
}

// classify returns the outcome of a response with the given JMeter response
// code and x-ratelimit-remaining value; the plan saves "-" for a missing
// header.
func classify(code, remaining string) outcome {
	if code == "429" {
		return refused
	}
	if remaining != "" && remaining != "-" {
		return admitted
	}
	if _, err := strconv.Atoi(code); err == nil {
		return undecided
	}
	return failed
}
