package main

import (
	"strings"
	"testing"
)

func TestFormatSearchResultSummaryModeOmitsSeqs(t *testing.T) {
	got := formatSearchResult("run-x", 3, []string{"1", "2"}, false, "complete", 10, 10, 1)
	if strings.Contains(got, "seqs=") {
		t.Fatalf("expected summary mode to omit seqs, got %q", got)
	}
	if !strings.Contains(got, "duplicates=1") {
		t.Fatalf("expected duplicates field, got %q", got)
	}
}

func TestFormatSearchResultVerboseModeKeepsSeqs(t *testing.T) {
	got := formatSearchResult("run-x", 2, []string{"1", "2"}, true, "complete", 10, 10, 1)
	if !strings.Contains(got, "seqs=[1 2]") {
		t.Fatalf("expected verbose mode to include seqs, got %q", got)
	}
}
