package main

import "fmt"

func formatSearchResult(runID string, totalMatches int, seqs []string, includeSeqs bool, status string, hitCount, totalCount, pages int) string {
	duplicates := totalMatches - len(seqs)
	if includeSeqs {
		return fmt.Sprintf("SEARCH_RESULT run_id=%s matches=%d unique_seq=%d duplicates=%d seqs=%v status=%s hit_count=%d count=%d pages=%d", runID, totalMatches, len(seqs), duplicates, seqs, status, hitCount, totalCount, pages)
	}
	return fmt.Sprintf("SEARCH_RESULT run_id=%s matches=%d unique_seq=%d duplicates=%d status=%s hit_count=%d count=%d pages=%d", runID, totalMatches, len(seqs), duplicates, status, hitCount, totalCount, pages)
}
