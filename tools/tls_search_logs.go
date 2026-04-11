package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/volcengine/volc-sdk-golang/service/tls"
)

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic("missing env: " + key)
	}
	return v
}

func envInt64(key string, def int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func asString(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func main() {
	endpoint := mustEnv("LOG_SERVICE_ENDPOINT")
	region := mustEnv("LOG_SERVICE_REGION")
	ak := mustEnv("LOG_SERVICE_AK")
	sk := mustEnv("LOG_SERVICE_SK")
	topic := mustEnv("LOG_SERVICE_TOPIC")
	runID := mustEnv("PERSIST_QUERY_RUN_ID")
	token := os.Getenv("LOG_SERVICE_TOKEN")
	expectCount := envInt("PERSIST_QUERY_EXPECT_COUNT", 0)
	expectExact := envInt("PERSIST_QUERY_EXPECT_EXACT", -1)
	allowDuplicates := envInt("PERSIST_QUERY_ALLOW_DUPLICATES", 0) != 0
	limit := envInt("PERSIST_QUERY_LIMIT", 500)
	timeoutMs := envInt64("PERSIST_QUERY_TIMEOUT_MS", 30000)
	pollMs := envInt64("PERSIST_QUERY_POLL_MS", 1000)
	startMs := envInt64("PERSIST_QUERY_START_MS", time.Now().Add(-5*time.Minute).UnixMilli())
	endMs := envInt64("PERSIST_QUERY_END_MS", time.Now().Add(1*time.Minute).UnixMilli())

	cli := tls.NewClient(endpoint, ak, sk, token, region)
	deadline := time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)

	for {
		totalMatches := 0
		seqSet := map[string]struct{}{}
		status := ""
		hitCount := 0
		totalCount := 0
		pages := 0
		for offset := int64(0); ; {
			req := &tls.SearchLogsRequest{
				TopicID:   topic,
				Query:     "*",
				StartTime: startMs,
				EndTime:   endMs,
				Limit:     limit,
				Sort:      "desc",
			}
			if offset > 0 {
				req.Offset = &offset
			}
			resp, err := cli.SearchLogsV2(req)
			if err != nil {
				fmt.Printf("SEARCH_ERR %T %v\n", err, err)
				os.Exit(2)
			}
			pages++
			status = resp.Status
			hitCount = resp.HitCount
			totalCount = resp.Count
			for _, logItem := range resp.Logs {
				if asString(logItem, "run_id") != runID {
					continue
				}
				totalMatches++
				seq := asString(logItem, "seq")
				if seq != "" {
					seqSet[seq] = struct{}{}
				}
			}
			if resp.ListOver || len(resp.Logs) == 0 {
				break
			}
			offset += int64(len(resp.Logs))
		}

		seqs := make([]string, 0, len(seqSet))
		for seq := range seqSet {
			seqs = append(seqs, seq)
		}
		sort.Strings(seqs)

		fmt.Printf("SEARCH_RESULT run_id=%s matches=%d unique_seq=%d duplicates=%d seqs=%v status=%s hit_count=%d count=%d pages=%d\n",
			runID, totalMatches, len(seqSet), totalMatches-len(seqSet), seqs, status, hitCount, totalCount, pages)

		if expectExact >= 0 {
			if len(seqSet) == expectExact && (allowDuplicates || totalMatches == len(seqSet)) {
				os.Exit(0)
			}
			if time.Now().After(deadline) {
				os.Exit(5)
			}
			time.Sleep(time.Duration(pollMs) * time.Millisecond)
			continue
		}

		if expectCount <= 0 || len(seqSet) >= expectCount {
			if !allowDuplicates && totalMatches != len(seqSet) {
				os.Exit(3)
			}
			os.Exit(0)
		}
		if time.Now().After(deadline) {
			os.Exit(4)
		}
		time.Sleep(time.Duration(pollMs) * time.Millisecond)
	}
}
