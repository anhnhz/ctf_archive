package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	hmacSecret  string
	metadataURL string
	httpClient  *http.Client
	buildStore  *BuildStore
)

type BuildStore struct {
	mu     sync.RWMutex
	builds map[string]*BuildRecord
}

type BuildRecord struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Image     string `json:"image"`
	StartedAt int64  `json:"started_at"`
	EndedAt   int64  `json:"ended_at,omitempty"`
	Steps     int    `json:"steps_completed"`
	TotalStep int    `json:"steps_total"`
	LogTail   string `json:"log_tail,omitempty"`
}

type FetchArtifactRequest struct {
	URL         string `json:"url"`
	WorkspaceID string `json:"workspace_id"`
	Checksum    string `json:"checksum,omitempty"`
}

type ValidateArtifactRequest struct {
	Artifact json.RawMessage `json:"artifact"`
	Action   string          `json:"action"`
	Target   string          `json:"target"`
	Registry string          `json:"registry,omitempty"`
}

type BuildRunRequest struct {
	Image      string            `json:"image"`
	Tag        string            `json:"tag"`
	Context    string            `json:"context"`
	BuildArgs  map[string]string `json:"build_args,omitempty"`
	Registry   string            `json:"registry"`
	WorkspaceID string           `json:"workspace_id"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	TraceID string `json:"trace_id"`
}

var blockedCIDRs []*net.IPNet

func init() {
	cidrs := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"0.0.0.0/8",
		"100.64.0.0/10",
		"198.18.0.0/15",
		"fc00::/7",
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		blockedCIDRs = append(blockedCIDRs, network)
	}
}

func main() {
	hmacSecret = os.Getenv("HMAC_SECRET")
	metadataURL = os.Getenv("METADATA_URL")
	if metadataURL == "" {
		metadataURL = "http://api-server:6000"
	}

	httpClient = &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	buildStore = &BuildStore{
		builds: make(map[string]*BuildRecord),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/build/fetch-artifact", handleFetchArtifact)
	mux.HandleFunc("/build/validate-artifact", handleValidateArtifact)
	mux.HandleFunc("/build/run", handleBuildRun)
	mux.HandleFunc("/build/status/", handleBuildStatus)
	mux.HandleFunc("/build/health", handleHealth)

	server := &http.Server{
		Addr:         ":9000",
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	fmt.Fprintf(os.Stderr, "build-runner listening on :9000\n")
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func generateTraceID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func generateBuildID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "bld-" + hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code string, msg string) {
	writeJSON(w, status, ErrorResponse{
		Error:   msg,
		Code:    code,
		TraceID: generateTraceID(),
	})
}

func isBlockedHost(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return true
	}

	host := parsed.Hostname()
	if host == "" {
		return true
	}

	lower := strings.ToLower(host)

	blockedHosts := []string{
		"localhost",
		"metadata.google.internal",
		"metadata.internal",
		"instance-data",
		"api-server",
		"build-runner",
		"policy-engine",
		"redis",
		"postgres",
	}
	for _, bh := range blockedHosts {
		if strings.Contains(lower, bh) {
			return true
		}
	}

	if lower == "::1" || lower == "[::1]" || lower == "0:0:0:0:0:0:0:1" {
		return true
	}

	ip := net.ParseIP(host)
	if ip != nil {
		for _, network := range blockedCIDRs {
			if network.Contains(ip) {
				return true
			}
		}

		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return true
		}
	}

	if strings.HasSuffix(lower, ".internal") || strings.HasSuffix(lower, ".local") {
		if lower != "host.docker.internal" {
			return true
		}
	}

	return false
}

func verifyInternalHMAC(r *http.Request, body []byte) bool {
	if hmacSecret == "" {
		return false
	}

	sig := r.Header.Get("X-Internal-HMAC")
	if sig == "" {
		return false
	}

	parts := strings.SplitN(sig, ":", 3)
	if len(parts) != 3 || parts[0] != "SHA256" {
		return false
	}

	ts, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}

	now := time.Now().Unix()
	if now-ts > 30 || ts-now > 5 {
		return false
	}

	mac := hmac.New(sha256.New, []byte(hmacSecret))
	mac.Write([]byte(r.Method))
	mac.Write([]byte(r.URL.Path))
	mac.Write([]byte(parts[1]))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expected), []byte(parts[2]))
}

func handleFetchArtifact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "READ_ERROR", "failed to read request body")
		return
	}
	defer r.Body.Close()

	var req FetchArtifactRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "malformed JSON payload")
		return
	}

	if req.URL == "" {
		writeError(w, http.StatusBadRequest, "MISSING_FIELD", "url is required")
		return
	}

	if req.WorkspaceID == "" {
		writeError(w, http.StatusBadRequest, "MISSING_FIELD", "workspace_id is required")
		return
	}

	if !strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://") {
		writeError(w, http.StatusBadRequest, "INVALID_SCHEME", "only http and https schemes are allowed")
		return
	}

	if isBlockedHost(req.URL) {
		writeError(w, http.StatusForbidden, "SSRF_BLOCKED", "request to internal or reserved address is not allowed")
		return
	}

	fetchReq, err := http.NewRequest(http.MethodGet, req.URL, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_URL", "unable to construct request for the given URL")
		return
	}
	fetchReq.Header.Set("User-Agent", "DarkHarbor-BuildRunner/1.0")
	fetchReq.Header.Set("Accept", "application/octet-stream, application/gzip, */*")

	resp, err := httpClient.Do(fetchReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, "FETCH_FAILED", fmt.Sprintf("artifact fetch failed: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		writeError(w, http.StatusBadGateway, "UPSTREAM_ERROR",
			fmt.Sprintf("upstream returned status %d", resp.StatusCode))
		return
	}

	artifactBody, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20))
	if err != nil {
		writeError(w, http.StatusBadGateway, "READ_FAILED", "failed to read artifact response")
		return
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	result := map[string]interface{}{
		"status":       "fetched",
		"size":         len(artifactBody),
		"content_type": contentType,
		"workspace_id": req.WorkspaceID,
	}

	if strings.HasPrefix(contentType, "application/json") || strings.HasPrefix(contentType, "text/") {
		result["body"] = string(artifactBody)
	} else {
		result["body_b64"] = hex.EncodeToString(artifactBody)
	}

	if req.Checksum != "" {
		h := sha256.Sum256(artifactBody)
		actual := hex.EncodeToString(h[:])
		result["checksum_match"] = actual == req.Checksum
		result["checksum_actual"] = actual
	}

	writeJSON(w, http.StatusOK, result)
}

func handleValidateArtifact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "READ_ERROR", "failed to read request body")
		return
	}
	defer r.Body.Close()

	var req ValidateArtifactRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "malformed JSON payload")
		return
	}

	allowedActions := map[string]bool{
		"export": true,
		"import": true,
		"verify": true,
	}

	if !allowedActions[req.Action] {
		writeError(w, http.StatusBadRequest, "INVALID_ACTION",
			fmt.Sprintf("action must be one of: export, import, verify (got %q)", req.Action))
		return
	}

	if req.Target == "" {
		writeError(w, http.StatusBadRequest, "MISSING_FIELD", "target is required")
		return
	}

	if len(req.Artifact) == 0 {
		writeError(w, http.StatusBadRequest, "MISSING_FIELD", "artifact payload is required")
		return
	}

	var artifactMap map[string]interface{}
	if err := json.Unmarshal(req.Artifact, &artifactMap); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ARTIFACT", "artifact must be a valid JSON object")
		return
	}

	requiredFields := []string{"name", "version", "layers"}
	for _, f := range requiredFields {
		if _, ok := artifactMap[f]; !ok {
			writeError(w, http.StatusBadRequest, "ARTIFACT_SCHEMA",
				fmt.Sprintf("artifact missing required field: %s", f))
			return
		}
	}

	policyPayload := map[string]interface{}{
		"action":   req.Action,
		"target":   req.Target,
		"artifact": artifactMap,
		"registry": req.Registry,
	}

	policyBody, err := json.Marshal(policyPayload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "MARSHAL_ERROR", "failed to encode policy request")
		return
	}

	policyURL := "http://policy-engine:5000/policy/evaluate"
	policyReq, err := http.NewRequest(http.MethodPost, policyURL, bytes.NewReader(policyBody))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create policy request")
		return
	}
	policyReq.Header.Set("Content-Type", "application/json")

	if hmacSecret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		mac := hmac.New(sha256.New, []byte(hmacSecret))
		mac.Write([]byte(policyReq.Method))
		mac.Write([]byte(policyReq.URL.Path))
		mac.Write([]byte(ts))
		mac.Write(policyBody)
		sig := hex.EncodeToString(mac.Sum(nil))
		policyReq.Header.Set("X-Internal-HMAC", fmt.Sprintf("SHA256:%s:%s", ts, sig))
	}

	policyResp, err := httpClient.Do(policyReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, "POLICY_UNREACHABLE", "policy engine is unavailable")
		return
	}
	defer policyResp.Body.Close()

	policyResult, err := io.ReadAll(io.LimitReader(policyResp.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadGateway, "POLICY_READ_ERROR", "failed to read policy response")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(policyResp.StatusCode)
	w.Write(policyResult)
}

func handleBuildRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "READ_ERROR", "failed to read request body")
		return
	}
	defer r.Body.Close()

	isInternal := verifyInternalHMAC(r, body)

	var req BuildRunRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_JSON", "malformed JSON payload")
		return
	}

	if req.Image == "" || req.Tag == "" {
		writeError(w, http.StatusBadRequest, "MISSING_FIELD", "image and tag are required")
		return
	}

	if req.Registry == "" {
		req.Registry = "harbor.darkharbor.internal"
	}

	if !isInternal {
		if req.WorkspaceID == "" {
			writeError(w, http.StatusBadRequest, "MISSING_FIELD", "workspace_id is required")
			return
		}
	}

	buildID := generateBuildID()
	totalSteps := 4
	if len(req.BuildArgs) > 0 {
		totalSteps = 5
	}

	record := &BuildRecord{
		ID:        buildID,
		Status:    "queued",
		Image:     fmt.Sprintf("%s/%s:%s", req.Registry, req.Image, req.Tag),
		StartedAt: time.Now().Unix(),
		TotalStep: totalSteps,
	}

	buildStore.mu.Lock()
	buildStore.builds[buildID] = record
	buildStore.mu.Unlock()

	go simulateBuild(buildID)

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"build_id":    buildID,
		"status":      "queued",
		"image":       record.Image,
		"steps_total": totalSteps,
		"poll_url":    fmt.Sprintf("/build/status/%s", buildID),
	})
}

func simulateBuild(buildID string) {
	buildStore.mu.Lock()
	record, ok := buildStore.builds[buildID]
	if !ok {
		buildStore.mu.Unlock()
		return
	}
	record.Status = "running"
	buildStore.mu.Unlock()

	stages := []string{
		"pulling base image",
		"resolving dependencies",
		"compiling layers",
		"pushing to registry",
		"finalizing manifest",
	}

	for i := 0; i < record.TotalStep && i < len(stages); i++ {
		jitter, _ := rand.Int(rand.Reader, big.NewInt(2000))
		sleepMs := 800 + jitter.Int64()
		time.Sleep(time.Duration(sleepMs) * time.Millisecond)

		buildStore.mu.Lock()
		record.Steps = i + 1
		record.LogTail = stages[i]
		buildStore.mu.Unlock()
	}

	buildStore.mu.Lock()
	record.Status = "completed"
	record.EndedAt = time.Now().Unix()
	buildStore.mu.Unlock()
}

func handleBuildStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	prefix := "/build/status/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "invalid path")
		return
	}

	buildID := strings.TrimPrefix(r.URL.Path, prefix)
	if buildID == "" {
		writeError(w, http.StatusBadRequest, "MISSING_FIELD", "build ID is required")
		return
	}

	buildStore.mu.RLock()
	record, ok := buildStore.builds[buildID]
	buildStore.mu.RUnlock()

	if !ok {
		writeError(w, http.StatusNotFound, "BUILD_NOT_FOUND",
			fmt.Sprintf("no build found with id %q", buildID))
		return
	}

	writeJSON(w, http.StatusOK, record)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "GET required")
		return
	}

	status := map[string]interface{}{
		"service":   "build-runner",
		"status":    "healthy",
		"version":   "1.2.0",
		"timestamp": time.Now().Unix(),
		"uptime_s":  time.Since(startTime).Seconds(),
	}

	policyReq, err := http.NewRequest(http.MethodGet, "http://policy-engine:5000/health", nil)
	if err == nil {
		policyResp, err := httpClient.Do(policyReq)
		if err == nil {
			policyResp.Body.Close()
			status["policy_engine"] = policyResp.StatusCode == 200
		} else {
			status["policy_engine"] = false
		}
	}

	writeJSON(w, http.StatusOK, status)
}

var startTime = time.Now()
