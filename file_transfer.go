package kvm

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	transfersDir      = "/userdata/jetkvm/transfers"
	transfersMaxBytes = 1 << 30 // 1 GB total cap
	transferIdleClean = time.Hour
)

// TransferFile is the metadata for a single transferred file.
type TransferFile struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Size       int64     `json:"size"`
	UploadedAt time.Time `json:"uploadedAt"`
	From       string    `json:"from"` // "target" | "operator"
}

type transferStore struct {
	mu         sync.RWMutex
	files      []*TransferFile
	totalBytes int64
	// lastSeenAt tracks the most recent file upload or session activity.
	// Used to decide when to auto-clean idle transfers.
	lastSeenAt time.Time
}

var globalTransfers = &transferStore{}

func init() {
	globalTransfers.load()
	go globalTransfers.cleanupLoop()
}

// load scans transfersDir on startup and rebuilds the in-memory index.
func (s *transferStore) load() {
	if err := os.MkdirAll(transfersDir, 0755); err != nil {
		return
	}
	entries, err := os.ReadDir(transfersDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(transfersDir, e.Name()))
		if err != nil {
			continue
		}
		var f TransferFile
		if err := json.Unmarshal(data, &f); err != nil {
			continue
		}
		// Only include entries whose data file actually exists.
		if _, err := os.Stat(filepath.Join(transfersDir, f.ID+".bin")); err != nil {
			continue
		}
		s.files = append(s.files, &f)
		s.totalBytes += f.Size
	}
	sort.Slice(s.files, func(i, j int) bool {
		return s.files[i].UploadedAt.Before(s.files[j].UploadedAt)
	})
	if len(s.files) > 0 {
		s.lastSeenAt = s.files[len(s.files)-1].UploadedAt
	}
}

// cleanupLoop wipes all transfers when the device has had no active WebRTC
// session AND no new uploads for longer than transferIdleClean.
func (s *transferStore) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		idle := time.Since(s.lastSeenAt) > transferIdleClean && currentSession == nil
		if idle && len(s.files) > 0 {
			for _, f := range s.files {
				os.Remove(filepath.Join(transfersDir, f.ID+".bin"))
				os.Remove(filepath.Join(transfersDir, f.ID+".json"))
			}
			s.files = nil
			s.totalBytes = 0
		}
		s.mu.Unlock()
	}
}

// touchLastSeen is called by WebRTC session management to reset the idle clock.
func transferStoreTouchLastSeen() {
	globalTransfers.mu.Lock()
	globalTransfers.lastSeenAt = time.Now()
	globalTransfers.mu.Unlock()
}

// evictOldest removes the oldest files until totalBytes+newSize fits within the cap.
// Caller must hold s.mu.
func (s *transferStore) evictOldest(newSize int64) {
	for len(s.files) > 0 && s.totalBytes+newSize > transfersMaxBytes {
		victim := s.files[0]
		s.files = s.files[1:]
		s.totalBytes -= victim.Size
		os.Remove(filepath.Join(transfersDir, victim.ID+".bin"))
		os.Remove(filepath.Join(transfersDir, victim.ID+".json"))
	}
}

// addFile registers a file whose .bin has already been written to disk.
func (s *transferStore) addFile(f *TransferFile) error {
	meta, err := json.Marshal(f)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evictOldest(f.Size)
	if err := os.WriteFile(filepath.Join(transfersDir, f.ID+".json"), meta, 0644); err != nil {
		return err
	}
	s.files = append(s.files, f)
	s.totalBytes += f.Size
	s.lastSeenAt = time.Now()
	return nil
}

func (s *transferStore) listFrom(from string) []*TransferFile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*TransferFile
	for _, f := range s.files {
		if f.From == from {
			out = append(out, f)
		}
	}
	return out
}

func (s *transferStore) listAll() []*TransferFile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := make([]*TransferFile, len(s.files))
	copy(cp, s.files)
	return cp
}

func (s *transferStore) get(id string) *TransferFile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, f := range s.files {
		if f.ID == id {
			return f
		}
	}
	return nil
}

func (s *transferStore) delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, f := range s.files {
		if f.ID == id {
			s.files = append(s.files[:i], s.files[i+1:]...)
			s.totalBytes -= f.Size
			os.Remove(filepath.Join(transfersDir, f.ID+".bin"))
			os.Remove(filepath.Join(transfersDir, f.ID+".json"))
			return true
		}
	}
	return false
}

func (s *transferStore) usedBytes() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.totalBytes
}

// ── HTTP handlers ─────────────────────────────────────────────────────────────

// uploadHandler streams the uploaded file directly to disk without buffering in RAM.
// We parse multipart manually instead of using ParseMultipartForm, which would buffer
// the entire file in RAM+tmpfs and OOM the device (only ~157 MB total RAM).
func uploadHandler(from string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Parse boundary from Content-Type header.
		_, params, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
		if err != nil || params["boundary"] == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid multipart content-type"})
			return
		}

		// Hard-limit the body to 1 GB to prevent runaway uploads.
		body := http.MaxBytesReader(c.Writer, c.Request.Body, transfersMaxBytes+4<<20)
		mr := multipart.NewReader(body, params["boundary"])

		// Read the first part — we only accept a single "file" field.
		part, err := mr.NextPart()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing file part"})
			return
		}
		filename := filepath.Base(part.FileName())
		if filename == "" || filename == "." {
			c.JSON(http.StatusBadRequest, gin.H{"error": "file field required"})
			return
		}

		if err := os.MkdirAll(transfersDir, 0755); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "storage error"})
			return
		}

		id := uuid.New().String()
		binPath := filepath.Join(transfersDir, id+".bin")
		out, err := os.Create(binPath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "storage error"})
			return
		}

		// Stream directly to disk — io.Copy uses a 32 KB buffer, never loads
		// the whole file into memory.
		n, err := io.Copy(out, part)
		out.Close()
		if err != nil {
			os.Remove(binPath)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "write error"})
			return
		}

		f := &TransferFile{
			ID:         id,
			Name:       filename,
			Size:       n,
			UploadedAt: time.Now(),
			From:       from,
		}
		if err := globalTransfers.addFile(f); err != nil {
			os.Remove(binPath)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "index error"})
			return
		}
		c.JSON(http.StatusOK, f)
	}
}

// handleTransferUploadTarget — POST /api/transfer (no auth): target uploads a file.
func handleTransferUploadTarget(c *gin.Context) { uploadHandler("target")(c) }

// handleTransferUploadOperator — POST /api/transfer/op (auth): operator uploads a file.
func handleTransferUploadOperator(c *gin.Context) { uploadHandler("operator")(c) }

// handleTransferListTarget — GET /api/transfer (no auth): target lists operator files.
func handleTransferListTarget(c *gin.Context) {
	files := globalTransfers.listFrom("operator")
	if files == nil {
		files = []*TransferFile{}
	}
	c.JSON(http.StatusOK, gin.H{
		"files":     files,
		"usedBytes": globalTransfers.usedBytes(),
		"capBytes":  int64(transfersMaxBytes),
	})
}

// handleTransferListOperator — GET /api/transfer/op (auth): operator lists all files.
func handleTransferListOperator(c *gin.Context) {
	files := globalTransfers.listAll()
	if files == nil {
		files = []*TransferFile{}
	}
	c.JSON(http.StatusOK, gin.H{
		"files":     files,
		"usedBytes": globalTransfers.usedBytes(),
		"capBytes":  int64(transfersMaxBytes),
	})
}

// handleTransferDownloadTarget — GET /api/transfer/:id (no auth): target downloads an operator file.
func handleTransferDownloadTarget(c *gin.Context) {
	id := c.Param("id")
	f := globalTransfers.get(id)
	if f == nil || f.From != "operator" {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	serveTransferFile(c, f)
}

// handleTransferDownloadOperator — GET /api/transfer/op/:id (auth): operator downloads any file.
func handleTransferDownloadOperator(c *gin.Context) {
	id := c.Param("id")
	f := globalTransfers.get(id)
	if f == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	serveTransferFile(c, f)
}

// handleTransferDelete — DELETE /api/transfer/:id (auth): delete any file.
func handleTransferDelete(c *gin.Context) {
	id := c.Param("id")
	if !globalTransfers.delete(id) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.Status(http.StatusNoContent)
}

func serveTransferFile(c *gin.Context, f *TransferFile) {
	binPath := filepath.Join(transfersDir, f.ID+".bin")
	fh, err := os.Open(binPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "read error"})
		return
	}
	defer fh.Close()
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, f.Name))
	c.Header("Content-Length", fmt.Sprintf("%d", f.Size))
	c.Header("Cache-Control", "no-store")
	c.DataFromReader(http.StatusOK, f.Size, "application/octet-stream", fh, nil)
}
