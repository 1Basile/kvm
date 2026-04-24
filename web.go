package kvm

import (
	"archive/zip"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	gin_logger "github.com/gin-contrib/logger"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jetkvm/kvm/internal/diagnostics"
	"github.com/jetkvm/kvm/internal/logging"
	"github.com/jetkvm/kvm/internal/supervisor"
	"github.com/pion/webrtc/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/vearutop/statigz"
	"golang.org/x/crypto/bcrypt"
)

//nolint:typecheck
//go:embed all:static
var staticFiles embed.FS

type WebRTCSessionRequest struct {
	Sd         string   `json:"sd"`
	OidcGoogle string   `json:"OidcGoogle,omitempty"`
	IP         string   `json:"ip,omitempty"`
	ICEServers []string `json:"iceServers,omitempty"`
}

type SetPasswordRequest struct {
	Password string `json:"password"`
}

type LoginRequest struct {
	Password string `json:"password"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

type LocalDevice struct {
	AuthMode     *string `json:"authMode"`
	DeviceID     string  `json:"deviceId"`
	LoopbackOnly bool    `json:"loopbackOnly"`
}

type DeviceStatus struct {
	IsSetup bool `json:"isSetup"`
}

type SetupRequest struct {
	LocalAuthMode string `json:"localAuthMode"`
	Password      string `json:"password,omitempty"`
}

var cachableFileExtensions = []string{
	".jpg", ".jpeg", ".png", ".svg", ".gif", ".webp", ".ico", ".woff2",
}

// MinPasswordLength is the minimum required length for new passwords.
// This is only enforced when setting or changing passwords, not when
// validating existing passwords (to maintain backward compatibility).
const MinPasswordLength = 8

// MaxPasswordLength is the maximum length bcrypt can hash. Go's bcrypt
// implementation rejects passwords over 72 bytes rather than silently
// truncating them.
const MaxPasswordLength = 72

const (
	// Cache durations for HTTP responses, in seconds.
	cacheImmutableMaxAge = 365 * 24 * 60 * 60 // 1 year
	cacheShortMaxAge     = 5 * 60             // 5 minutes

	// authTokenMaxAge is the lifetime of the authToken cookie, in seconds.
	authTokenMaxAge = 7 * 24 * 60 * 60 // 1 week
)

func setupRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	gin.DisableConsoleColor()
	r := gin.Default()
	r.Use(gin_logger.SetLogger(
		gin_logger.WithLogger(func(*gin.Context, zerolog.Logger) zerolog.Logger {
			return *ginLogger
		}),
	))

	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to get rooted static files subdirectory")
	}
	staticFileServer := http.StripPrefix("/static", statigz.FileServer(
		staticFS.(fs.ReadDirFS),
	))

	// Security headers middleware
	r.Use(func(c *gin.Context) {
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Next()
	})

	// Add a custom middleware to set cache headers for images
	// This is crucial for optimizing the initial welcome screen load time
	// By enabling caching, we ensure that pre-loaded images are stored in the browser cache
	// This allows for a smoother enter animation and improved user experience on the welcome screen
	r.Use(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/static/assets/immutable/") {
			c.Header("Cache-Control", fmt.Sprintf("public, max-age=%d, immutable", cacheImmutableMaxAge))
			c.Next()
			return
		}

		if strings.HasPrefix(c.Request.URL.Path, "/static/") {
			ext := filepath.Ext(c.Request.URL.Path)
			if slices.Contains(cachableFileExtensions, ext) {
				c.Header("Cache-Control", fmt.Sprintf("public, max-age=%d", cacheShortMaxAge))
			}
		}

		c.Next()
	})

	// /clip — unauthenticated clipboard sync page for the target machine.
	// The target opens this URL in their browser; the page auto-reads their
	// clipboard on focus and POSTs it to /api/clip so the operator can receive it.
	r.GET("/clip", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", clipSyncPageHTML)
	})
	r.POST("/api/clip", handleClipPost)
	r.GET("/api/clip", handleClipGet)
	r.GET("/api/clip/out", handleClipOutGet) // operator → target; polled by /clip page on target

	// File transfer — unauthenticated (target side, accessed from /clip page)
	r.POST("/api/transfer", handleTransferUploadTarget)
	r.GET("/api/transfer", handleTransferListTarget)
	r.GET("/api/transfer/:id", handleTransferDownloadTarget)

	r.GET("/robots.txt", func(c *gin.Context) {
		c.Header("Content-Type", "text/plain")
		c.Header("Cache-Control", fmt.Sprintf("public, max-age=%d, immutable", cacheImmutableMaxAge))
		c.String(http.StatusOK, "User-agent: *\nDisallow: /")
	})

	r.Any("/static/*w", func(c *gin.Context) {
		staticFileServer.ServeHTTP(c.Writer, c.Request)
	})

	// Public routes (no authentication required)
	r.POST("/auth/login-local", handleLogin)

	// We use this to determine if the device is setup
	r.GET("/device/status", handleDeviceStatus)

	// We use this to setup the device in the welcome page
	r.POST("/device/setup", handleSetup)

	// A Prometheus metrics endpoint.
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Developer mode protected routes
	developerModeRouter := r.Group("/developer/")
	developerModeRouter.Use(basicAuthProtectedMiddleware(true))
	{
		// pprof
		developerModeRouter.GET("/pprof/", gin.WrapF(pprof.Index))
		developerModeRouter.GET("/pprof/cmdline", gin.WrapF(pprof.Cmdline))
		developerModeRouter.GET("/pprof/profile", gin.WrapF(pprof.Profile))
		developerModeRouter.POST("/pprof/symbol", gin.WrapF(pprof.Symbol))
		developerModeRouter.GET("/pprof/symbol", gin.WrapF(pprof.Symbol))
		developerModeRouter.GET("/pprof/trace", gin.WrapF(pprof.Trace))
		developerModeRouter.GET("/pprof/allocs", gin.WrapH(pprof.Handler("allocs")))
		developerModeRouter.GET("/pprof/block", gin.WrapH(pprof.Handler("block")))
		developerModeRouter.GET("/pprof/goroutine", gin.WrapH(pprof.Handler("goroutine")))
		developerModeRouter.GET("/pprof/heap", gin.WrapH(pprof.Handler("heap")))
		developerModeRouter.GET("/pprof/mutex", gin.WrapH(pprof.Handler("mutex")))
		developerModeRouter.GET("/pprof/threadcreate", gin.WrapH(pprof.Handler("threadcreate")))

		logging.AttachSSEHandler(developerModeRouter)
	}

	// Protected routes (allows both password and noPassword modes)
	protected := r.Group("/")
	protected.Use(protectedMiddleware())
	{
		/*
		 * Legacy WebRTC session endpoint
		 *
		 * This endpoint is maintained for backward compatibility when users upgrade from a version
		 * using the legacy HTTP-based signaling method to the new WebSocket-based signaling method.
		 *
		 * During the upgrade process, when the "Rebooting device after update..." message appears,
		 * the browser still runs the previous JavaScript code which polls this endpoint to establish
		 * a new WebRTC session. Once the session is established, the page will automatically reload
		 * with the updated code.
		 *
		 * Without this endpoint, the stale JavaScript would fail to establish a connection,
		 * causing users to see the "Rebooting device after update..." message indefinitely
		 * until they manually refresh the page, leading to a confusing user experience.
		 */
		protected.POST("/webrtc/session", handleWebRTCSession)
		protected.GET("/webrtc/signaling/client", handleLocalWebRTCSignal)
		protected.POST("/cloud/register", handleCloudRegister)
		protected.GET("/cloud/state", handleCloudState)
		protected.GET("/device", handleDevice)
		protected.POST("/auth/logout", handleLogout)

		protected.POST("/auth/password-local", handleCreatePassword)
		protected.PUT("/auth/password-local", handleUpdatePassword)
		protected.DELETE("/auth/local-password", handleDeletePassword)
		protected.POST("/storage/upload", handleUploadHttp)

		protected.POST("/device/send-wol/:mac-addr", handleSendWOLMagicPacket)

		protected.GET("/diagnostics", handleDiagnosticsDownload)

		protected.GET("/api/clipboard", handleGetClipboard)
		protected.POST("/api/clipboard", handleSetClipboard)
		protected.POST("/api/clip/out", handleClipOutPost) // operator → target

		// File transfer — authenticated (operator side)
		protected.POST("/api/transfer/op", handleTransferUploadOperator)
		protected.GET("/api/transfer/op", handleTransferListOperator)
		protected.GET("/api/transfer/op/:id", handleTransferDownloadOperator)
		protected.DELETE("/api/transfer/:id", handleTransferDelete)
	}

	// Catch-all route for SPA
	r.NoRoute(func(c *gin.Context) {
		if c.Request.Method == "GET" && c.NegotiateFormat(gin.MIMEHTML) == gin.MIMEHTML {
			c.FileFromFS("/", http.FS(staticFS))
			return
		}
		c.Status(http.StatusNotFound)
	})

	return r
}

// clipSyncPageHTML is served at /clip (no auth required). The target machine
// opens this URL in Chrome/Edge, grants clipboard-read permission once, and
// from then on the page auto-reads their clipboard whenever the tab is focused
// and pushes any new content to the shared clipboard buffer via POST /api/clip.
// The KVM operator retrieves it with the existing "Receive from target" button.
var clipSyncPageHTML = []byte(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Clipboard Sync</title>
<style>
*,*::before,*::after{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,sans-serif;background:#f9fafb;color:#111;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:16px}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:32px 28px;width:100%;max-width:420px;box-shadow:0 1px 6px rgba(0,0,0,.07)}
h1{font-size:17px;font-weight:600;margin:0 0 3px}
.sub{font-size:13px;color:#6b7280;margin:0 0 18px}
.status-box{display:flex;align-items:center;gap:10px;background:#f3f4f6;border-radius:7px;padding:11px 14px;margin-bottom:12px;min-height:44px}
.dot{width:9px;height:9px;border-radius:50%;background:#d1d5db;flex-shrink:0;transition:background .3s}
.dot.ok{background:#22c55e;box-shadow:0 0 0 3px rgba(34,197,94,.15)}
.dot.err{background:#ef4444}
.dot.spin{background:#3b82f6;animation:blink 1s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
#msg{font-size:13px;color:#374151;line-height:1.4;word-break:break-word}
.btn{width:100%;padding:10px;border:none;border-radius:7px;font-size:14px;font-weight:500;cursor:pointer;font-family:inherit;background:#111;color:#fff;transition:background .15s;margin-bottom:10px}
.btn:hover{background:#333}
.btn.sec{background:#f3f4f6;color:#111}
.btn.sec:hover{background:#e5e7eb}
.divider{display:flex;align-items:center;gap:10px;margin:2px 0 10px;color:#9ca3af;font-size:12px}
.divider::before,.divider::after{content:'';flex:1;height:1px;background:#e5e7eb}
textarea{width:100%;height:72px;border:1px solid #e5e7eb;border-radius:7px;padding:9px 11px;font-size:13px;font-family:inherit;resize:none;outline:none;color:#111;margin-bottom:10px}
textarea:focus{border-color:#6b7280}
textarea::placeholder{color:#9ca3af}
.preview{margin-top:14px;border-top:1px solid #f3f4f6;padding-top:14px;display:none}
.preview-label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:#9ca3af;margin-bottom:8px}
.preview-item{background:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;padding:8px 10px;margin-bottom:6px;font-size:12px;overflow:hidden}
.preview-item img{max-width:100%;max-height:180px;display:block;border-radius:4px;margin-top:4px}
.preview-item .mime{font-size:10px;color:#9ca3af;margin-bottom:4px}
.hint{font-size:11.5px;color:#9ca3af;margin-top:10px;text-align:center;line-height:1.5}
.mode-bar{display:flex;gap:6px;margin-bottom:18px}
.mode-btn{flex:1;padding:7px;border:1px solid #e5e7eb;border-radius:6px;font-size:13px;cursor:pointer;background:#fff;color:#374151;font-family:inherit;transition:all .15s}
.mode-btn.active{background:#111;color:#fff;border-color:#111}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%) translateY(30px);background:#1e40af;color:#fff;border-radius:9px;padding:12px 18px;font-size:13px;font-weight:500;box-shadow:0 4px 16px rgba(0,0,0,.2);opacity:0;transition:opacity .3s,transform .3s;pointer-events:none;max-width:360px;text-align:center;line-height:1.4;z-index:100}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.drop-zone{border:2px dashed #d1d5db;border-radius:8px;padding:28px 16px;text-align:center;color:#9ca3af;font-size:13px;cursor:pointer;transition:all .2s;margin-bottom:12px}
.drop-zone.drag-over{border-color:#3b82f6;background:#eff6ff;color:#1d4ed8}
.drop-zone input[type=file]{display:none}
.file-list{display:flex;flex-direction:column;gap:6px;margin-bottom:12px}
.file-row{display:flex;align-items:center;justify-content:space-between;background:#f9fafb;border:1px solid #e5e7eb;border-radius:7px;padding:8px 10px;gap:8px}
.file-row-name{font-size:13px;font-weight:500;color:#111;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;min-width:0}
.file-row-meta{font-size:11px;color:#9ca3af;white-space:nowrap;flex-shrink:0}
.file-row-dl{font-size:12px;font-weight:500;color:#2563eb;text-decoration:none;flex-shrink:0}
.file-row-dl:hover{text-decoration:underline}
.section-label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:#9ca3af;margin:14px 0 6px}
.storage-bar-wrap{height:4px;background:#e5e7eb;border-radius:2px;margin-bottom:14px;overflow:hidden}
.storage-bar{height:100%;background:#3b82f6;border-radius:2px;transition:width .4s}
.upload-progress{height:4px;background:#e5e7eb;border-radius:2px;margin-top:6px;overflow:hidden;display:none}
.upload-progress-fill{height:100%;background:#3b82f6;border-radius:2px;transition:width .2s}
</style>
</head>
<body>
<div class="card">
  <div class="mode-bar">
    <button class="mode-btn" id="btnFiles" onclick="setMode('files')">Files</button>
    <button class="mode-btn" id="btnSend" onclick="setMode('send')">Clipboard</button>
    <button class="mode-btn" id="btnRecv" onclick="setMode('recv')">Receive</button>
  </div>

  <!-- SEND MODE -->
  <div id="sendMode">
    <h1>Send Clipboard</h1>
    <p class="sub">Syncs text, images &amp; HTML from this machine to the KVM operator.</p>
    <div class="status-box"><div class="dot" id="sDot"></div><span id="sMsg">Ready</span></div>
    <button class="btn" onclick="sendNow()">Sync Now</button>
    <div class="divider">or paste manually (Firefox)</div>
    <textarea id="pasteArea" placeholder="Paste here (Ctrl+V / Cmd+V) &#8212; works in all browsers"></textarea>
    <div class="preview" id="sendPreview">
      <div class="preview-label">Last synced</div>
      <div id="sendPreviewItems"></div>
    </div>
    <p class="hint">Chrome/Edge: auto-syncs on tab focus (text + images).<br>Firefox: paste below for text.</p>
  </div>

  <!-- RECEIVE MODE -->
  <div id="recvMode" style="display:none">
    <h1>Receive Clipboard</h1>
    <p class="sub">Preview what the target sent, then copy it to your clipboard.</p>
    <div class="status-box"><div class="dot" id="rDot"></div><span id="rMsg">Loading&hellip;</span></div>
    <!-- preview shown BEFORE the copy button so user can inspect first -->
    <div id="recvPreview" style="margin-bottom:14px;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;display:none">
      <div style="padding:8px 12px;background:#f9fafb;border-bottom:1px solid #e5e7eb;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:#6b7280;display:flex;align-items:center;justify-content:space-between">
        <span>From target</span><span id="recvAge" style="font-weight:400;color:#9ca3af"></span>
      </div>
      <div id="recvPreviewItems" style="padding:10px 12px;display:flex;flex-direction:column;gap:8px"></div>
    </div>
    <button class="btn" id="copyBtn" onclick="recvCopy()" style="display:none">Copy to My Clipboard</button>
    <button class="btn sec" onclick="loadRecv()">Refresh</button>
  </div>

  <!-- FILES MODE -->
  <div id="filesMode" style="display:none">
    <h1>File Transfer</h1>
    <p class="sub">Drop files to send to the KVM operator, or download files they sent you.</p>

    <!-- storage usage bar -->
    <div class="storage-bar-wrap"><div class="storage-bar" id="storageBar" style="width:0%"></div></div>
    <div id="storageLabel" style="font-size:11px;color:#9ca3af;margin-bottom:12px;text-align:right"></div>

    <!-- upload to operator -->
    <div class="section-label">Send to operator</div>
    <div class="drop-zone" id="dropZone" onclick="document.getElementById('fileInput').click()">
      <input type="file" id="fileInput" multiple onchange="handleFileInputChange(this)">
      <div>&#128194; Drop files here or <strong>click to browse</strong></div>
      <div style="font-size:11px;margin-top:4px">Max 1&nbsp;GB total &mdash; oldest files removed when full</div>
      <div class="upload-progress" id="uploadProgress"><div class="upload-progress-fill" id="uploadProgressFill" style="width:0%"></div></div>
    </div>
    <div id="uploadStatus" style="font-size:12px;color:#6b7280;margin-bottom:8px;min-height:18px"></div>

    <!-- files from operator -->
    <div class="section-label">From operator</div>
    <div id="opFilesList"><div style="font-size:13px;color:#9ca3af">Loading&hellip;</div></div>
    <button class="btn sec" style="margin-top:8px" onclick="loadOpFiles()">&#8635; Refresh</button>
  </div>
</div>
<div class="toast" id="opToast"></div>
<script>
// ── helpers ────────────────────────────────────────────────────────────────
function b64ToBlob(b64, mime) {
  var bin = atob(b64), arr = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return new Blob([arr], {type: mime});
}
async function blobToB64(blob) {
  return new Promise(function(res) {
    var r = new FileReader();
    r.onloadend = function() { res(r.result.split(',')[1]); };
    r.readAsDataURL(blob);
  });
}
function setS(msg, type) {
  document.getElementById('sMsg').textContent = msg;
  document.getElementById('sDot').className = 'dot' + (type ? ' '+type : '');
}
function setR(msg, type) {
  document.getElementById('rMsg').textContent = msg;
  document.getElementById('rDot').className = 'dot' + (type ? ' '+type : '');
}

// ── mode switching ─────────────────────────────────────────────────────────
function setMode(m) {
  document.getElementById('sendMode').style.display = m === 'send' ? '' : 'none';
  document.getElementById('recvMode').style.display = m === 'recv' ? '' : 'none';
  document.getElementById('filesMode').style.display = m === 'files' ? '' : 'none';
  document.getElementById('btnSend').className = 'mode-btn' + (m === 'send' ? ' active' : '');
  document.getElementById('btnRecv').className = 'mode-btn' + (m === 'recv' ? ' active' : '');
  document.getElementById('btnFiles').className = 'mode-btn' + (m === 'files' ? ' active' : '');
  if (m === 'recv') { loadRecv(); startRecvPoll(); } else { stopRecvPoll(); }
  if (m === 'files') { loadOpFiles(); startFilesPoll(); } else { stopFilesPoll(); }
}
// honour hash — default is files
if (location.hash === '#receive') setMode('recv');
else if (location.hash === '#send') setMode('send');
else setMode('files');

// ── send preview (compact confirmation after sync) ─────────────────────────
function sendRenderItems(items) {
  var el = document.getElementById('sendPreviewItems');
  var wrap = document.getElementById('sendPreview');
  el.innerHTML = '';
  if (!items || !items.length) return;
  items.forEach(function(item) {
    item.types.forEach(function(t) {
      var d = document.createElement('div');
      d.className = 'preview-item';
      var label = document.createElement('div');
      label.className = 'mime';
      label.textContent = t.mime;
      d.appendChild(label);
      if (t.mime.startsWith('image/')) {
        var img = document.createElement('img');
        img.src = 'data:' + t.mime + ';base64,' + t.data;
        d.appendChild(img);
      } else if (t.mime === 'text/plain') {
        var pre = document.createElement('div');
        pre.style.cssText = 'white-space:pre-wrap;max-height:80px;overflow:auto;font-size:12px';
        pre.textContent = t.data.length > 200 ? t.data.slice(0,200) + '\u2026' : t.data;
        d.appendChild(pre);
      }
      el.appendChild(d);
    });
  });
  wrap.style.display = '';
}

// ── SEND mode ──────────────────────────────────────────────────────────────
var lastSentHash = null;

async function readRichClipboard() {
  if (!navigator.clipboard || !navigator.clipboard.read) return null;
  try {
    var items = await navigator.clipboard.read();
    var payload = [];
    for (var i = 0; i < items.length; i++) {
      var types = [];
      for (var j = 0; j < items[i].types.length; j++) {
        var mime = items[i].types[j];
        var blob = await items[i].getType(mime);
        var data;
        if (mime.startsWith('text/')) {
          data = await blob.text();
        } else {
          data = await blobToB64(blob);
        }
        types.push({mime: mime, data: data});
      }
      payload.push({types: types});
    }
    return payload;
  } catch(e) { throw e; }
}

async function postClip(payload) {
  var r = await fetch('/api/clip', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  });
  return r.ok;
}

function hashPayload(p) {
  return JSON.stringify(p).length + '|' + (p[0] && p[0].types[0] ? p[0].types[0].data.slice(0,32) : '');
}

function describePayload(payload) {
  var parts = [];
  payload.forEach(function(item) {
    item.types.forEach(function(t) {
      if (t.mime === 'text/plain') parts.push('text (' + t.data.length + ' chars)');
      else if (t.mime.startsWith('image/')) parts.push(t.mime.split('/')[1].toUpperCase() + ' image (' + Math.round(t.data.length * 3 / 4 / 1024) + ' KB)');
      else if (t.mime === 'text/html') parts.push('HTML');
      else parts.push(t.mime);
    });
  });
  return parts.join(', ');
}

async function doSend(payload, force) {
  if (!payload || !payload.length) return;
  var h = hashPayload(payload);
  if (!force && h === lastSentHash) return;
  var desc = describePayload(payload);
  setS('Uploading ' + desc + '\u2026', 'spin');
  try {
    var ok = await postClip(payload);
    if (ok) {
      lastSentHash = h;
      setS('\u2713 Synced: ' + desc, 'ok');
      sendRenderItems(payload);
    } else {
      setS('Sync failed (server error).', 'err');
    }
  } catch(e) { setS('Upload failed: ' + e.message, 'err'); }
}

async function sendNow() {
  setS('Reading clipboard\u2026', 'spin');
  var payload;
  try {
    payload = await readRichClipboard();
  } catch(e) {
    setS('Clipboard read failed: ' + e.message, 'err');
    return;
  }
  if (payload) {
    await doSend(payload, true); // force=true: always upload on manual sync
  } else {
    setS('Paste text below \u2014 auto-read unavailable in this browser.', '');
    document.getElementById('pasteArea').focus();
  }
}

// paste-area fallback (text only, all browsers)
document.getElementById('pasteArea').addEventListener('paste', function(e) {
  var text = (e.clipboardData || window.clipboardData).getData('text');
  if (!text) return;
  setS('Syncing\u2026', 'spin');
  var payload = [{types:[{mime:'text/plain', data:text}]}];
  doSend(payload).then(function() {
    setTimeout(function() { document.getElementById('pasteArea').value=''; }, 600);
  });
});

async function autoSync() {
  var payload = await readRichClipboard();
  if (payload) await doSend(payload);
}
document.addEventListener('visibilitychange', function() { if (!document.hidden) autoSync(); });
window.addEventListener('focus', autoSync);

// ── RECEIVE mode ───────────────────────────────────────────────────────────
var recvItems = null;
var recvPollTimer = null;
var recvLoadedAt = null;

function recvRenderItems(items) {
  var el = document.getElementById('recvPreviewItems');
  var preview = document.getElementById('recvPreview');
  var copyBtn = document.getElementById('copyBtn');
  el.innerHTML = '';
  if (!items || !items.length) {
    preview.style.display = 'none';
    copyBtn.style.display = 'none';
    return;
  }
  items.forEach(function(item) {
    item.types.forEach(function(t) {
      var d = document.createElement('div');
      d.style.cssText = 'background:#f9fafb;border:1px solid #e5e7eb;border-radius:6px;padding:8px 10px;font-size:12px;overflow:hidden';
      var label = document.createElement('div');
      label.style.cssText = 'font-size:10px;color:#9ca3af;margin-bottom:4px;font-family:monospace';
      label.textContent = t.mime;
      d.appendChild(label);
      if (t.mime.startsWith('image/')) {
        var img = document.createElement('img');
        img.src = 'data:' + t.mime + ';base64,' + t.data;
        img.style.cssText = 'max-width:100%;max-height:240px;display:block;border-radius:4px;cursor:pointer';
        img.title = 'Click to open full size';
        img.onclick = function() { window.open(img.src); };
        d.appendChild(img);
        var sz = document.createElement('div');
        sz.style.cssText = 'font-size:10px;color:#9ca3af;margin-top:4px';
        sz.textContent = Math.round(t.data.length * 3 / 4 / 1024) + ' KB';
        d.appendChild(sz);
      } else if (t.mime === 'text/plain') {
        var pre = document.createElement('pre');
        pre.style.cssText = 'margin:0;white-space:pre-wrap;word-break:break-word;max-height:160px;overflow-y:auto;font-size:12px;font-family:inherit;color:#111';
        pre.textContent = t.data.length > 600 ? t.data.slice(0,600) + '\u2026' : t.data;
        d.appendChild(pre);
        var sz = document.createElement('div');
        sz.style.cssText = 'font-size:10px;color:#9ca3af;margin-top:4px';
        sz.textContent = t.data.length.toLocaleString() + ' chars';
        d.appendChild(sz);
      } else if (t.mime === 'text/html') {
        var frame = document.createElement('iframe');
        frame.sandbox = 'allow-same-origin';
        frame.style.cssText = 'width:100%;height:120px;border:none;background:#fff;border-radius:4px';
        d.appendChild(frame);
        // write HTML after appending so srcdoc works cross-browser
        setTimeout(function(f, h) { return function() {
          f.srcdoc = h;
        }; }(frame, t.data), 0);
        var sz = document.createElement('div');
        sz.style.cssText = 'font-size:10px;color:#9ca3af;margin-top:4px';
        sz.textContent = 'HTML \u2014 ' + t.data.length.toLocaleString() + ' chars';
        d.appendChild(sz);
      } else {
        var note = document.createElement('div');
        note.style.color = '#6b7280';
        note.textContent = t.mime + ' \u2014 ' + Math.round(t.data.length * 3 / 4 / 1024) + ' KB';
        d.appendChild(note);
      }
      el.appendChild(d);
    });
  });
  preview.style.display = '';
  copyBtn.style.display = '';
}

function updateRecvAge() {
  if (!recvLoadedAt) return;
  var secs = Math.round((Date.now() - recvLoadedAt) / 1000);
  var txt = secs < 5 ? 'just now' : secs < 60 ? secs + 's ago' : Math.round(secs/60) + 'm ago';
  var el = document.getElementById('recvAge');
  if (el) el.textContent = txt;
}
setInterval(updateRecvAge, 5000);

async function loadRecv() {
  setR('Loading\u2026', 'spin');
  try {
    var r = await fetch('/api/clip');
    var items = await r.json();
    // only re-render if content changed (avoid flicker on poll)
    var newHash = JSON.stringify(items);
    if (newHash !== JSON.stringify(recvItems)) {
      recvItems = items;
      recvRenderItems(recvItems);
      recvLoadedAt = Date.now();
    }
    if (!recvItems || !recvItems.length) {
      setR('Nothing synced yet \u2014 waiting\u2026', '');
    } else {
      updateRecvAge();
      setR('Ready \u2014 inspect the preview, then copy.', 'ok');
    }
  } catch(e) { setR('Failed to load.', 'err'); }
}

function startRecvPoll() {
  stopRecvPoll();
  recvPollTimer = setInterval(loadRecv, 3000);
}
function stopRecvPoll() {
  if (recvPollTimer) { clearInterval(recvPollTimer); recvPollTimer = null; }
}

async function recvCopy() {
  if (!recvItems || !recvItems.length) { setR('Nothing to copy.', 'err'); return; }
  if (!navigator.clipboard || !navigator.clipboard.write) {
    // fallback: copy first text/plain item
    for (var i = 0; i < recvItems.length; i++) {
      for (var j = 0; j < recvItems[i].types.length; j++) {
        var t = recvItems[i].types[j];
        if (t.mime === 'text/plain') {
          await navigator.clipboard.writeText(t.data);
          setR('\u2713 Text copied to clipboard.', 'ok');
          return;
        }
      }
    }
    setR('Cannot write rich clipboard in this browser.', 'err');
    return;
  }
  try {
    // Build ClipboardItems preserving all MIME types
    var clipItems = recvItems.map(function(item) {
      var map = {};
      item.types.forEach(function(t) {
        if (t.mime.startsWith('text/')) {
          map[t.mime] = new Blob([t.data], {type: t.mime});
        } else {
          map[t.mime] = b64ToBlob(t.data, t.mime);
        }
      });
      return new ClipboardItem(map);
    });
    await navigator.clipboard.write(clipItems);
    setR('\u2713 Copied to clipboard (' + clipItems.length + ' item(s)).', 'ok');
  } catch(e) {
    // Fallback to plain text if write() fails (e.g. unsupported MIME in Firefox)
    for (var i = 0; i < recvItems.length; i++) {
      for (var j = 0; j < recvItems[i].types.length; j++) {
        var t = recvItems[i].types[j];
        if (t.mime === 'text/plain') {
          await navigator.clipboard.writeText(t.data);
          setR('\u2713 Text copied (rich types unsupported in this browser).', 'ok');
          return;
        }
      }
    }
    setR('Copy failed: ' + e.message, 'err');
  }
}

// ── OPERATOR → TARGET (clip/out) ──────────────────────────────────────────
var clipOutSeq = 0;
var clipOutToastTimer = null;

function showOpToast(msg) {
  var t = document.getElementById('opToast');
  t.textContent = msg;
  t.classList.add('show');
  if (clipOutToastTimer) clearTimeout(clipOutToastTimer);
  clipOutToastTimer = setTimeout(function() { t.classList.remove('show'); }, 5000);
}

async function applyClipOut(items) {
  if (!items || !items.length) return;
  // Describe what arrived
  var parts = [];
  items.forEach(function(item) {
    item.types.forEach(function(t) {
      if (t.mime === 'text/plain') parts.push('text (' + t.data.length + ' chars)');
      else if (t.mime.startsWith('image/')) parts.push(t.mime.split('/')[1].toUpperCase() + ' image');
      else if (t.mime === 'text/html') parts.push('HTML');
      else parts.push(t.mime);
    });
  });
  var desc = parts.join(', ');
  try {
    if (navigator.clipboard && navigator.clipboard.write) {
      var clipItems = items.map(function(item) {
        var map = {};
        item.types.forEach(function(t) {
          if (t.mime.startsWith('text/')) map[t.mime] = new Blob([t.data], {type: t.mime});
          else map[t.mime] = b64ToBlob(t.data, t.mime);
        });
        return new ClipboardItem(map);
      });
      await navigator.clipboard.write(clipItems);
    } else {
      // Fallback: write first text/plain
      for (var i = 0; i < items.length; i++) {
        for (var j = 0; j < items[i].types.length; j++) {
          if (items[i].types[j].mime === 'text/plain') {
            await navigator.clipboard.writeText(items[i].types[j].data);
            break;
          }
        }
      }
    }
    showOpToast('\u2713 Operator synced to your clipboard: ' + desc);
  } catch(e) {
    showOpToast('Operator sent ' + desc + ' \u2014 tap here to apply');
    document.getElementById('opToast').style.pointerEvents = 'auto';
    document.getElementById('opToast').onclick = async function() {
      try { await navigator.clipboard.write([]); } catch(e2) { /* ignore */ }
      applyClipOut(items);
      document.getElementById('opToast').style.pointerEvents = 'none';
      document.getElementById('opToast').onclick = null;
    };
  }
}

async function pollClipOut() {
  try {
    var r = await fetch('/api/clip/out');
    var d = await r.json();
    if (d.seq && d.seq !== clipOutSeq) {
      var prevSeq = clipOutSeq;
      clipOutSeq = d.seq;
      if (prevSeq !== 0 && d.items && d.items.length) {
        // only auto-apply if this is an update (not initial page load)
        await applyClipOut(d.items);
      }
    }
  } catch(e) { /* ignore network errors */ }
}
setInterval(pollClipOut, 3000);
pollClipOut(); // seed initial seq so first real update triggers apply

// auto-start
autoSync();

// ── FILES mode ─────────────────────────────────────────────────────────────
var filesPollTimer = null;

function startFilesPoll() { stopFilesPoll(); filesPollTimer = setInterval(loadOpFiles, 5000); }
function stopFilesPoll() { if (filesPollTimer) { clearInterval(filesPollTimer); filesPollTimer = null; } }

function fmtBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n/1024).toFixed(1) + ' KB';
  if (n < 1073741824) return (n/1048576).toFixed(1) + ' MB';
  return (n/1073741824).toFixed(2) + ' GB';
}

function fmtAge(iso) {
  var secs = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (secs < 5) return 'just now';
  if (secs < 60) return secs + 's ago';
  if (secs < 3600) return Math.round(secs/60) + 'm ago';
  return Math.round(secs/3600) + 'h ago';
}

async function loadOpFiles() {
  try {
    var r = await fetch('/api/transfer');
    var d = await r.json();
    var el = document.getElementById('opFilesList');
    var bar = document.getElementById('storageBar');
    var lbl = document.getElementById('storageLabel');
    if (bar && d.capBytes) {
      var pct = Math.min(100, Math.round(d.usedBytes / d.capBytes * 100));
      bar.style.width = pct + '%';
      bar.style.background = pct > 80 ? '#ef4444' : '#3b82f6';
      lbl.textContent = fmtBytes(d.usedBytes) + ' / ' + fmtBytes(d.capBytes) + ' used';
    }
    var files = d.files || [];
    if (!files.length) {
      el.innerHTML = '<div style="font-size:13px;color:#9ca3af">No files from operator yet.</div>';
      return;
    }
    el.innerHTML = '';
    var list = document.createElement('div');
    list.className = 'file-list';
    files.forEach(function(f) {
      var row = document.createElement('div');
      row.className = 'file-row';
      var name = document.createElement('div');
      name.className = 'file-row-name';
      name.textContent = f.name;
      name.title = f.name;
      var meta = document.createElement('div');
      meta.className = 'file-row-meta';
      meta.textContent = fmtBytes(f.size) + ' \u00b7 ' + fmtAge(f.uploadedAt);
      var dl = document.createElement('a');
      dl.className = 'file-row-dl';
      dl.href = '/api/transfer/' + f.id;
      dl.textContent = '\u2193 Download';
      dl.download = f.name;
      row.appendChild(name);
      row.appendChild(meta);
      row.appendChild(dl);
      list.appendChild(row);
    });
    el.appendChild(list);
  } catch(e) {
    document.getElementById('opFilesList').innerHTML = '<div style="font-size:13px;color:#ef4444">Failed to load.</div>';
  }
}

// drag & drop + file input upload
var dropZone = document.getElementById('dropZone');
dropZone.addEventListener('dragover', function(e) { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', function() { dropZone.classList.remove('drag-over'); });
dropZone.addEventListener('drop', function(e) {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  uploadFiles(Array.from(e.dataTransfer.files));
});

function handleFileInputChange(input) {
  if (input.files.length) uploadFiles(Array.from(input.files));
  input.value = '';
}

async function uploadFiles(files) {
  if (!files.length) return;
  var status = document.getElementById('uploadStatus');
  var bar = document.getElementById('uploadProgress');
  var fill = document.getElementById('uploadProgressFill');
  bar.style.display = '';
  for (var i = 0; i < files.length; i++) {
    var f = files[i];
    status.textContent = 'Uploading ' + f.name + '\u2026';
    fill.style.width = Math.round((i / files.length) * 100) + '%';
    var fd = new FormData();
    fd.append('file', f);
    try {
      var r = await fetch('/api/transfer', { method: 'POST', body: fd });
      if (!r.ok) {
        var err = await r.json().catch(function() { return {error: 'upload failed'}; });
        status.textContent = '\u274c ' + f.name + ': ' + (err.error || 'upload failed');
        continue;
      }
    } catch(e) {
      status.textContent = '\u274c ' + f.name + ': network error';
      continue;
    }
  }
  fill.style.width = '100%';
  status.textContent = '\u2713 ' + files.length + ' file(s) sent to operator.';
  setTimeout(function() { bar.style.display = 'none'; fill.style.width = '0%'; status.textContent = ''; }, 3000);
}
</script>
</body>
</html>`)

// ClipType holds one MIME-type entry within a clipboard item.
type ClipType struct {
	MIME string `json:"mime"` // e.g. "text/plain", "image/png"
	Data string `json:"data"` // base64-encoded bytes for binary types; raw text for text/* types
}

// ClipItem represents one entry in a multi-item clipboard snapshot.
type ClipItem struct {
	Types []ClipType `json:"types"`
}

// clipboard holds the shared state between target (/clip page) and operator (KVM UI).
var (
	clipboardMu      sync.RWMutex
	clipboardContent string     // plain-text extraction for /api/clipboard (backward compat)
	clipItems        []ClipItem // rich multi-type snapshot: target → operator (GET/POST /api/clip)
	clipOutItems     []ClipItem // rich multi-type snapshot: operator → target (GET/POST /api/clip/out)
	clipOutSeq       uint64     // incremented on every POST to /api/clip/out; lets target detect changes
)

// handleClipPost stores a rich clipboard snapshot POSTed as JSON from the /clip page.
// Also accepts plain text for backward compatibility.
func handleClipPost(c *gin.Context) {
	const maxBody = 16 << 20 // 16 MB
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBody))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "read error"})
		return
	}

	var items []ClipItem
	if strings.HasPrefix(c.GetHeader("Content-Type"), "application/json") {
		if err := json.Unmarshal(body, &items); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
			return
		}
	} else {
		// Plain-text fallback.
		items = []ClipItem{{Types: []ClipType{{MIME: "text/plain", Data: string(body)}}}}
	}

	// Extract plain text for the existing /api/clipboard endpoint.
	text := ""
	for _, item := range items {
		for _, t := range item.Types {
			if t.MIME == "text/plain" {
				text = t.Data
				break
			}
		}
		if text != "" {
			break
		}
	}

	clipboardMu.Lock()
	clipItems = items
	clipboardContent = text
	clipboardMu.Unlock()

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// handleClipGet returns the current rich clipboard snapshot.
func handleClipGet(c *gin.Context) {
	clipboardMu.RLock()
	items := clipItems
	clipboardMu.RUnlock()
	if items == nil {
		items = []ClipItem{}
	}
	c.JSON(http.StatusOK, items)
}

// handleClipOutPost stores a rich clipboard snapshot sent by the operator (React UI)
// for the target machine to receive via GET /api/clip/out.
func handleClipOutPost(c *gin.Context) {
	const maxBody = 16 << 20 // 16 MB
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxBody))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "read error"})
		return
	}
	var items []ClipItem
	if strings.HasPrefix(c.GetHeader("Content-Type"), "application/json") {
		if err := json.Unmarshal(body, &items); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
			return
		}
	} else {
		items = []ClipItem{{Types: []ClipType{{MIME: "text/plain", Data: string(body)}}}}
	}
	clipboardMu.Lock()
	clipOutItems = items
	clipOutSeq++
	seq := clipOutSeq
	clipboardMu.Unlock()
	c.JSON(http.StatusOK, gin.H{"ok": true, "seq": seq})
}

// handleClipOutGet returns the current operator→target clipboard snapshot with a sequence
// number so the /clip page on the target can detect new content without re-rendering.
func handleClipOutGet(c *gin.Context) {
	clipboardMu.RLock()
	items := clipOutItems
	seq := clipOutSeq
	clipboardMu.RUnlock()
	if items == nil {
		items = []ClipItem{}
	}
	c.JSON(http.StatusOK, gin.H{"seq": seq, "items": items})
}

// handleGetClipboard returns plain text for the React UI "Receive from target" button.
func handleGetClipboard(c *gin.Context) {
	clipboardMu.RLock()
	content := clipboardContent
	clipboardMu.RUnlock()
	c.JSON(http.StatusOK, gin.H{"content": content})
}

// handleSetClipboard stores plain text sent by the React UI "Send to target" button.
func handleSetClipboard(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}
	text := string(body)
	clipboardMu.Lock()
	clipboardContent = text
	clipItems = []ClipItem{{Types: []ClipType{{MIME: "text/plain", Data: text}}}}
	clipboardMu.Unlock()
	c.Status(http.StatusNoContent)
}

// resolveMDNSLocal resolves a single .local hostname to an IP via the device's
// persistent mDNS connection. Shared by resolveMDNSCandidate and resolveSDPMDNSCandidates.
func resolveMDNSLocal(hostname string) (net.IP, error) {
	resolveCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for {
		if mDNS != nil {
			ip, err := mDNS.QueryHost(resolveCtx, hostname)
			if err == nil {
				return ip, nil
			}
			if !strings.Contains(err.Error(), "mDNS server not running") {
				return nil, fmt.Errorf("mDNS resolve %s: %w", hostname, err)
			}
		}
		select {
		case <-resolveCtx.Done():
			return nil, fmt.Errorf("mDNS not ready after timeout, cannot resolve %s", hostname)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// resolveSDPMDNSCandidates rewrites any .local ICE candidate addresses embedded
// in an SDP string (non-trickle ICE) with their resolved IPs. Chrome/Vivaldi may
// include obfuscated .local candidates directly in the SDP offer rather than
// trickling them separately, so they bypass resolveMDNSCandidate entirely.
func resolveSDPMDNSCandidates(sdp string) (string, error) {
	// SDP uses \r\n line endings per RFC 4566, but handle \n too.
	sep := "\r\n"
	if !strings.Contains(sdp, "\r\n") {
		sep = "\n"
	}
	lines := strings.Split(sdp, sep)
	localCount := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "a=candidate:") && strings.Contains(line, ".local") {
			localCount++
		}
	}
	dbgLog("resolveSDPMDNSCandidates: SDP has %d candidate lines, %d with .local", func() int {
		n := 0
		for _, l := range lines {
			if strings.HasPrefix(l, "a=candidate:") {
				n++
			}
		}
		return n
	}(), localCount)
	for i, line := range lines {
		if !strings.HasPrefix(line, "a=candidate:") {
			continue
		}
		// candidate attribute format (RFC 8839):
		//   a=candidate:<foundation> <comp> <proto> <prio> <addr> <port> typ <type> ...
		attrVal := strings.TrimPrefix(line, "a=")
		parts := strings.Fields(attrVal)
		if len(parts) < 6 {
			continue
		}
		addr := parts[4]
		if !strings.HasSuffix(addr, ".local") {
			continue
		}
		ip, err := resolveMDNSLocal(addr)
		if err != nil {
			return sdp, err
		}
		dbgLog("resolveSDPMDNSCandidates: %s → %s", addr, ip)
		parts[4] = ip.String()
		lines[i] = "a=" + strings.Join(parts, " ")
	}
	return strings.Join(lines, sep), nil
}

func resolveMDNSCandidate(candidate webrtc.ICECandidateInit) (webrtc.ICECandidateInit, error) {
	if !strings.Contains(candidate.Candidate, ".local") {
		return candidate, nil
	}

	// ICE candidate SDP attribute format (RFC 8839):
	//   candidate:<foundation> <component> <protocol> <priority> <address> <port> typ <type> ...
	// The address is at field index 4.
	parts := strings.Fields(candidate.Candidate)
	if len(parts) < 6 {
		return candidate, nil
	}

	hostname := parts[4]
	if !strings.HasSuffix(hostname, ".local") {
		return candidate, nil
	}

	ip, err := resolveMDNSLocal(hostname)
	if err != nil {
		return candidate, err
	}
	dbgLog("resolveMDNSCandidate: %s → %s", hostname, ip)
	parts[4] = ip.String()
	candidate.Candidate = strings.Join(parts, " ")
	return candidate, nil
}

// TODO: support multiple sessions?
var currentSession *Session

func handleWebRTCSession(c *gin.Context) {
	var req WebRTCSessionRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	// Close the previous session BEFORE creating the new one. Creating a new session while
	// the old one is alive causes two pion ICE agents to compete for the mDNS multicast
	// socket (224.0.0.251:5353). The second bind silently fails and leaves the new agent
	// with a closed mDNS connection, breaking all candidate resolution.
	if currentSession != nil {
		dbgLog("handleWebRTCSession: currentSession!=nil ptr=%p → closing old session first", currentSession.peerConnection)
		writeJSONRPCEvent("otherSessionConnected", nil, currentSession)
		_ = currentSession.peerConnection.Close()
		currentSession = nil
		dbgLog("handleWebRTCSession: old session Close() returned, sleeping 200ms")
		time.Sleep(200 * time.Millisecond)
		dbgLog("handleWebRTCSession: sleep done, creating new session")
	} else {
		dbgLog("handleWebRTCSession: currentSession==nil, creating new session directly")
	}

	session, err := newSession(SessionConfig{MDNSMode: config.NetworkConfig.MDNSMode.String})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	sd, err := session.ExchangeOffer(req.Sd)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	// Cancel any ongoing keyboard macro when session changes
	cancelKeyboardMacro()

	currentSession = session
	transferStoreTouchLastSeen()
	c.JSON(http.StatusOK, gin.H{"sd": sd})
}

var (
	pingMessage = []byte("ping")
	pongMessage = []byte("pong")
)

func handleLocalWebRTCSignal(c *gin.Context) {
	// get the source from the request
	source := c.ClientIP()
	connectionID := uuid.New().String()

	scopedLogger := websocketLogger.With().
		Str("component", "websocket").
		Str("source", source).
		Str("sourceType", "local").
		Logger()

	scopedLogger.Info().Msg("new websocket connection established")

	// Create WebSocket options with InsecureSkipVerify to bypass origin check
	wsOptions := &websocket.AcceptOptions{
		InsecureSkipVerify: true, // Allow connections from any origin
		OnPingReceived: func(ctx context.Context, payload []byte) bool {
			scopedLogger.Debug().Bytes("payload", payload).Msg("ping frame received")

			metricConnectionTotalPingReceivedCount.WithLabelValues("local", source).Inc()
			metricConnectionLastPingReceivedTimestamp.WithLabelValues("local", source).SetToCurrentTime()

			return true
		},
	}

	wsCon, err := websocket.Accept(c.Writer, c.Request, wsOptions)
	if err != nil {
		scopedLogger.Warn().Err(err).Msg("failed to accept websocket connection")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to establish WebSocket connection"})
		return
	}

	// Now use conn for websocket operations
	defer wsCon.Close(websocket.StatusNormalClosure, "")

	err = wsjson.Write(context.Background(), wsCon, gin.H{"type": "device-metadata", "data": gin.H{"deviceVersion": builtAppVersion}})
	if err != nil {
		scopedLogger.Warn().Err(err).Msg("failed to write device metadata")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send device metadata"})
		return
	}

	err = handleWebRTCSignalWsMessages(wsCon, false, source, connectionID, &scopedLogger)
	if err != nil {
		scopedLogger.Warn().Err(err).Msg("websocket session ended with error")
	}
}

func handleWebRTCSignalWsMessages(
	wsCon *websocket.Conn,
	isCloudConnection bool,
	source string,
	connectionID string,
	scopedLogger *zerolog.Logger,
) error {
	runCtx, cancelRun := context.WithCancel(context.Background())
	defer func() {
		if isCloudConnection {
			setCloudConnectionState(CloudConnectionStateDisconnected)
		}
		cancelRun()
	}()

	// connection type
	var sourceType string
	if isCloudConnection {
		sourceType = "cloud"
	} else {
		sourceType = "local"
	}

	l := scopedLogger.With().
		Str("source", source).
		Str("sourceType", sourceType).
		Str("connectionID", connectionID).
		Logger()

	l.Info().Msg("new websocket connection established")

	go func() {
		for {
			time.Sleep(WebsocketPingInterval)

			if ctxErr := runCtx.Err(); ctxErr != nil {
				if !errors.Is(ctxErr, context.Canceled) {
					l.Warn().Str("error", ctxErr.Error()).Msg("websocket connection closed")
				} else {
					l.Trace().Str("error", ctxErr.Error()).Msg("websocket connection closed as the context was canceled")
				}
				return
			}

			// set the timer for the ping duration
			timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
				metricConnectionLastPingDuration.WithLabelValues(sourceType, source).Set(v)
				metricConnectionPingDuration.WithLabelValues(sourceType, source).Observe(v)
			}))

			l.Trace().Msg("sending ping frame")
			err := wsCon.Ping(runCtx)
			if err != nil {
				l.Warn().Str("error", err.Error()).Msg("websocket ping error")
				cancelRun()
				return
			}

			// dont use `defer` here because we want to observe the duration of the ping
			duration := timer.ObserveDuration()

			metricConnectionTotalPingSentCount.WithLabelValues(sourceType, source).Inc()
			metricConnectionLastPingTimestamp.WithLabelValues(sourceType, source).SetToCurrentTime()

			l.Trace().Str("duration", duration.String()).Msg("received pong frame")
		}
	}()

	if isCloudConnection {
		// create a channel to receive the disconnect event, once received, we cancelRun
		cloudDisconnectChan = make(chan error)
		defer func() {
			close(cloudDisconnectChan)
			cloudDisconnectChan = nil
		}()
		go func() {
			for err := range cloudDisconnectChan {
				if err == nil {
					continue
				}
				cloudLogger.Info().Err(err).Msg("disconnecting from cloud due to")
				cancelRun()
			}
		}()
	}

	for {
		typ, msg, err := wsCon.Read(runCtx)
		if err != nil {
			l.Warn().Str("error", err.Error()).Msg("websocket read error")
			return err
		}
		if typ != websocket.MessageText {
			// ignore non-text messages
			continue
		}

		var message struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}

		if bytes.Equal(msg, pingMessage) {
			l.Info().Str("message", string(msg)).Msg("ping message received")
			err = wsCon.Write(context.Background(), websocket.MessageText, pongMessage)
			if err != nil {
				l.Warn().Str("error", err.Error()).Msg("unable to write pong message")
				return err
			}

			metricConnectionTotalPingReceivedCount.WithLabelValues(sourceType, source).Inc()
			metricConnectionLastPingReceivedTimestamp.WithLabelValues(sourceType, source).SetToCurrentTime()

			continue
		}

		err = json.Unmarshal(msg, &message)
		if err != nil {
			l.Warn().Str("error", err.Error()).Msg("unable to parse ws message")
			continue
		}

		if message.Type == "offer" {
			l.Info().Msg("new session request received")
			var req WebRTCSessionRequest
			err = json.Unmarshal(message.Data, &req)
			if err != nil {
				l.Warn().Str("error", err.Error()).Msg("unable to parse session request data")
				continue
			}

			if req.OidcGoogle != "" {
				l.Info().Str("oidcGoogle", req.OidcGoogle).Msg("new session request with OIDC Google")
			}

			metricConnectionSessionRequestCount.WithLabelValues(sourceType, source).Inc()
			metricConnectionLastSessionRequestTimestamp.WithLabelValues(sourceType, source).SetToCurrentTime()
			err = handleSessionRequest(runCtx, wsCon, req, isCloudConnection, source, &l)
			if err != nil {
				l.Warn().Str("error", err.Error()).Msg("error starting new session")
				continue
			}
		} else if message.Type == "new-ice-candidate" {
			l.Info().Str("data", string(message.Data)).Msg("The client sent us a new ICE candidate")
			var candidate webrtc.ICECandidateInit

			// Attempt to unmarshal as a ICECandidateInit
			if err := json.Unmarshal(message.Data, &candidate); err != nil {
				l.Warn().Str("error", err.Error()).Msg("unable to parse incoming ICE candidate data")
				continue
			}

			if candidate.Candidate == "" {
				l.Warn().Msg("empty incoming ICE candidate, skipping")
				continue
			}

			l.Info().Str("data", fmt.Sprintf("%v", candidate)).Msg("unmarshalled incoming ICE candidate")

			if currentSession == nil {
				l.Warn().Msg("no current session, skipping incoming ICE candidate")
				continue
			}

			// Resolve .local mDNS candidates ourselves since pion's ICE mDNS
			// socket is disabled to avoid port 5353 conflicts with the device mDNS.
			candidate, err = resolveMDNSCandidate(candidate)
			if err != nil {
				l.Warn().Str("error", err.Error()).Str("candidate", candidate.Candidate).Msg("failed to resolve mDNS ICE candidate, skipping")
				continue
			}

			l.Info().Str("data", fmt.Sprintf("%v", candidate)).Msg("adding incoming ICE candidate to current session")
			dbgLog("AddICECandidate ptr=%p candidate=%q", currentSession.peerConnection, candidate.Candidate)
			if err = currentSession.peerConnection.AddICECandidate(candidate); err != nil {
				l.Warn().Str("error", err.Error()).Msg("failed to add incoming ICE candidate to our peer connection")
				dbgLog("AddICECandidate FAILED ptr=%p: %v", currentSession.peerConnection, err)
			} else {
				dbgLog("AddICECandidate OK ptr=%p", currentSession.peerConnection)
			}
		}
	}
}

func handleLogin(c *gin.Context) {
	if config.LocalAuthMode == "noPassword" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Login is disabled in noPassword mode"})
		return
	}

	// Check rate limit before processing
	ip := c.ClientIP()
	if allowed, retryAfter := passwordRateLimiter.IsAllowed(ip); !allowed {
		c.Header("Retry-After", fmt.Sprintf("%d", retryAfter))
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":       "Too many failed attempts. Please try again later.",
			"retry_after": retryAfter,
		})
		return
	}

	var req LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(config.HashedPassword), []byte(req.Password))
	if err != nil {
		passwordRateLimiter.RecordFailure(ip)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
		return
	}

	// Clear rate limit on successful login
	passwordRateLimiter.RecordSuccess(ip)

	config.LocalAuthToken = uuid.New().String()

	if err := SaveConfig(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save configuration"})
		return
	}

	// Set the cookie
	c.SetCookie("authToken", config.LocalAuthToken, authTokenMaxAge, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

func handleLogout(c *gin.Context) {
	config.LocalAuthToken = ""
	if err := SaveConfig(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save configuration"})
		return
	}

	// Clear the auth cookie
	c.SetCookie("authToken", "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

func protectedMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if config.LocalAuthMode == "noPassword" {
			c.Next()
			return
		}

		authToken, err := c.Cookie("authToken")
		if err != nil || authToken != config.LocalAuthToken || authToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func sendErrorJsonThenAbort(c *gin.Context, status int, message string) {
	c.JSON(status, gin.H{"error": message})
	c.Abort()
}

func basicAuthProtectedMiddleware(requireDeveloperMode bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if requireDeveloperMode {
			devModeState, err := rpcGetDevModeState()
			if err != nil {
				sendErrorJsonThenAbort(c, http.StatusInternalServerError, "Failed to get developer mode state")
				return
			}

			if !devModeState.Enabled {
				sendErrorJsonThenAbort(c, http.StatusUnauthorized, "Developer mode is not enabled")
				return
			}
		}

		if config.LocalAuthMode == "noPassword" {
			sendErrorJsonThenAbort(c, http.StatusForbidden, "The resource is not available in noPassword mode")
			return
		}

		// calculate basic auth credentials
		_, password, ok := c.Request.BasicAuth()
		if !ok {
			c.Header("WWW-Authenticate", "Basic realm=\"JetKVM\"")
			sendErrorJsonThenAbort(c, http.StatusUnauthorized, "Basic auth is required")
			return
		}

		err := bcrypt.CompareHashAndPassword([]byte(config.HashedPassword), []byte(password))
		if err != nil {
			sendErrorJsonThenAbort(c, http.StatusUnauthorized, "Invalid password")
			return
		}

		c.Next()
	}
}

func getBindAddress(listenPort int) string {
	// Determine the binding address based on the config
	var bindAddress string
	useIPv4 := config.NetworkConfig.IPv4Mode.String != "disabled"
	useIPv6 := config.NetworkConfig.IPv6Mode.String != "disabled"

	if config.LocalLoopbackOnly {
		if useIPv4 && useIPv6 {
			bindAddress = fmt.Sprintf("localhost:%d", listenPort)
		} else if useIPv4 {
			bindAddress = fmt.Sprintf("127.0.0.1:%d", listenPort)
		} else if useIPv6 {
			bindAddress = fmt.Sprintf("[::1]:%d", listenPort)
		}
	} else {
		if useIPv4 && useIPv6 {
			bindAddress = fmt.Sprintf(":%d", listenPort)
		} else if useIPv4 {
			bindAddress = fmt.Sprintf("0.0.0.0:%d", listenPort)
		} else if useIPv6 {
			bindAddress = fmt.Sprintf("[::]:%d", listenPort)
		}
	}
	return bindAddress
}

// setupTargetRouter creates a minimal unauthenticated router for the target
// machine. It serves the /clip sync page and the file-transfer endpoints on a
// dedicated port so the target can reach it without navigating to /clip.
func setupTargetRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Next()
	})

	// Serve the sync page at "/".
	r.GET("/", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", clipSyncPageHTML)
	})

	// Clipboard sync page + APIs (same handlers as main router).
	r.GET("/clip", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", clipSyncPageHTML)
	})
	r.POST("/api/clip", handleClipPost)
	r.GET("/api/clip", handleClipGet)
	r.GET("/api/clip/out", handleClipOutGet)

	// File transfer — target side only (no auth).
	r.POST("/api/transfer", handleTransferUploadTarget)
	r.GET("/api/transfer", handleTransferListTarget)
	r.GET("/api/transfer/:id", handleTransferDownloadTarget)

	return r
}

func RunWebServer() {
	r := setupRouter()

	// Determine the binding address based on the config
	bindAddress := getBindAddress(80) // default port

	// Start the dedicated target sync server on port 45452.
	// It exposes only the unauthenticated /clip + file-transfer endpoints so
	// target machines can bookmark http://<kvm-ip>:45452 without a path.
	go func() {
		targetAddr := getBindAddress(45452)
		logger.Info().Str("bindAddress", targetAddr).Msg("Starting target sync server")
		if err := setupTargetRouter().Run(targetAddr); err != nil {
			logger.Error().Err(err).Msg("Target sync server failed")
		}
	}()

	logger.Info().Str("bindAddress", bindAddress).Bool("loopbackOnly", config.LocalLoopbackOnly).Msg("Starting web server")
	if err := r.Run(bindAddress); err != nil {
		panic(err)
	}
}

func handleDevice(c *gin.Context) {
	response := LocalDevice{
		AuthMode:     &config.LocalAuthMode,
		DeviceID:     GetDeviceID(),
		LoopbackOnly: config.LocalLoopbackOnly,
	}

	c.JSON(http.StatusOK, response)
}

func handleCreatePassword(c *gin.Context) {
	if config.HashedPassword != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password already set"})
		return
	}

	// We only allow users with noPassword mode to set a new password
	// Users with password mode are not allowed to set a new password without providing the old password
	// We have a PUT endpoint for changing the password, use that instead
	if config.LocalAuthMode != "noPassword" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password mode is not enabled"})
		return
	}

	var req SetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if len(req.Password) < MinPasswordLength {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters"})
		return
	}

	if len(req.Password) > MaxPasswordLength {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at most 72 characters"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	config.HashedPassword = string(hashedPassword)
	config.LocalAuthToken = uuid.New().String()
	config.LocalAuthMode = "password"
	if err := SaveConfig(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save configuration"})
		return
	}

	// Set the cookie
	c.SetCookie("authToken", config.LocalAuthToken, authTokenMaxAge, "/", "", false, true)

	c.JSON(http.StatusCreated, gin.H{"message": "Password set successfully"})
}

func handleUpdatePassword(c *gin.Context) {
	if config.HashedPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password is not set"})
		return
	}

	// We only allow users with password mode to change their password
	// Users with noPassword mode are not allowed to change their password
	if config.LocalAuthMode != "password" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password mode is not enabled"})
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.OldPassword == "" || req.NewPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Validate new password length (not old password - may be shorter from before this requirement)
	if len(req.NewPassword) < MinPasswordLength {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters"})
		return
	}

	if len(req.NewPassword) > MaxPasswordLength {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at most 72 characters"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(config.HashedPassword), []byte(req.OldPassword)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect old password"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash new password"})
		return
	}

	config.HashedPassword = string(hashedPassword)
	config.LocalAuthToken = uuid.New().String()
	if err := SaveConfig(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save configuration"})
		return
	}

	// Set the cookie
	c.SetCookie("authToken", config.LocalAuthToken, authTokenMaxAge, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
}

func handleDeletePassword(c *gin.Context) {
	if config.HashedPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password is not set"})
		return
	}

	if config.LocalAuthMode != "password" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password mode is not enabled"})
		return
	}

	var req LoginRequest // Reusing LoginRequest struct for password
	if err := c.ShouldBindJSON(&req); err != nil || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(config.HashedPassword), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect password"})
		return
	}

	// Disable password
	config.HashedPassword = ""
	config.LocalAuthToken = ""
	config.LocalAuthMode = "noPassword"
	if err := SaveConfig(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save configuration"})
		return
	}

	c.SetCookie("authToken", "", -1, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{"message": "Password disabled successfully"})
}

func handleDeviceStatus(c *gin.Context) {
	// Add CORS headers to allow cross-origin requests
	// This is safe because device/status is a public endpoint
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", "GET, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Content-Type")

	// Handle preflight requests
	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(http.StatusNoContent)
		return
	}

	response := DeviceStatus{
		IsSetup: config.LocalAuthMode != "",
	}

	c.JSON(http.StatusOK, response)
}

func handleCloudState(c *gin.Context) {
	response := CloudState{
		Connected: config.CloudToken != "",
		URL:       config.CloudURL,
		AppURL:    config.CloudAppURL,
	}

	c.JSON(http.StatusOK, response)
}

func handleSetup(c *gin.Context) {
	// Check if the device is already set up
	if config.LocalAuthMode != "" || config.HashedPassword != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Device is already set up"})
		return
	}

	ip := c.ClientIP()
	if allowed, retryAfter := passwordRateLimiter.IsAllowed(ip); !allowed {
		c.Header("Retry-After", fmt.Sprintf("%d", retryAfter))
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":       "Too many failed attempts. Please try again later.",
			"retry_after": retryAfter,
		})
		return
	}

	var req SetupRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		passwordRateLimiter.RecordFailure(ip)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	if req.LocalAuthMode != "password" && req.LocalAuthMode != "noPassword" {
		passwordRateLimiter.RecordFailure(ip)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid localAuthMode"})
		return
	}

	config.LocalAuthMode = req.LocalAuthMode

	if req.LocalAuthMode == "password" {
		if req.Password == "" {
			passwordRateLimiter.RecordFailure(ip)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password is required for password mode"})
			return
		}

		if len(req.Password) < MinPasswordLength {
			passwordRateLimiter.RecordFailure(ip)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters"})
			return
		}

		if len(req.Password) > MaxPasswordLength {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at most 72 characters"})
			return
		}

		// Hash the password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}

		config.HashedPassword = string(hashedPassword)
		config.LocalAuthToken = uuid.New().String()

		// Set the cookie
		c.SetCookie("authToken", config.LocalAuthToken, authTokenMaxAge, "/", "", false, true)
	} else {
		// For noPassword mode, ensure the password field is empty
		config.HashedPassword = ""
		config.LocalAuthToken = ""
	}

	err := SaveConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save config"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Device setup completed successfully"})
}

func handleSendWOLMagicPacket(c *gin.Context) {
	inputMacAddr := c.Param("mac-addr")
	macAddr, err := net.ParseMAC(inputMacAddr)
	if err != nil {
		logger.Warn().Err(err).Str("inputMacAddr", inputMacAddr).Msg("Invalid MAC address provided")
		c.String(http.StatusBadRequest, "Invalid mac address provided")
		return
	}

	macAddrString := macAddr.String()
	broadcastIP := c.Query("broadcastIP")
	err = rpcSendWOLMagicPacket(macAddrString, broadcastIP)
	if err != nil {
		logger.Warn().Err(err).Str("macAddrString", macAddrString).Msg("Failed to send WOL magic packet")
		c.String(http.StatusInternalServerError, "Failed to send WOL to %s: %v", macAddrString, err)
		return
	}

	c.String(http.StatusOK, "WOL sent to %s ", macAddr)
}

func handleDiagnosticsDownload(c *gin.Context) {
	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()

		zw := zip.NewWriter(pw)

		// 1. Application log (full, no truncation)
		if err := addFileToZip(zw, "app.log", supervisor.AppLogPath); err != nil {
			logger.Warn().Err(err).Msg("failed to add app log to diagnostics zip")
		}

		// 2. System diagnostics
		var diagBuf bytes.Buffer
		diag := diagnostics.New(diagnostics.Options{
			Writer: &diagBuf,
			GetSessionInfo: func() diagnostics.SessionInfo {
				info := diagnostics.SessionInfo{
					ActiveSessions:    getActiveSessions(),
					HasCurrentSession: currentSession != nil,
				}
				if currentSession != nil {
					sessionInfo := currentSession.GetDiagnosticsInfo()
					info.ICEConnectionState = sessionInfo.ICEConnectionState
					info.SignalingState = sessionInfo.SignalingState
					info.ConnectionState = sessionInfo.ConnectionState
					info.DataChannels = sessionInfo.DataChannels
				}
				return info
			},
		})
		diag.LogAll("download")
		if err := addBytesToZip(zw, "system-diagnostics.txt", diagBuf.Bytes()); err != nil {
			logger.Warn().Err(err).Msg("failed to add system diagnostics to zip")
		}

		// 3. All crash dumps (full content)
		if entries, err := filepath.Glob(filepath.Join(supervisor.ErrorDumpDir, "jetkvm-*.log")); err == nil {
			for _, path := range entries {
				if err := addFileToZip(zw, "crashes/"+filepath.Base(path), path); err != nil {
					logger.Warn().Err(err).Str("path", path).Msg("failed to add crash dump to zip")
				}
			}
		}

		// 4. Configuration (with secrets redacted)
		redactedConfig := *config
		redactedConfig.CloudToken = ""
		redactedConfig.LocalAuthToken = ""
		redactedConfig.HashedPassword = ""
		redactedConfig.GoogleIdentity = ""
		if configData, err := json.MarshalIndent(redactedConfig, "", "  "); err == nil {
			if err := addBytesToZip(zw, "config.json", configData); err != nil {
				logger.Warn().Err(err).Msg("failed to add config to zip")
			}
		}

		// Close ZIP writer to write central directory (required for valid ZIP)
		if err := zw.Close(); err != nil {
			logger.Error().Err(err).Msg("failed to finalize diagnostics zip")
		}
	}()

	filename := fmt.Sprintf("jetkvm-diagnostics-%s.zip", time.Now().Format("20060102-150405"))
	extraHeaders := map[string]string{
		"Content-Disposition": fmt.Sprintf("attachment; filename=%s", filename),
	}

	c.DataFromReader(http.StatusOK, -1, "application/zip", pr, extraHeaders)
}

func addFileToZip(zw *zip.Writer, name, srcPath string) error {
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()

	w, err := zw.Create(name)
	if err != nil {
		return err
	}

	_, err = io.Copy(w, f)
	return err
}

func addBytesToZip(zw *zip.Writer, name string, data []byte) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
