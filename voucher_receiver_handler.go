// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

const maxVoucherSize = 10 * 1024 * 1024 // 10MB

// VoucherReceiverHandler handles HTTP requests for receiving vouchers
type VoucherReceiverHandler struct {
	config        *Config
	db            *sqlite.DB
	tokenManager  *VoucherReceiverTokenManager
	deviceStorage *DeviceStorageManager
}

// NewVoucherReceiverHandler creates a new voucher receiver handler
func NewVoucherReceiverHandler(config *Config, db *sqlite.DB, tokenManager *VoucherReceiverTokenManager, deviceStorage *DeviceStorageManager) *VoucherReceiverHandler {
	return &VoucherReceiverHandler{
		config:        config,
		db:            db,
		tokenManager:  tokenManager,
		deviceStorage: deviceStorage,
	}
}

// VoucherResponse is the JSON response structure
type VoucherResponse struct {
	Status    string `json:"status"`
	VoucherID string `json:"voucher_id,omitempty"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

// ServeHTTP handles the HTTP request
func (h *VoucherReceiverHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Only accept POST
	if r.Method != http.MethodPost {
		h.sendError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Authenticate request
	sourceIP := h.getSourceIP(r)
	tokenUsed, authenticated := h.authenticate(ctx, r)
	if !authenticated {
		slog.Warn("voucher receiver: authentication failed", "source_ip", sourceIP)
		h.sendError(w, http.StatusUnauthorized, "authentication required or invalid token")
		return
	}

	// Parse multipart form
	if err := r.ParseMultipartForm(maxVoucherSize); err != nil {
		slog.Warn("voucher receiver: failed to parse multipart form", "error", err, "source_ip", sourceIP)
		h.sendError(w, http.StatusBadRequest, "failed to parse multipart data")
		return
	}

	// Get voucher file
	file, header, err := r.FormFile("voucher")
	if err != nil {
		slog.Warn("voucher receiver: voucher file missing", "error", err, "source_ip", sourceIP)
		h.sendError(w, http.StatusBadRequest, "voucher file missing")
		return
	}
	defer func() {
		if err := file.Close(); err != nil {
			slog.Warn("voucher receiver: failed to close file", "error", err)
		}
	}()

	// Check file size
	if header.Size > maxVoucherSize {
		slog.Warn("voucher receiver: voucher file too large", "size", header.Size, "source_ip", sourceIP)
		h.sendError(w, http.StatusRequestEntityTooLarge, "voucher file exceeds size limit")
		return
	}

	// Read voucher data
	voucherData, err := io.ReadAll(io.LimitReader(file, maxVoucherSize))
	if err != nil {
		slog.Error("voucher receiver: failed to read voucher file", "error", err, "source_ip", sourceIP)
		h.sendError(w, http.StatusInternalServerError, "failed to read voucher file")
		return
	}

	// Parse voucher
	voucher, err := h.parseVoucher(voucherData)
	if err != nil {
		slog.Warn("voucher receiver: failed to parse voucher", "error", err, "source_ip", sourceIP)
		h.sendError(w, http.StatusBadRequest, fmt.Sprintf("invalid voucher format: %v", err))
		return
	}

	guid := voucher.Header.Val.GUID
	guidStr := hex.EncodeToString(guid[:])

	// Get optional metadata
	serial := r.FormValue("serial")
	model := r.FormValue("model")
	manufacturer := r.FormValue("manufacturer")

	slog.Info("voucher receiver: received voucher",
		"guid", guidStr,
		"serial", serial,
		"model", model,
		"manufacturer", manufacturer,
		"source_ip", sourceIP,
		"size", header.Size)

	// Validate ownership if configured
	if h.config.VoucherReceiver.ValidateOwnership {
		valid, err := h.validateOwnership(ctx, voucher)
		if err != nil {
			slog.Error("voucher receiver: ownership validation error", "guid", guidStr, "error", err)
			h.sendError(w, http.StatusInternalServerError, "ownership validation failed")
			return
		}
		if !valid {
			slog.Warn("voucher receiver: voucher not signed to our owner key", "guid", guidStr, "source_ip", sourceIP)
			h.sendError(w, http.StatusForbidden, "voucher not signed to this owner")
			return
		}
	}

	// Check if voucher already exists
	voucherPath := filepath.Join(h.deviceStorage.VoucherDir, guidStr+".fdoov")
	if _, err := os.Stat(voucherPath); err == nil {
		slog.Warn("voucher receiver: voucher already exists", "guid", guidStr, "source_ip", sourceIP)
		h.sendError(w, http.StatusConflict, "voucher already exists for this device")
		return
	}

	// Save voucher to file
	if err := h.saveVoucher(voucherPath, voucherData); err != nil {
		slog.Error("voucher receiver: failed to save voucher", "guid", guidStr, "error", err)
		h.sendError(w, http.StatusInternalServerError, "failed to save voucher")
		return
	}

	// Log to audit table
	if err := h.tokenManager.LogReceivedVoucher(ctx, guid, serial, model, manufacturer, sourceIP, tokenUsed, header.Size); err != nil {
		slog.Error("voucher receiver: failed to log audit entry", "guid", guidStr, "error", err)
	}

	slog.Info("voucher receiver: voucher accepted and stored",
		"guid", guidStr,
		"path", voucherPath,
		"source_ip", sourceIP)

	// Send success response
	h.sendSuccess(w, guidStr, "Voucher accepted and stored")
}

// authenticate checks if the request is authenticated
func (h *VoucherReceiverHandler) authenticate(ctx context.Context, r *http.Request) (string, bool) {
	// If auth not required, allow
	if !h.config.VoucherReceiver.RequireAuth {
		return "", true
	}

	// Get Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", false
	}

	// Parse Bearer token
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}

	token := parts[1]

	// Check global token first
	if h.config.VoucherReceiver.GlobalToken != "" && token == h.config.VoucherReceiver.GlobalToken {
		return "global", true
	}

	// Check database tokens
	valid, err := h.tokenManager.ValidateReceiverToken(ctx, token)
	if err != nil {
		slog.Error("voucher receiver: token validation error", "error", err)
		return "", false
	}

	if valid {
		return token, true
	}

	return "", false
}

// getSourceIP extracts the source IP from the request
func (h *VoucherReceiverHandler) getSourceIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

// parseVoucher parses a voucher from PEM or raw CBOR data
func (h *VoucherReceiverHandler) parseVoucher(data []byte) (*fdo.Voucher, error) {
	// Try parsing as PEM first
	pemData := string(data)
	if strings.Contains(pemData, "-----BEGIN OWNERSHIP VOUCHER-----") {
		start := strings.Index(pemData, "-----BEGIN OWNERSHIP VOUCHER-----")
		end := strings.Index(pemData, "-----END OWNERSHIP VOUCHER-----")
		if start == -1 || end == -1 {
			return nil, fmt.Errorf("invalid PEM format")
		}

		start += len("-----BEGIN OWNERSHIP VOUCHER-----")
		base64Data := strings.TrimSpace(pemData[start:end])
		base64Data = strings.ReplaceAll(base64Data, "\n", "")
		base64Data = strings.ReplaceAll(base64Data, "\r", "")

		cborData, err := base64.StdEncoding.DecodeString(base64Data)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64: %w", err)
		}
		data = cborData
	}

	// Parse CBOR
	var voucher fdo.Voucher
	if err := cbor.Unmarshal(data, &voucher); err != nil {
		return nil, fmt.Errorf("failed to unmarshal voucher: %w", err)
	}

	return &voucher, nil
}

// validateOwnership checks if the voucher is signed to one of our owner keys
func (h *VoucherReceiverHandler) validateOwnership(ctx context.Context, voucher *fdo.Voucher) (bool, error) {
	// Get the last owner public key from the voucher
	voucherOwnerKey, err := voucher.OwnerPublicKey()
	if err != nil {
		return false, fmt.Errorf("failed to extract owner public key from voucher: %w", err)
	}

	// Get all our owner keys
	keyTypes := []protocol.KeyType{
		protocol.Secp256r1KeyType,
		protocol.Secp384r1KeyType,
		protocol.Rsa2048RestrKeyType,
		protocol.RsaPkcsKeyType,
	}

	for _, keyType := range keyTypes {
		ourKey, _, err := h.db.OwnerKey(ctx, keyType, 3072)
		if err != nil {
			// Key type not available, skip
			continue
		}

		// Compare public keys
		if ourKey.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(voucherOwnerKey) {
			return true, nil
		}
	}

	return false, nil
}

// saveVoucher saves the voucher to disk in PEM format
func (h *VoucherReceiverHandler) saveVoucher(path string, data []byte) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// If data is already PEM, write directly
	if strings.Contains(string(data), "-----BEGIN OWNERSHIP VOUCHER-----") {
		return os.WriteFile(path, data, 0644)
	}

	// Convert CBOR to PEM format
	base64Data := base64.StdEncoding.EncodeToString(data)

	// Format PEM with line breaks every 64 characters
	var pemBuilder strings.Builder
	pemBuilder.WriteString("-----BEGIN OWNERSHIP VOUCHER-----\n")
	for i := 0; i < len(base64Data); i += 64 {
		end := i + 64
		if end > len(base64Data) {
			end = len(base64Data)
		}
		pemBuilder.WriteString(base64Data[i:end])
		pemBuilder.WriteString("\n")
	}
	pemBuilder.WriteString("-----END OWNERSHIP VOUCHER-----\n")

	// Write to temp file first, then rename (atomic)
	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, []byte(pemBuilder.String()), 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tempPath, path); err != nil {
		if removeErr := os.Remove(tempPath); removeErr != nil {
			slog.Warn("failed to remove temp file", "path", tempPath, "error", removeErr)
		}
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// sendSuccess sends a successful JSON response
func (h *VoucherReceiverHandler) sendSuccess(w http.ResponseWriter, voucherID, message string) {
	resp := VoucherResponse{
		Status:    "accepted",
		VoucherID: voucherID,
		Message:   message,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to encode success response", "error", err)
	}
}

// sendError sends an error JSON response
func (h *VoucherReceiverHandler) sendError(w http.ResponseWriter, statusCode int, message string) {
	resp := VoucherResponse{
		Status:    "error",
		Message:   message,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to encode error response", "error", err)
	}
}
