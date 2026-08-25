package logging

import (
	"log"
	"log/slog"
	"os"
)

// Legacy loggers — kept for backward compatibility.
// Existing code using logging.Info.Printf(...) etc. continues to work.
var (
	Info  = log.New(log.Writer(), "[INFO] ", log.LstdFlags|log.Lmsgprefix)
	Warn  = log.New(log.Writer(), "[WARN] ", log.LstdFlags|log.Lmsgprefix)
	Error = log.New(log.Writer(), "[ERROR] ", log.LstdFlags|log.Lmsgprefix)
)

// L is the structured logger (slog). Use this for new code.
// Default: JSON handler writing to stderr with source info.
var L *slog.Logger

func init() {
	SetJSON()
}

// SetJSON configures structured JSON logging to stderr.
func SetJSON() {
	L = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level:     slog.LevelInfo,
		AddSource: true,
	}))
	slog.SetDefault(L)
}

// SetText configures human-readable text logging (useful for dev).
func SetText() {
	L = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level:     slog.LevelInfo,
		AddSource: true,
	}))
	slog.SetDefault(L)
}

// With returns a child logger with additional context fields.
func With(args ...any) *slog.Logger {
	return L.With(args...)
}

// Warnf is a convenience wrapper for callers that used logging.Warnf().
func Warnf(format string, args ...any) {
	Warn.Printf(format, args...)
}
