// Package logger provides a customizable logging utility.
package logger

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// LevelTrace is the logging level for trace messages.
const LevelTrace = slog.Level(-6)

// LevelFatal is the logging level for fatal messages.
const LevelFatal = slog.Level(10)

// LevelPanic is the logging level for panic messages.
const LevelPanic = slog.Level(12)

// LevelNames maps logging levels to their human-readable names.
var LevelNames = map[slog.Leveler]string{
	LevelTrace: "TRACE",
	LevelFatal: "FATAL",
	LevelPanic: "PANIC",
}

var logger *slog.Logger

func init() {
	replace := func(groups []string, a slog.Attr) slog.Attr {
		// Format time.
		if a.Key == slog.TimeKey && len(groups) == 0 {
			t := a.Value.Time().Format("2006-01-02 15:04:05")
			return slog.Attr{Key: slog.TimeKey, Value: slog.AnyValue(t)}
		}

		// Format level label.
		if a.Key == slog.LevelKey {
			level := a.Value.Any().(slog.Level)
			levelLabel, exists := LevelNames[level]

			if !exists {
				levelLabel = level.String()
			}
			a.Value = slog.StringValue(levelLabel)
			return a
		}

		// Remove the directory from the source's filename.
		if a.Key == slog.SourceKey {
			source := a.Value.Any().(*slog.Source)
			source.File = filepath.Base(source.File)
		}
		return a
	}

	_, ok := os.LookupEnv("bepassDev")
	if ok {
		logger = slog.New(slog.NewTextHandler(os.Stdout,
			&slog.HandlerOptions{AddSource: true, Level: LevelTrace, ReplaceAttr: replace}))
	} else {
		logger = slog.New(slog.NewTextHandler(os.Stdout,
			&slog.HandlerOptions{AddSource: false, Level: slog.LevelInfo, ReplaceAttr: replace}))
	}
}

// GetLogger returns the global logger instance.
func GetLogger() *slog.Logger {
	return logger
}

func log(ctx context.Context, level slog.Level, msg string, args ...interface{}) {
	if !logger.Enabled(ctx, level) {
		return
	}

	var pcs [1]uintptr
	runtime.Callers(3, pcs[:])
	r := slog.NewRecord(time.Now(), level, msg, pcs[0])
	r.Add(args...)
	_ = logger.Handler().Handle(ctx, r)
}

func logf(ctx context.Context, level slog.Level, format string, args ...interface{}) {
	if !logger.Enabled(ctx, level) {
		return
	}

	var pcs [1]uintptr
	runtime.Callers(3, pcs[:])
	r := slog.NewRecord(time.Now(), level, fmt.Sprintf(format, args...), pcs[0])
	_ = logger.Handler().Handle(ctx, r)
}

// Error logs an error message.
func Error(msg string, args ...interface{}) {
	log(context.Background(), slog.LevelError, msg, args...)
}

// Errorf logs a formatted error message.
func Errorf(format string, args ...interface{}) {
	logf(context.Background(), slog.LevelError, format, args...)
}

// ErrorContext logs an error message within a specified context.
func ErrorContext(ctx context.Context, msg string, args ...interface{}) {
	log(ctx, slog.LevelError, msg, args...)
}

// Info logs an informational message.
func Info(msg string, args ...interface{}) {
	log(context.Background(), slog.LevelInfo, msg, args...)
}

// Infof logs a formatted informational message.
func Infof(format string, args ...interface{}) {
	logf(context.Background(), slog.LevelInfo, format, args...)
}

// Warn logs a warning message.
func Warn(msg string, args ...interface{}) {
	log(context.Background(), slog.LevelWarn, msg, args...)
}

// Warnf logs a formatted warning message.
func Warnf(format string, args ...interface{}) {
	logf(context.Background(), slog.LevelWarn, format, args...)
}

// Debug logs a debug message.
func Debug(msg string, args ...interface{}) {
	log(context.Background(), slog.LevelDebug, msg, args...)
}

// Debugf logs a formatted debug message.
func Debugf(format string, args ...interface{}) {
	logf(context.Background(), slog.LevelDebug, format, args...)
}

// Trace logs a trace message.
func Trace(msg string, args ...interface{}) {
	log(context.Background(), LevelTrace, msg, args...)
}

// Tracef logs a formatted trace message.
func Tracef(format string, args ...interface{}) {
	logf(context.Background(), LevelTrace, format, args...)
}

// Fatal logs a fatal message and exits the program with status code 1.
func Fatal(msg string, args ...interface{}) {
	log(context.Background(), LevelFatal, msg, args...)
	os.Exit(1)
}

// Fatalf logs a formatted fatal message and exits the program with status code 1.
func Fatalf(format string, args ...interface{}) {
	logf(context.Background(), LevelFatal, format, args...)
	os.Exit(1)
}

// Panic logs a panic message and panics.
func Panic(msg string, args ...interface{}) {
	log(context.Background(), LevelPanic, msg, args...)
	panic(msg)
}

// Panicf logs a formatted panic message and panics.
func Panicf(format string, args ...interface{}) {
	logf(context.Background(), LevelPanic, format, args...)
	panic(fmt.Sprintf(format, args...))
}
