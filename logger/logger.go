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

const (
	LevelTrace = slog.Level(-6)
	LevelFatal = slog.Level(10)
	LevelPanic = slog.Level(12)
)

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

func GetLogger() *slog.Logger {
	return logger
}

func log(ctx context.Context, level slog.Level, msg string, args ...any) {
	if !logger.Enabled(ctx, level) {
		return
	}

	var pcs [1]uintptr
	runtime.Callers(3, pcs[:])
	r := slog.NewRecord(time.Now(), level, msg, pcs[0])
	r.Add(args...)
	_ = logger.Handler().Handle(ctx, r)
}

func logf(ctx context.Context, level slog.Level, format string, args ...any) {
	if !logger.Enabled(ctx, level) {
		return
	}

	var pcs [1]uintptr
	runtime.Callers(3, pcs[:])
	r := slog.NewRecord(time.Now(), level, fmt.Sprintf(format, args...), pcs[0])
	_ = logger.Handler().Handle(ctx, r)
}

func Error(msg string, args ...any) {
	log(context.Background(), slog.LevelError, msg, args...)
}

func Errorf(format string, args ...any) {
	logf(context.Background(), slog.LevelError, format, args...)
}

func ErrorContext(ctx context.Context, msg string, args ...any) {
	log(ctx, slog.LevelError, msg, args...)
}

func Info(msg string, args ...any) {
	log(context.Background(), slog.LevelInfo, msg, args...)
}

func Infof(format string, args ...any) {
	logf(context.Background(), slog.LevelInfo, format, args...)
}

func Warn(msg string, args ...any) {
	log(context.Background(), slog.LevelWarn, msg, args...)
}

func Warnf(format string, args ...any) {
	logf(context.Background(), slog.LevelWarn, format, args...)
}

func Debug(msg string, args ...any) {
	log(context.Background(), slog.LevelDebug, msg, args...)
}

func Debugf(format string, args ...any) {
	logf(context.Background(), slog.LevelDebug, format, args...)
}

func Trace(msg string, args ...any) {
	log(context.Background(), LevelTrace, msg, args...)
}

func Tracef(format string, args ...any) {
	logf(context.Background(), LevelTrace, format, args...)
}

func Fatal(msg string, args ...any) {
	log(context.Background(), LevelFatal, msg, args...)
	os.Exit(1)
}

func Fatalf(format string, args ...any) {
	logf(context.Background(), LevelFatal, format, args...)
	os.Exit(1)
}

func Panic(msg string, args ...any) {
	log(context.Background(), LevelPanic, msg, args...)
	panic(msg)
}

func Panicf(format string, args ...any) {
	logf(context.Background(), LevelPanic, format, args...)
	panic(fmt.Sprintf(format, args...))
}
