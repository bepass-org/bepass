package logger

import (
	"fmt"
	"log"
	"time"
)

// Logger is used to provide debug logger
type Logger interface {
	Errorf(format string, args ...interface{})
	Error(args ...interface{})
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Debug(args ...interface{})
	Debugf(format string, args ...interface{})
	Warn(args ...interface{})
	Warnf(format string, args ...interface{})
	Fatal(args ...interface{})
	Fatalf(format string, args ...interface{})
	Panic(args ...interface{})
}

// Std represents a standard logger
type Std struct {
	*log.Logger
}

// NewLogger creates a new standard logger with log.Logger
func NewLogger(l *log.Logger) *Std {
	return &Std{l}
}

// logLevel represents the log level
type logLevel int

const (
	logLevelError logLevel = iota
	logLevelInfo
	logLevelDebug
	logLevelWarn
	logLevelFatal
	logLevelPanic
)

// logLevelColors represents the ANSI color codes for log levels
var logLevelColors = map[logLevel]string{
	logLevelError: "\033[31m", // Red
	logLevelInfo:  "\033[0m",  // Default
	logLevelDebug: "\033[36m", // Cyan
	logLevelWarn:  "\033[33m", // Yellow
	logLevelFatal: "\033[31m", // Red
	logLevelPanic: "\033[35m", // Magenta
}

// logLevelNames represents the names of log levels
var logLevelNames = map[logLevel]string{
	logLevelError: "E",
	logLevelInfo:  "I",
	logLevelDebug: "D",
	logLevelWarn:  "W",
	logLevelFatal: "F",
	logLevelPanic: "P",
}

// logMessage represents a log message
type logMessage struct {
	level   logLevel
	message string
}

// logf logs a formatted message with a log level
func (sf Std) logf(level logLevel, format string, args ...interface{}) {
	msg := logMessage{
		level:   level,
		message: fmt.Sprintf(format, args...),
	}
	sf.log(msg)
}

// log logs a message with a log level
func (sf Std) loge(level logLevel, args ...interface{}) {
	msg := logMessage{
		level:   level,
		message: fmt.Sprint(args...),
	}
	sf.log(msg)
}

// log logs a log message
func (sf Std) log(msg logMessage) {
	logTime := time.Now().Format("2006-01-02 15:04:05")
	levelColor := logLevelColors[msg.level]
	levelName := logLevelNames[msg.level]

	logFormat := "%s [%s]: %s\033[0m"

	sf.Printf(logFormat, logTime, levelColor+levelName, msg.message)
}

// Errorf implements the Logger interface for formatted error messages
func (sf Std) Errorf(format string, args ...interface{}) {
	sf.logf(logLevelError, format, args...)
}

// Error implements the Logger interface for error messages
func (sf Std) Error(args ...interface{}) {
	sf.loge(logLevelError, args...)
}

// Infof implements the Logger interface for formatted info messages
func (sf Std) Infof(format string, args ...interface{}) {
	sf.logf(logLevelInfo, format, args...)
}

// Info implements the Logger interface for info messages
func (sf Std) Info(args ...interface{}) {
	sf.loge(logLevelInfo, args...)
}

// Debugf implements the Logger interface for formatted debug messages
func (sf Std) Debugf(format string, args ...interface{}) {
	sf.logf(logLevelDebug, format, args...)
}

// Debug implements the Logger interface for debug messages
func (sf Std) Debug(args ...interface{}) {
	sf.loge(logLevelDebug, args...)
}

// Warnf implements the Logger interface for formatted warning messages
func (sf Std) Warnf(format string, args ...interface{}) {
	sf.logf(logLevelWarn, format, args...)
}

// Warn implements the Logger interface for warning messages
func (sf Std) Warn(args ...interface{}) {
	sf.loge(logLevelWarn, args...)
}

// Fatalf implements the Logger interface for formatted fatal messages
func (sf Std) Fatalf(format string, args ...interface{}) {
	sf.logf(logLevelFatal, format, args...)
}

// Fatal implements the Logger interface for fatal messages
func (sf Std) Fatal(args ...interface{}) {
	sf.loge(logLevelFatal, args...)
}

// Panicf implements the Logger interface for formatted panicmessages
func (sf Std) Panicf(format string, args ...interface{}) {
	sf.logf(logLevelPanic, format, args...)
}

// Panic implements the Logger interface for panic messages
func (sf Std) Panic(args ...interface{}) {
	sf.loge(logLevelPanic, args...)
}
