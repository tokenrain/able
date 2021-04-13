package common

import (
	"io"
	stdLog "log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"
)

// import "gopkg.in/natefinch/lumberjack.v2"

// RandomString generates a 40 character string made up of uppercase
// letters, lowercase letters, and numbers.
func RandomString() string {
	chars := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789")
	length := rand.Intn(39) + 1
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteRune(chars[rand.Intn(len(chars))])
	}
	return b.String()
}

// ReverseString reverses any string.
func ReverseString(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// InitLog returns a pointer to a logus.Logger that has been configured
// based on logging specification.
func InitLog(logStdOut bool, logDirName, logFileName, logType string) *logrus.Logger {
	var log = logrus.New()
	var logFile *os.File
	var err error

	// lumberjack for log rotation

	if logStdOut {
		log.Out = os.Stdout
	} else {
		logPath := filepath.Join(logDirName, logFileName)
		logFile, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			stdLog.Fatalf("Can not open %s for writing, %s", logPath, err)
		}
		// If you startup "interactively" then log to stdout even when
		// logfiles are set.
		if terminal.IsTerminal(int(os.Stdout.Fd())) {
			log.Out = io.MultiWriter(logFile, os.Stdout)
		} else {
			log.Out = logFile
		}
	}

	if logType == "line" {
		log.Formatter = &logrus.TextFormatter{
			DisableColors: true,
		}
	} else {
		log.Formatter = &logrus.JSONFormatter{
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime: "@timestamp", // ELK
			},
		}
	}

	return log
}
