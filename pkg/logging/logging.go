
package logging

import "log"

var (
	Info  = log.New(log.Writer(), "[INFO] ", log.LstdFlags|log.Lmsgprefix)
	Warn  = log.New(log.Writer(), "[WARN] ", log.LstdFlags|log.Lmsgprefix)
	Error = log.New(log.Writer(), "[ERROR] ", log.LstdFlags|log.Lmsgprefix)
)
