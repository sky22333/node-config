package profile

import "errors"

var (
	ErrInvalidFormat     = errors.New("node-config: invalid format")
	ErrUnsupportedScheme = errors.New("node-config: unsupported scheme")
	ErrUnsupportedType   = errors.New("node-config: unsupported protocol type")
	ErrRemovedInSingBox  = errors.New("node-config: protocol removed in sing-box")
	ErrEmptyInput        = errors.New("node-config: empty input")
	ErrProfileNotFound   = errors.New("node-config: profile not found")
)

// ParseError wraps a parse failure with context.
type ParseError struct {
	Link string
	Err  error
}

func (e *ParseError) Error() string {
	if e.Link == "" {
		return e.Err.Error()
	}
	return e.Err.Error() + ": " + e.Link
}

func (e *ParseError) Unwrap() error { return e.Err }

func NewParseError(link string, err error) error {
	return &ParseError{Link: link, Err: err}
}
