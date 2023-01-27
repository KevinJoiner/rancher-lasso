package client

import (
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
)

// RequestModifier is a function used to modify a request before it is sent.
type RequestModifier func(*rest.Request)

// Options holds options specific to lasso Clients.
type Options struct {
	RequestModifiers []RequestModifier
}

// GetOptions holds options for performing get operations with a lasso Clients.
type GetOptions struct {
	Options
	metav1.GetOptions
}

// UpdateOptions holds options for performing update operations with a lasso Clients.
type UpdateOptions struct {
	Options
	metav1.UpdateOptions
}

// CreateOptions holds options for performing create operations with a lasso Clients.
type CreateOptions struct {
	Options
	metav1.CreateOptions
}

// ListOptions holds options for performing list operations with a lasso Clients.
type ListOptions struct {
	Options
	metav1.ListOptions
}

// DeleteOptions holds options for performing delete operations with a lasso Clients.
type DeleteOptions struct {
	Options
	metav1.DeleteOptions
}

// PatchOptions holds options for performing patch operations with a lasso Clients.
type PatchOptions struct {
	Options
	metav1.PatchOptions
}

// SetWarningHandler returns a RequestModifier that adds the given warning handler to the request
func SetWarningHandler(handler rest.WarningHandler) RequestModifier {
	return func(request *rest.Request) {
		request.WarningHandler(handler)
	}
}

// // Impersonate returns a RequestModifier that will add impersonation headers to the request as the given user and groups.
// func Impersonate(rest.ImpersonationConfig) RequestModifier {
// 	return func(request *rest.Request) {
// 		if username != "" {
// 			request.SetHeader("Impersonate-User", username)
// 		}
// 		if len(groups) != 0 {
// 			request.SetHeader("Impersonate-Group", groups...)
// 		}
// 	}
// }

// Impersonate returns a RequestModifier that will add impersonation headers to the request as the given user and groups.
func Impersonate(config rest.ImpersonationConfig) RequestModifier {
	return func(req *rest.Request) {
		req.SetHeader(transport.ImpersonateUserHeader, config.UserName)
		if config.UID != "" {
			req.SetHeader(transport.ImpersonateUIDHeader, config.UID)
		}
		req.SetHeader(transport.ImpersonateGroupHeader, config.Groups...)
		for k, v := range config.Extra {
			req.SetHeader(transport.ImpersonateUserExtraHeaderPrefix+sanitizeHeaderKey(k), v...)

		}
	}
}

func sanitizeHeaderKey(s string) string {
	buf := strings.Builder{}
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch b {
		case '!', '#', '$', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			// valid non alpha numeric characters from https://www.rfc-editor.org/rfc/rfc7230#section-3.2.6
			buf.WriteByte(b)
			continue
		}

		if 'a' <= b && b <= 'z' || '0' <= b && b <= '9' {
			buf.WriteByte(b)
			continue
		}

		// Kubernetes requires lower-case characters
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
			buf.WriteByte(b)
			continue
		}

		// %-encode bytes that should be escaped:
		// https://tools.ietf.org/html/rfc3986#section-2.1
		fmt.Fprintf(&buf, "%%%02X", b)
	}
	return buf.String()
}
