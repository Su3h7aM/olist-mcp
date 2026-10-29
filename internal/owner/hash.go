package owner

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Bounds on the Argon2id parameters accepted from the configured hash. A hash
// outside them is rejected, so a bad or hostile value cannot make login either
// trivially weak or a denial-of-service.
const (
	argonVersion   = 19
	minMemoryKiB   = 8 * 1024
	maxMemoryKiB   = 256 * 1024
	minTimeCost    = 1
	maxTimeCost    = 10
	minParallelism = 1
	maxParallelism = 8
	minSaltLen     = 16
	maxSaltLen     = 64
	minKeyLen      = 16
	maxKeyLen      = 64
)

type argonHash struct {
	memory  uint32
	time    uint32
	threads uint8
	salt    []byte
	key     []byte
}

// parseArgon2idHash parses a PHC-format string such as
// $argon2id$v=19$m=65536,t=3,p=4$<salt>$<key>. Only canonical base64 is accepted.
func parseArgon2idHash(encoded string) (argonHash, error) {
	var h argonHash
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return h, errors.New("password hash must be argon2id in PHC format")
	}
	if parts[2] != fmt.Sprintf("v=%d", argonVersion) {
		return h, errors.New("unsupported argon2 version")
	}
	fields := strings.Split(parts[3], ",")
	if len(fields) != 3 || !strings.HasPrefix(fields[0], "m=") || !strings.HasPrefix(fields[1], "t=") || !strings.HasPrefix(fields[2], "p=") {
		return h, errors.New("argon2 parameters must be m=,t=,p= in that order")
	}
	m, err := strconv.ParseUint(fields[0][2:], 10, 32)
	if err != nil || m < minMemoryKiB || m > maxMemoryKiB {
		return h, errors.New("argon2 memory is outside the allowed range")
	}
	t, err := strconv.ParseUint(fields[1][2:], 10, 32)
	if err != nil || t < minTimeCost || t > maxTimeCost {
		return h, errors.New("argon2 time cost is outside the allowed range")
	}
	p, err := strconv.ParseUint(fields[2][2:], 10, 8)
	if err != nil || p < minParallelism || p > maxParallelism {
		return h, errors.New("argon2 parallelism is outside the allowed range")
	}
	salt, err := canonicalBase64(parts[4])
	if err != nil || len(salt) < minSaltLen || len(salt) > maxSaltLen {
		return h, errors.New("argon2 salt is malformed or outside the allowed length")
	}
	key, err := canonicalBase64(parts[5])
	if err != nil || len(key) < minKeyLen || len(key) > maxKeyLen {
		return h, errors.New("argon2 key is malformed or outside the allowed length")
	}
	h.memory, h.time, h.threads, h.salt, h.key = uint32(m), uint32(t), uint8(p), salt, key
	return h, nil
}

// canonicalBase64 decodes unpadded standard base64 and rejects any input that
// does not re-encode to exactly the same text.
func canonicalBase64(s string) ([]byte, error) {
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if base64.RawStdEncoding.EncodeToString(b) != s {
		return nil, errors.New("non-canonical base64")
	}
	return b, nil
}

// verify derives a key from password and compares it in constant time.
func (h argonHash) verify(password string) bool {
	derived := argon2.IDKey([]byte(password), h.salt, h.time, h.memory, h.threads, uint32(len(h.key)))
	return subtle.ConstantTimeCompare(derived, h.key) == 1
}
