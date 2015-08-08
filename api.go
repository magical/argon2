// Package argon implements the Argon2 password hashing function as specified
// in the document
//
//     https://password-hashing.net/submissions/specs/Argon-v3.pdf
//
// Argon2 comes in two flavors:
//
// Argon2i uses data-independent memory access, making it suitable for hashing secret information such as passwords.
//
// Argon2d uses data-dependent memory access, making it not suitable for hashing secret information due to potential side-channel attacks.
//
package argon

import "errors"

const (
	maxPar = 64

	maxIter = 1<<32 - 1

	minMemory = 8 << 10
	maxMemory = 1<<32 - 1

	minSalt     = 8
	maxSalt     = 1<<32 - 1
	maxPassword = 1<<32 - 1
)

// Key derives a key from the password, salt, and cost parameters.
//
// The salt must be at least 8 bytes long.
func Key(password, salt []byte, n, par int, mem int64, keyLen int) ([]byte, error) {
	if int64(len(password)) > maxPassword {
		return nil, errors.New("argon: password too long")
	}

	if len(salt) < minSalt {
		return nil, errors.New("argon: salt too short")
	} else if int64(len(salt)) > maxSalt {
		return nil, errors.New("argon: salt too long")
	}

	if n < 1 || int64(n) > maxIter {
		return nil, errors.New("argon: invalid n")
	}

	if par < 1 || par > maxPar {
		return nil, errors.New("argon: invalid par")
	}

	if mem < minMemory || mem > maxMemory {
		return nil, errors.New("argon: invalid mem")
	}

	// Round down to a multiple of 4 * par
	mem = mem / (4096 * int64(par)) * (4 * int64(par))

	if mem < 8*int64(par) {
		mem = 8 * int64(par)
	}

	output := make([]byte, keyLen)
	argon2(output, password, salt, nil, nil, uint32(par), uint32(mem), uint32(n), nil)
	return output, nil
}
