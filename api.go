// +build ignore

package argon

func Hash()

// n is the number of iterations
// m is the bytes of memory
// p is the degree of parallelism
// output, password, and salt can be any length
func Key(output, password, salt []byte, n, m, p int)
