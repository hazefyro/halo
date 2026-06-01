package hasher

type Hasher interface {
	Hash(password string) (string, error)
	Verify(hash, password string) error
}
