package keys

// Storage has many implementation, based on security and sharing requirements
// like disk-backed, mem-backed, vault, db, etc.
type Storage interface {
	Put(name string, salt []byte, key []byte, info Info) error
	Get(name string) ([]byte, []byte, Info, error)
	List() (Infos, error)
	Delete(name string) error
}
