package master_key

import (
	utils "github.com/duvrdx/oasys-crypto/pkg/encryption"
)

type MasterKey struct {
	Key     []byte
	Salt    []byte
	KeySize int
}

func NewMasterKey(password string, keySize int) (*MasterKey, error) {
	salt, err := utils.GenerateSalt(keySize)

	if err != nil {
		return nil, err
	}

	key, err := utils.DeriveKey([]byte(password), salt, keySize)

	if err != nil {
		return nil, err
	}

	return &MasterKey{
		Key:     key,
		Salt:    salt,
		KeySize: keySize,
	}, nil
}

func (mk *MasterKey) Encrypt(plaintext string) (string, error) {
	return utils.Encrypt(plaintext, mk.Key)
}

func (mk *MasterKey) Decrypt(ciphertext string) (string, error) {
	return utils.Decrypt(ciphertext, mk.Key)
}

func (mk *MasterKey) VerifyDerivedKey(password string) bool {
	return utils.VerifyDerivedKey([]byte(password), mk.Salt, mk.Key, mk.KeySize)

}

func (mk *MasterKey) GetKey() []byte {
	return mk.Key
}

func (mk *MasterKey) GetSalt() []byte {
	return mk.Salt
}

func (mk *MasterKey) GetKeySize() int {
	return mk.KeySize
}

func (mk *MasterKey) SetKey(key []byte) {
	mk.Key = key
}

func (mk *MasterKey) SetSalt(salt []byte) {
	mk.Salt = salt
}

func (mk *MasterKey) SetKeySize(keySize int) {
	mk.KeySize = keySize
}
