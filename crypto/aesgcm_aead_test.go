package crypto

import (
	"crypto/rand"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("AES-GCM", func() {
	var (
		alice, bob                       AEAD
		keyAlice, keyBob, ivAlice, ivBob []byte
	)

	BeforeEach(func() {
		keyAlice = make([]byte, 16)
		keyBob = make([]byte, 16)
		ivAlice = make([]byte, 4)
		ivBob = make([]byte, 4)
		rand.Reader.Read(keyAlice)
		rand.Reader.Read(keyBob)
		rand.Reader.Read(ivAlice)
		rand.Reader.Read(ivBob)
		var err error
		alice, err = NewAEADAESGCM(keyBob, keyAlice, ivBob, ivAlice)
		Expect(err).ToNot(HaveOccurred())
		bob, err = NewAEADAESGCM(keyAlice, keyBob, ivAlice, ivBob)
		Expect(err).ToNot(HaveOccurred())
	})

	It("seals and opens", func() {
		b := alice.Seal(42, []byte("aad"), []byte("foobar"))
		text, err := bob.Open(42, []byte("aad"), b)
		Expect(err).ToNot(HaveOccurred())
		Expect(text).To(Equal([]byte("foobar")))
	})

	It("seals and opens reverse", func() {
		b := bob.Seal(42, []byte("aad"), []byte("foobar"))
		text, err := alice.Open(42, []byte("aad"), b)
		Expect(err).ToNot(HaveOccurred())
		Expect(text).To(Equal([]byte("foobar")))
	})

	It("has the proper length", func() {
		b := bob.Seal(42, []byte("aad"), []byte("foobar"))
		Expect(b).To(HaveLen(6 + 12))
	})

	It("fails with wrong aad", func() {
		b := alice.Seal(42, []byte("aad"), []byte("foobar"))
		_, err := bob.Open(42, []byte("aad2"), b)
		Expect(err).To(HaveOccurred())
	})

	It("rejects wrong key and iv sizes", func() {
		var err error
		e := "AES-GCM: expected 16-byte keys and 4-byte IVs"
		_, err = NewAEADAESGCM(keyBob[1:], keyAlice, ivBob, ivAlice)
		Expect(err).To(MatchError(e))
		_, err = NewAEADAESGCM(keyBob, keyAlice[1:], ivBob, ivAlice)
		Expect(err).To(MatchError(e))
		_, err = NewAEADAESGCM(keyBob, keyAlice, ivBob[1:], ivAlice)
		Expect(err).To(MatchError(e))
		_, err = NewAEADAESGCM(keyBob, keyAlice, ivBob, ivAlice[1:])
		Expect(err).To(MatchError(e))
	})
})