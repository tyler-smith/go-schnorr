package schnorr

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/gcash/bchd/bchec"
)

var (
	curve = bchec.S256()

	bigZero = big.NewInt(0)
)

var (
	ErrEOverflow = errors.New("e has overflowed")
	ErrEIsZero   = errors.New("e is zero")

	ErrPointAtInfinity = errors.New("Point is at infinity")

	ErrSignatureInvalid = errors.New("Signature invalid")
)

/**
 * Custom Schnorr-based signature scheme.
 *
 * Signing:
 *   Inputs:
 *     32-byte message m,
 *     32-byte scalar key x (!=0)
 *     public key point P,
 *     32-byte scalar nonce k (!=0)
 *
 *   Compute point R = k * G. Negate nonce if R.y is not a quadratic residue.
 *   Compute scalar e = Hash(R.x || compressed(P) || m). Reject nonce if e == 0 or e >= order.
 *   Compute scalar s = k + e * x.
 *   The signature is (R.x, s).
 *
 * Verification:
 *   Inputs:
 *     32-byte message m,
 *     public key point P,
 *     signature: (32-byte r, scalar s)
 *
 *   Signature is invalid if s >= order or r >= p.
 *   Compute scalar e = Hash(r || compressed(P) || m). Reject e == 0 or e >= order.
 *   Option 1 (faster for single verification):
 *     Compute point R = s * G - e * P.
 *       Reject if R is infinity or R.y is not a quadratic residue.
 *       Signature is valid if the serialization of R.x equals r.
 *   Option 2 (allows batch validation):
 *     Decompress x coordinate r into point R, with R.y a quadratic residue.
 *       Reject if R is not on the curve.
 *       Signature is valid if R + e * P - s * G == 0.
 */

// type signature [64]byte

type secp256k1_scalar uint32

// type Signature struct {
// 	r []byte
// 	s *big.Int
// }

type Signature []byte

func (s Signature) String() string {
	return hex.EncodeToString(s)
	// return hex.EncodeToString(s.r) + hex.EncodeToString(s.s.Bytes())
}

func Sign(privKey *bchec.PrivateKey, pubKey *bchec.PublicKey, msg []byte) Signature {
	// return signWithNonce(privKey, pubKey, nonceRFC6979(privKey.D, msg), msg)
	return signWithNonce2(privKey, pubKey, nonceRFC6979(privKey.D, msg), msg)
}

// Signing
// Input:

// The secret key d: an integer in the range 1..n-1.
// The message m: a 32-byte array
// To sign m for public key dG:
// Let k' = int(hash(bytes(d) || m)) mod n.
// Fail if k' = 0.
// Let R = k'G.
// Let k = k' if jacobi(y(R)) = 1, otherwise let k = n - k' .
// Let e = int(hash(bytes(x(R)) || bytes(dG) || m)) mod n.
// The signature is bytes(x(R)) || bytes(k + ed mod n).
func signWithNonce2(privKey *bchec.PrivateKey, pubKey *bchec.PublicKey, k *big.Int, msgHash []byte) Signature {
	sig := Signature{}
	if privKey.D.Cmp(bigZero) == 0 {
		return sig
	}

	fmt.Println(hex.EncodeToString(append(privKey.D.Bytes(), msgHash...)))
	// Let k' = int(hash(bytes(d) || m)) mod n.
	kHash := sha256.Sum256(append(privKey.D.Bytes(), msgHash...))
	kPrime := new(big.Int).SetBytes(kHash[:])
	kPrime.Mod(kPrime, curve.N)

	// Fail if k' = 0.
	if kPrime.Cmp(bigZero) == 0 {
		return sig
	}

	// Let R = k'G.
	Rx, Ry := curve.ScalarBaseMult(kPrime.Bytes())

	// Let k = k' if jacobi(y(R)) = 1, otherwise let k = n - k' .
	if Ry.Cmp(curve.N) < 0 {
		k = kPrime
		// k.Neg(k)
	} else {

		// k.Neg(k)
		n := new(big.Int).SetBytes(curve.N.Bytes())
		k = n.Sub(n, kPrime)
	}

	// Normalize
	RxBytes := Rx.Bytes()
	RxBytesArr := [32]byte{}
	for i := 0; i < len(RxBytes); i++ {
		RxBytesArr[i] = RxBytes[i]
	}
	for i := len(RxBytes); i < 32; i++ {
		RxBytesArr[i] = 0
	}
	RxFieldBytes := new(fieldVal).SetBytes(&RxBytesArr).Normalize().Bytes()
	Rx = new(big.Int).SetBytes(RxFieldBytes[:])

	// Let e = int(hash(bytes(x(R)) || bytes(dG) || m)) mod n.
	e, err := computeE(Rx, pubKey, msgHash)
	if err != nil {
		panic(err)
		return sig
	}

	e.Mul(e, privKey.D)
	e.Mod(e, curve.N)

	return append(Rx.Bytes(), e.Bytes()...)

	// The signature is bytes(x(R)) || bytes(k + ed mod n).

	// fmt.Println("Signing with nonce:", hex.EncodeToString(k.Bytes()))

	// if privKey.D.Cmp(bigZero) == 0 || k.Cmp(bigZero) == 0 {
	// 	return sig
	// }

	// Compute point R = k * G
	// Rx, Ry := curve.ScalarBaseMult(k.Bytes())

	// // Negate nonce if R.y is not a quadratic residue.
	// if Ry.Cmp(curve.N) < 0 {
	// 	k.Neg(k)
	// }

	// // Normalize
	// RxBytes := Rx.Bytes()
	// RxBytesArr := [32]byte{}
	// for i := 0; i < len(RxBytes); i++ {
	// 	RxBytesArr[i] = RxBytes[i]
	// }
	// for i := len(RxBytes); i < 32; i++ {
	// 	RxBytesArr[i] = 0
	// }
	// RxFieldBytes := new(fieldVal).SetBytes(&RxBytesArr).Normalize().Bytes()
	// Rx = new(big.Int).SetBytes(RxFieldBytes[:])

	// // Compute e
	// e, err := computeE(Rx, pubKey, msgHash)
	// if err != nil {
	// 	return sig
	// }

	// // Compute scalar s = k + e * x.
	// e.Mul(e, privKey.D)
	// s := e.Add(e, k)

	// The signature is (R.x, s).
	// return Signature{Rx.Bytes(), s}
} // The signature is bytes(x(R)) || bytes(k + ed mod n).

// func signWithNonce(privKey *bchec.PrivateKey, pubKey *bchec.PublicKey, k *big.Int, msgHash []byte) Signature {
// 	sig := Signature{}

// 	fmt.Println("Signing with nonce:", hex.EncodeToString(k.Bytes()))

// 	if privKey.D.Cmp(bigZero) == 0 || k.Cmp(bigZero) == 0 {
// 		return sig
// 	}

// 	// Compute point R = k * G
// 	Rx, Ry := curve.ScalarBaseMult(k.Bytes())

// 	// Negate nonce if R.y is not a quadratic residue.
// 	if Ry.Cmp(curve.N) < 0 {
// 		k.Neg(k)
// 	}

// 	// Normalize
// 	RxBytes := Rx.Bytes()
// 	RxBytesArr := [32]byte{}
// 	for i := 0; i < len(RxBytes); i++ {
// 		RxBytesArr[i] = RxBytes[i]
// 	}
// 	for i := len(RxBytes); i < 32; i++ {
// 		RxBytesArr[i] = 0
// 	}
// 	RxFieldBytes := new(fieldVal).SetBytes(&RxBytesArr).Normalize().Bytes()
// 	Rx = new(big.Int).SetBytes(RxFieldBytes[:])

// 	// Compute e
// 	e, err := computeE(Rx, pubKey, msgHash)
// 	if err != nil {
// 		return sig
// 	}

// 	// Compute scalar s = k + e * x.
// 	e.Mul(e, privKey.D)
// 	s := e.Add(e, k)

// 	// The signature is (R.x, s).
// 	return Signature{Rx.Bytes(), s}
// }

func Verify(pubKey *bchec.PublicKey, sig Signature, msg []byte) error {
	if pubKey.X.Cmp(bigZero) == 0 && pubKey.Y.Cmp(bigZero) == 0 {
		return ErrPointAtInfinity
	}

	r := new(big.Int).SetBytes(sig[0:32])
	// r := new(big.Int).SetBytes(sig.r)
	e, err := computeE(r, pubKey, msg)
	if err != nil {
		return err
	}

	e.Neg(e)

	sGx, sGy := curve.ScalarBaseMult(sig[32:])
	// sGx, sGy := curve.ScalarBaseMult(sig.s.Bytes())
	if err != nil {
		return err
	}

	ePx, ePy := curve.ScalarMult(pubKey.X, pubKey.Y, e.Bytes())
	if err != nil {
		return err
	}

	Rx, Ry := curve.Add(sGx, sGy, ePx, ePy)

	if Rx.Cmp(bigZero) == 0 && Ry.Cmp(bigZero) == 0 {
		return ErrPointAtInfinity
	}

	fmt.Println("checking sig...")
	fmt.Println(Rx.Cmp(r) != 0, Ry.Cmp(curve.N) > 0)
	if Rx.Cmp(r) != 0 || Ry.Cmp(curve.N) > 0 {
		return ErrSignatureInvalid
	}

	return nil
}

// computeE
// scalar e = Hash(R.x || compressed(P) || m). Reject nonce if e == 0 or e >= order.
//
// Let e = int(hash(bytes(x(R)) || bytes(dG) || m)) mod n.
func computeE(Rx *big.Int, pubKey *bchec.PublicKey, msg []byte) (*big.Int, error) {
	hasher := sha256.New()

	_, err := hasher.Write(Rx.Bytes())
	if err != nil {
		return nil, err
	}

	_, err = hasher.Write(pubKey.SerializeCompressed())
	if err != nil {
		return nil, err
	}

	_, err = hasher.Write(msg)
	if err != nil {
		return nil, err
	}

	hash := hasher.Sum(nil)

	// Overflow
	// if len(hash) > 32 {
	// 	return nil, ErrEOverflow
	// }

	e := new(big.Int).SetBytes(hash)

	// e is 0
	if e.Cmp(bigZero) == 0 {
		return nil, ErrEIsZero
	}

	e.Mod(e, curve.N)

	return e, nil
}

func doubleSHA256(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:]
}
