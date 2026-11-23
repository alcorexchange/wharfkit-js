import {ed25519} from '@noble/curves/ed25519.js'

import {arrayEquals, secureRandom} from '../utils'

import {transactionSigningMessage} from './signing-message'

/**
 * alcor-chain ED keys (Ed25519, Solana / Phantom). Mirrors libfc `fc::crypto::ed` of the chain.
 *
 * - Private key: libsodium's 64-byte secret, `seed(32) ‖ public key(32)`.
 * - A transaction digest is signed as the alcor-chain signing text (`transactionSigningText`), what
 *   Phantom `signMessage` gets.
 * - Signature: 96 bytes, `public key(32) ‖ ed25519 signature(64)`; the embedded key makes it "recoverable".
 */

const SECRET_LENGTH = 64
const PUBLIC_LENGTH = 32
const SIGNATURE_LENGTH = 96

/**
 * Generate a 64-byte ED secret (`seed ‖ public key`).
 * @internal
 */
export function edGenerate(): Uint8Array {
    const seed = secureRandom(PUBLIC_LENGTH)
    const secret = new Uint8Array(SECRET_LENGTH)
    secret.set(seed, 0)
    secret.set(ed25519.getPublicKey(seed), PUBLIC_LENGTH)
    return secret
}

/**
 * The public key of a 64-byte ED secret.
 * @throws If the secret's public half does not belong to its seed.
 * @internal
 */
export function edGetPublic(secret: Uint8Array): Uint8Array {
    if (secret.length !== SECRET_LENGTH) {
        throw new Error(`ED private key must be ${SECRET_LENGTH} bytes, got ${secret.length}`)
    }
    const embedded = secret.slice(PUBLIC_LENGTH)
    const derived = ed25519.getPublicKey(secret.subarray(0, PUBLIC_LENGTH))
    if (!arrayEquals(derived, embedded)) {
        throw new Error('ED private key: public half does not match the seed')
    }
    return embedded
}

/**
 * Sign a digest with a 64-byte ED secret, returning the 96-byte chain signature.
 * @internal
 */
export function edSign(secret: Uint8Array, digest: Uint8Array): Uint8Array {
    const pubkey = edGetPublic(secret)
    const sig = ed25519.sign(transactionSigningMessage(digest), secret.subarray(0, PUBLIC_LENGTH))
    const signature = new Uint8Array(SIGNATURE_LENGTH)
    signature.set(pubkey, 0)
    signature.set(sig, PUBLIC_LENGTH)
    return signature
}

/**
 * Verify a detached 64-byte Ed25519 signature over unchanged bytes (chain: `ed::verify_detached`).
 * RFC 8032 checks (zip215 off): canonical encodings, s < L, no small-order key. noble then checks the
 * cofactored equation and libsodium the cofactorless one, so a few crafted signatures pass here and fail
 * on the chain: 5 of the chain's 253 frozen vectors, none the other way round (test/alcor-keys.ts).
 * The chain decides; this check is for clients only.
 * @internal
 */
export function edVerifyDetached(
    signature: Uint8Array,
    message: Uint8Array,
    pubkey: Uint8Array
): boolean {
    if (signature.length !== 64 || pubkey.length !== PUBLIC_LENGTH) {
        return false
    }
    return ed25519.verify(signature, message, pubkey, {zip215: false})
}

/**
 * Verify the detached part of a 96-byte ED signature over a digest with the given key.
 * The embedded key is ignored here, as on the chain.
 * @internal
 */
export function edVerify(signature: Uint8Array, digest: Uint8Array, pubkey: Uint8Array): boolean {
    if (signature.length !== SIGNATURE_LENGTH) {
        return false
    }
    return edVerifyDetached(signature.subarray(PUBLIC_LENGTH), transactionSigningMessage(digest), pubkey)
}

/**
 * Return the key embedded in a 96-byte ED signature after checking that it signed the digest.
 * @throws If the signature does not verify against its embedded key.
 * @internal
 */
export function edRecover(signature: Uint8Array, digest: Uint8Array): Uint8Array {
    const pubkey = signature.slice(0, PUBLIC_LENGTH)
    if (!edVerify(signature, digest, pubkey)) {
        throw new Error('ED25519 signature verification failed during recovery')
    }
    return pubkey
}
