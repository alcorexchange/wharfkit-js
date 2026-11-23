import {keccak_256} from '@noble/hashes/sha3.js'

import {arrayEquals} from '../utils'

import {getCurve} from './curves'
import {transactionSigningMessage} from './signing-message'

/**
 * alcor-chain EM keys (secp256k1, MetaMask).
 *
 * A transaction digest is signed as an EIP-191 personal message over the alcor-chain signing text
 * (`transactionSigningText`), the way MetaMask `personal_sign` does. Signatures are Ethereum's
 * 65 bytes `r ‖ s ‖ v` with `v = 27 + recid`. Mirrors libfc `fc::em` of the chain.
 */

const MESSAGE_PREFIX = '\x19Ethereum Signed Message:\n'

/**
 * The hash an EM key signs for a digest:
 * keccak256("\x19Ethereum Signed Message:\n" ‖ len(text) ‖ text), text = `transactionSigningText(digest)`.
 * @internal
 */
export function emMessageHash(digest: Uint8Array): Uint8Array {
    const text = transactionSigningMessage(digest)
    const prefix = new TextEncoder().encode(MESSAGE_PREFIX + text.length)
    const message = new Uint8Array(prefix.length + text.length)
    message.set(prefix, 0)
    message.set(text, prefix.length)
    return keccak_256(message)
}

/**
 * Sign a digest with an EM key, returning the signature parts (low-s, RFC 6979, like libsecp256k1).
 * @internal
 */
export function emSign(secret: Uint8Array, digest: Uint8Array) {
    const sig = getCurve('EM').sign(emMessageHash(digest), secret, {
        prehash: false,
        format: 'recovered',
        lowS: true,
    })
    return {type: 'EM', r: sig.slice(1, 33), s: sig.slice(33, 65), recid: sig[0]}
}

/**
 * Recover the compressed public key from a 65-byte `r ‖ s ‖ v` EM signature over a digest.
 * @internal
 */
export function emRecover(signature: Uint8Array, digest: Uint8Array): Uint8Array {
    if (signature.length !== 65) {
        throw new Error(`EM signature must be 65 bytes, got ${signature.length}`)
    }
    // One encoding per signature, as the chain requires: v is 27 or 28, 0 < r < n, 0 < s <= n / 2 (low s).
    // A wallet that returns v = 0 / 1 is normalized by the wallet plugin before the signature is built.
    const v = signature[64]
    if (v !== 27 && v !== 28) {
        throw new Error('EM signature v must be 27 or 28')
    }
    const n = getCurve('EM').Point.CURVE().n
    const toBig = (b: Uint8Array) => BigInt('0x' + Array.from(b, (x) => x.toString(16).padStart(2, '0')).join(''))
    const r = toBig(signature.subarray(0, 32))
    const s = toBig(signature.subarray(32, 64))
    if (r === 0n || r >= n || s === 0n || s > n >> 1n) {
        throw new Error('EM signature r or s out of range (s must be low)')
    }
    const recovered = new Uint8Array(65)
    recovered[0] = v - 27
    recovered.set(signature.subarray(0, 64), 1)
    return getCurve('EM').recoverPublicKey(recovered, emMessageHash(digest), {prehash: false})
}

/**
 * Verify an EM signature over a digest by recovering its key, as the chain does.
 * @internal
 */
export function emVerify(signature: Uint8Array, digest: Uint8Array, pubkey: Uint8Array): boolean {
    let recovered: Uint8Array
    try {
        recovered = emRecover(signature, digest)
    } catch {
        return false
    }
    return arrayEquals(recovered, pubkey)
}

/**
 * Parse a secp256k1 point (33 compressed or 65 uncompressed bytes) and return it compressed.
 * @throws If the point is not on the curve.
 * @internal
 */
export function emCompress(point: Uint8Array): Uint8Array {
    return getCurve('EM').Point.fromBytes(point).toBytes(true)
}

/**
 * Return a compressed secp256k1 point as 65 uncompressed bytes (`04 ‖ x ‖ y`).
 * @throws If the point is not on the curve.
 * @internal
 */
export function emUncompress(point: Uint8Array): Uint8Array {
    return getCurve('EM').Point.fromBytes(point).toBytes(false)
}
