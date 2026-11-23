import {arrayToHex} from '../utils'

/**
 * alcor-chain: the text an EM key (MetaMask `personal_sign`) or an ED key (Phantom `signMessage`) signs for a
 * transaction digest: this prefix, then the digest as lowercase hex. The wallet shows the text, so a signature
 * given to a site as a login or a "nonce" is never a transaction signature.
 *
 * Consensus: the node recovers EM/ED signatures over exactly these bytes (libfc `fc/crypto/signing_message.hpp`).
 * A wallet plugin passes `transactionSigningText(digest)` to MetaMask / Phantom as is.
 */
export const TRANSACTION_SIGNING_PREFIX = 'Alcor Chain transaction\nSign only in an app you trust\n'

/** The text to sign for a transaction digest. */
export function transactionSigningText(digest: Uint8Array): string {
    return TRANSACTION_SIGNING_PREFIX + arrayToHex(digest)
}

/** The UTF-8 bytes of `transactionSigningText(digest)`. */
export function transactionSigningMessage(digest: Uint8Array): Uint8Array {
    return new TextEncoder().encode(transactionSigningText(digest))
}
