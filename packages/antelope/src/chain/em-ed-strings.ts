import {Base58} from '../base58'
import {hexToArray} from '../utils'
import {emCompress} from '../crypto/em'

/**
 * alcor-chain: parsing of the EM / ED string forms, as the chain does it (libfc `ethereum_utils.cpp`,
 * `elliptic_ed.hpp`). EM data is hex with an optional `0x`, ED data is base58 without a checksum.
 * Not exported from the package.
 */

/**
 * Decode the hex part of `SIG_EM_…` / `PVT_EM_…` (optional `0x`), requiring exactly `size` bytes.
 * @internal
 */
export function decodeEmHex(value: string, size: number): Uint8Array {
    const data = hexToArray(value.startsWith('0x') ? value.slice(2) : value)
    if (data.length !== size) {
        throw new Error(`Invalid EM data length, expected ${size} bytes, got ${data.length}`)
    }
    return data
}

/**
 * Parse the hex part of `PUB_EM_…`, like the chain: optional `0x`, then 66 hex (compressed, `02`/`03`),
 * 128 hex (bare `x ‖ y`) or 130 hex (`04 ‖ x ‖ y`). Returns the 33-byte compressed point.
 * @throws If the length is wrong or the point is not on the curve.
 * @internal
 */
export function decodeEmPublicKey(value: string): Uint8Array {
    const hex = value.startsWith('0x') ? value.slice(2) : value
    let point: Uint8Array
    switch (hex.length) {
        case 66:
        case 130:
            point = hexToArray(hex)
            break
        case 128:
            point = hexToArray('04' + hex)
            break
        default:
            throw new Error(`Invalid EM public key length (${hex.length} hex chars)`)
    }
    const prefix = point[0]
    if (hex.length === 66 ? prefix !== 0x02 && prefix !== 0x03 : prefix !== 0x04) {
        throw new Error('Invalid EM public key prefix')
    }
    return emCompress(point)
}

/**
 * Decode the base58 part of `PUB_ED_…` / `SIG_ED_…` / `PVT_ED_…`, requiring exactly `size` bytes.
 * @internal
 */
export function decodeEdBase58(value: string, size: number): Uint8Array {
    const data = Base58.decode(value).array
    if (data.length !== size) {
        throw new Error(`Invalid ED data length, expected ${size} bytes, got ${data.length}`)
    }
    return data
}
