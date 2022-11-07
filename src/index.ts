import { deriveKey } from "@stablelib/pbkdf2";
import { SHA512 } from "@stablelib/sha512";

export * as ECDSA from "./ecdsa";
export * as Ed25519 from "./ed25519";

export const Hard = 0x80000000;

export interface ExtendedKey {
    readonly chainCode: Uint8Array;
    derive(index: number): ExtendedKey;
    derivePath(path: Iterable<number>): ExtendedKey;
    bytes(): Uint8Array;
}

export type ExtendedPublicKey = ExtendedKey;

export interface ExtendedPrivateKey extends ExtendedKey {
    derive(index: number): ExtendedPrivateKey;
    derivePath(path: number[]): ExtendedPrivateKey;
    getPublic(): ExtendedPublicKey;
}

// Generates the seed value from the mnemonic as specified in BIP-39.
// The seed is the primary secret used to derive root keys and their derivatives
export function newSeedFromMnemonic(mnemonic: string, password?: string): Uint8Array {
    const pwd = new TextEncoder().encode(mnemonic);
    const salt = new TextEncoder().encode("mnemonic" + (password || ""));
    return deriveKey(SHA512, pwd, salt, 2048, 64);
}

export class Path extends Array<number> {
    static from(iterable: Iterable<number> | ArrayLike<number>): Path {
        return super.from(iterable).map((x) => x >>> 0);
    }

    static fromString(s: string): Path {
        if (s.length === 0) {
            return new Path();
        }
        let parts = s.split("/");
        const out: number[] = [];
        if (parts[0] === "m") {
            parts = parts.slice(1);
        }
        for (let p of parts) {
            if (p.length === 0) {
                throw new Error(`invalid BIP32 path: ${s}`);
            }
            let h = 0;
            const last = p[p.length - 1];
            if (last === "'" || last === "h" || last === "H") {
                h = Hard;
                p = p.slice(0, p.length - 1);
            }
            const index = (parseInt(p, 10) | h) >>> 0;
            out.push(index);
        }
        return Path.from(out);
    }

    toString(): string {
        let out = "m";
        for (const x of this) {
            out += "/" + String(x & ~Hard);
            if ((x & Hard) !== 0) {
                out += "'";
            }
        }
        return out;
    }
}
