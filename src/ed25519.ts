import { HMAC } from "@stablelib/hmac";
import { SHA512 } from "@stablelib/sha512";
import { generateKeyPairFromSeed } from "@stablelib/ed25519";
import { ExtendedPrivateKey, ExtendedPublicKey, Hard } from "./index";
import { parseHex } from "./utils";

// MinSeedSize is the minimal allowed seed byte length
const minSeedSize = 16;
// MaxSeedSize is the maximal allowed seed byte length
const maxSeedSize = 64;

const ed25519Key = "ed25519 seed";

export class PrivateKey implements ExtendedPrivateKey {
    constructor(readonly priv: Uint8Array, readonly chainCode: Uint8Array) {}

    static fromSeed(seedSrc: Uint8Array | string): PrivateKey {
        const seed = typeof seedSrc === "string" ? parseHex(seedSrc) : seedSrc;
        if (seed.length < minSeedSize || seed.length > maxSeedSize) {
            throw new Error(`bad seed size ${seed.length}`);
        }
        const key = new TextEncoder().encode(ed25519Key);
        const sum = new HMAC(SHA512, key).update(seed).digest();
        return new PrivateKey(generateKeyPairFromSeed(sum.subarray(0, 32)).secretKey, sum.subarray(32));
    }

    seed(): Uint8Array {
        return this.priv.subarray(0, 32);
    }

    pub(): Uint8Array {
        return this.priv.subarray(32);
    }

    derive(index: number): PrivateKey {
        if ((index & Hard) === 0) {
            throw new Error("non hardened derivation");
        }
        const data = new Uint8Array(37);
        data.set(this.seed(), 1);
        new DataView(data.buffer).setUint32(33, index);
        const sum = new HMAC(SHA512, this.chainCode).update(data).digest();
        return new PrivateKey(generateKeyPairFromSeed(sum.subarray(0, 32)).secretKey, sum.subarray(32));
    }

    derivePath(path: Iterable<number>): PrivateKey {
        let key: PrivateKey = this;
        for (const x of path) {
            key = key.derive(x);
        }
        return key;
    }

    getPublic(): PublicKey {
        return new PublicKey(this.pub(), this.chainCode);
    }

    bytes(): Uint8Array {
        return new Uint8Array(this.priv);
    }
}

export class PublicKey implements ExtendedPublicKey {
    constructor(readonly pub: Uint8Array, readonly chainCode: Uint8Array) {}

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    derive(index: number): PrivateKey {
        throw new Error("can't use public key for derivation");
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    derivePath(path: Iterable<number>): PrivateKey {
        throw new Error("can't use public key for derivation");
    }

    bytes(): Uint8Array {
        return new Uint8Array(this.pub);
    }
}
