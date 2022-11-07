import { ec, curve } from "elliptic";
import { Hard, ExtendedPrivateKey, ExtendedPublicKey } from "./index";
import { HMAC } from "@stablelib/hmac";
import { SHA512 } from "@stablelib/sha512";
import BN from "bn.js";
import { parseHex } from "./utils";

export type CurveName = "p256" | "secp256k1";

const seedKey: Record<CurveName, string> = {
    p256: "Nist256p1 seed",
    secp256k1: "Bitcoin seed",
};

interface KeyPair extends ec.KeyPair {
    priv: BN | null;
    pub: curve.base.BasePoint | null;
}

// MinSeedSize is the minimal allowed seed byte length
const minSeedSize = 16;
// MaxSeedSize is the maximal allowed seed byte length
const maxSeedSize = 64;

export class PrivateKey implements ExtendedPrivateKey {
    readonly keyPair: KeyPair;

    constructor(priv: ec.KeyPair, public readonly chainCode: Uint8Array) {
        this.keyPair = <KeyPair>priv;
    }

    static fromSeed(seedSrc: Uint8Array | string, curve: CurveName): PrivateKey {
        let seed = typeof seedSrc === "string" ? parseHex(seedSrc) : seedSrc;
        if (seed.length < minSeedSize || seed.length > maxSeedSize) {
            throw new Error(`bad seed size ${seed.length}`);
        }
        if (!Object.prototype.hasOwnProperty.call(seedKey, curve)) {
            throw new Error(`unknown curve ${curve}`);
        }
        const c = new ec(curve);
        if (c.n?.bitLength() !== 256) {
            throw new Error(`invalid curve bit size ${c.n?.bitLength()}`);
        }

        const key = new TextEncoder().encode(seedKey[curve]);
        let d: BN, chain: Uint8Array;
        while (true) {
            const sum = new HMAC(SHA512, key).update(seed).digest();
            d = new BN(sum.subarray(0, 32));
            chain = sum.subarray(32);
            if (d.isZero() || d.cmp(c.n) >= 0) {
                seed = sum;
            } else {
                break;
            }
        }

        const keyPair = <KeyPair>c.keyPair({});
        keyPair.priv = d;
        return new PrivateKey(keyPair, chain);
    }

    derive(index: number): PrivateKey {
        const data = new Uint8Array(37);
        if ((index & Hard) !== 0) {
            // hardened derivation
            data.set(this.keyPair.getPrivate().toArray(), 1);
        } else {
            data.set(this.keyPair.getPublic().encodeCompressed(), 0);
        }
        new DataView(data.buffer).setUint32(33, index);

        let d: BN, chain: Uint8Array;
        while (true) {
            const sum = new HMAC(SHA512, this.chainCode).update(data).digest();
            d = new BN(sum.subarray(0, 32));
            chain = sum.subarray(32);
            if (this.keyPair.ec.n && d.cmp(this.keyPair.ec.n) < 0) {
                d = d.add(this.keyPair.getPrivate()).mod(this.keyPair.ec.n);
                if (!d.isZero()) {
                    break;
                }
            }
            data.set(chain, 1);
            data[0] = 1;
        }
        const keyPair = <KeyPair>this.keyPair.ec.keyPair({});
        keyPair.priv = d;
        return new PrivateKey(keyPair, chain);
    }

    getPublic(): PublicKey {
        const keyPair = <KeyPair>this.keyPair.ec.keyPair({});
        keyPair.pub = this.keyPair.getPublic();
        return new PublicKey(keyPair, this.chainCode);
    }

    derivePath(path: Iterable<number>): PrivateKey {
        let key: PrivateKey = this;
        for (const x of path) {
            key = key.derive(x);
        }
        return key;
    }

    bytes(): Uint8Array {
        if (!this.keyPair.priv) {
            throw new Error("not a private key");
        }
        // pad to 32 bytes as toArray() length argument seems to be ignored (BN bug)
        const src = this.keyPair.priv.toArray();
        const out = new Uint8Array(32);
        out.set(src, out.length - src.length);
        return out;
    }
}

export class PublicKey implements ExtendedPublicKey {
    readonly keyPair: KeyPair;

    constructor(pub: ec.KeyPair, public readonly chainCode: Uint8Array) {
        this.keyPair = <KeyPair>pub;
    }

    derive(index: number): PublicKey {
        if ((index & Hard) !== 0) {
            throw new Error("can't use hardened derivation with public key");
        }
        const data = new Uint8Array(37);
        data.set(this.keyPair.getPublic().encodeCompressed(), 0);
        new DataView(data.buffer).setUint32(33, index);

        let point: curve.base.BasePoint, chain: Uint8Array;
        while (true) {
            const sum = new HMAC(SHA512, this.chainCode).update(data).digest();
            const k = new BN(sum.subarray(0, 32));
            chain = sum.subarray(32);
            if (this.keyPair.ec.n && k.cmp(this.keyPair.ec.n) < 0) {
                point = (<curve.base.BasePoint>this.keyPair.ec.g).mul(k).add(this.keyPair.getPublic());
                if (!point.isInfinity()) {
                    break;
                }
            }
            data.set(chain, 1);
            data[0] = 1;
        }

        const keyPair = <KeyPair>this.keyPair.ec.keyPair({});
        keyPair.pub = point;
        return new PublicKey(keyPair, chain);
    }

    derivePath(path: Iterable<number>): PublicKey {
        let key: PublicKey = this;
        for (const x of path) {
            key = key.derive(x);
        }
        return key;
    }

    bytes(): Uint8Array {
        if (!this.keyPair.pub) {
            throw new Error("not a public key");
        }
        return new Uint8Array(this.keyPair.pub.encodeCompressed());
    }
}
