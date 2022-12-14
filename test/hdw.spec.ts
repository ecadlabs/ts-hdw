import { newSeedFromMnemonic, Path, Hard } from "../src";

it("seed from mnemonic", () => {
    const mnemonic =
        "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin";
    const seed = new Uint8Array([
        0xb1, 0x19, 0x97, 0xfa, 0xff, 0x42, 0x0a, 0x33, 0x1b, 0xb4, 0xa4, 0xff, 0xdc, 0x8b, 0xdc, 0x8b, 0xa7, 0xc0,
        0x17, 0x32, 0xa9, 0x9a, 0x30, 0xd8, 0x3d, 0xbb, 0xeb, 0xd4, 0x69, 0x66, 0x6c, 0x84, 0xb4, 0x7d, 0x09, 0xd3,
        0xf5, 0xf4, 0x72, 0xb3, 0xb9, 0x38, 0x4a, 0xc6, 0x34, 0xbe, 0xba, 0x2a, 0x44, 0x0b, 0xa3, 0x6e, 0xc7, 0x66,
        0x11, 0x44, 0x13, 0x2f, 0x35, 0xe2, 0x06, 0x87, 0x35, 0x64,
    ]);
    const result = newSeedFromMnemonic(mnemonic);
    expect(result).toEqual(seed);
});

interface PathTestCase {
    path: string;
    out: Path;
    str: string;
}

const pathTests: PathTestCase[] = [
    {
        path: "",
        str: "m",
        out: new Path(),
    },
    {
        path: "m",
        str: "m",
        out: new Path(),
    },
    {
        path: "m/1",
        str: "m/1",
        out: Path.from([1]),
    },
    {
        path: "m/1'",
        str: "m/1'",
        out: Path.from([1 | Hard]),
    },
    {
        path: "1h/1000",
        str: "m/1'/1000",
        out: Path.from([1 | Hard, 1000]),
    },
    {
        path: "m/1/1000'",
        str: "m/1/1000'",
        out: Path.from([1, 1000 | Hard]),
    },
];

it("path", () => {
    for (const p of pathTests) {
        const result = Path.fromString(p.path);
        expect(result).toEqual(p.out);
        expect(result.toString()).toBe(p.str);
    }
});
