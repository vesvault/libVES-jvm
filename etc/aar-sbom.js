#!/usr/bin/env node
/*
 * aar-sbom.js -- the SBOM (CycloneDX 1.6) of a libVES-jvm .aar.
 *
 *   ./gradlew sbom      (build/outputs/sbom/libVES-jvm-<version>.cdx.json)
 *
 *   node etc/aar-sbom.js [--deps DIR] [--name FILE] [--out OUT] [AAR]
 *
 * AAR defaults to build/outputs/aar/libves-jvm-release.aar, DIR (the
 * prebuilts it was linked from) to src/main/cpp/deps, FILE (the name the
 * .aar is published under) to libVES-jvm-<version>.aar, and OUT to stdout.
 * The Gradle task runs assembleRelease first, so the .aar is the build of
 * this checkout by Gradle's own up-to-date check. Gradle leaves an
 * up-to-date .aar alone, so its age says nothing, and this script does not
 * look at it.
 *
 * No scanner can write this SBOM. The .aar has no Java dependencies, and
 * everything third-party in it is C compiled into jni/<abi>/libVES.so:
 * libVES.c, and OpenSSL, libcurl and liboqs from static prebuilts. So the
 * components come from build-inputs.json, and this script checks that the
 * file describes the .aar in front of it:
 *
 *   - the checkout: tracked files unchanged, and the libVES.c submodule at
 *     the commit and version the inputs name
 *   - the .aar: exactly the entries described here, classes.jar holding only
 *     com.vesvault.libves classes, each library linking only bundled or
 *     platform libraries, and every object in it from the NDK clang named
 *   - each component: its version string in libVES.so, its version macro in
 *     the prebuilt's headers, the SHA-256 of each prebuilt archive, and for
 *     liboqs the KEMs both libVES.so exports and oqsconfig.h enables
 *
 * It stops, writing nothing, when any of them does not hold. Deterministic:
 * no timestamp, and the serial number is derived from the content, so the
 * same .aar and inputs give the same SBOM.
 */
'use strict';
const { execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const ROOT = path.resolve(__dirname, '..');
const die = (msg) => { process.stderr.write(`aar-sbom: ${msg}\n`); process.exit(1); };
const usage = () => {
    process.stderr.write('usage: node etc/aar-sbom.js [--deps DIR] [--name FILE] [--out OUT] [AAR]\n');
    process.exit(64);
};
let aarPath, depsDir, pubName, outPath;
for (const argv = process.argv.slice(2); argv.length;) {
    const a = argv.shift();
    if (a === '--deps' && argv.length) depsDir = argv.shift();
    else if (a === '--name' && argv.length) pubName = argv.shift();
    else if (a === '--out' && argv.length) outPath = argv.shift();
    else if (!a.startsWith('-') && !aarPath) aarPath = a;
    else usage();
}
aarPath = path.resolve(aarPath || path.join(ROOT, 'build/outputs/aar/libves-jvm-release.aar'));
depsDir = path.resolve(depsDir || path.join(ROOT, 'src/main/cpp/deps'));
const git = (...args) => execFileSync('git', ['-C', ROOT].concat(args), { encoding: 'utf8' }).trim();
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

const inputs = JSON.parse(fs.readFileSync(path.join(ROOT, 'build-inputs.json'), 'utf8'));
const abi = inputs.abi;
const libs = inputs.components;
const lib = (name) => libs.find((c) => c.name === name) || die(`build-inputs.json names no ${name}`);

// ---- the checkout
const gradle = fs.readFileSync(path.join(ROOT, 'build.gradle.kts'), 'utf8');
const version = (gradle.match(/^version\s*=\s*"([^"]+)"/m) || [])[1] || die('build.gradle.kts sets no version');
if (!/^[0-9A-Za-z.+-]+$/.test(version)) die(`unexpected version "${version}"`);
const revision = git('rev-parse', 'HEAD');
const dirty = git('status', '--porcelain', '--untracked-files=no');
if (dirty) die(`the checkout has changes, so the .aar is not the build of ${revision}:\n${dirty}`);
const ves = lib('libVES.c');
const gitlink = git('rev-parse', `HEAD:${ves.submodule}`);
if (gitlink !== ves.commit) die(`the ${ves.submodule} submodule is pinned at ${gitlink}, build-inputs.json says ${ves.commit}`);
const vesH = fs.readFileSync(path.join(ROOT, ves.submodule, 'lib/libVES.h'), 'utf8');
const vesCode = (vesH.match(/#define\s+LIBVES_VERSION_CODE\s+"([^"]+)"/) || [])[1];
if (vesCode !== ves.version) die(`libVES.h says ${vesCode}, build-inputs.json says libVES.c ${ves.version}`);

// ---- the .aar: a zip, read here so the script needs nothing but node
const CRC = Array.from({ length: 256 }, (_, n) => {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
});
const crc32 = (buf) => {
    let c = 0xffffffff;
    for (const b of buf) c = CRC[(c ^ b) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
};
function unzip(buf, what) {
    let e = -1;
    for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 0xffff); i--) {
        if (buf.readUInt32LE(i) === 0x06054b50) { e = i; break; }
    }
    if (e < 0) die(`${what} is not a zip file`);
    const count = buf.readUInt16LE(e + 10);
    let p = buf.readUInt32LE(e + 16);
    if (count === 0xffff || p === 0xffffffff) die(`${what} is a zip64 file, which this script does not read`);
    const files = new Map();
    for (let k = 0; k < count; k++) {
        if (buf.readUInt32LE(p) !== 0x02014b50) die(`${what}: bad central directory`);
        const method = buf.readUInt16LE(p + 10), crc = buf.readUInt32LE(p + 16);
        const csize = buf.readUInt32LE(p + 20), usize = buf.readUInt32LE(p + 24);
        const nlen = buf.readUInt16LE(p + 28), xlen = buf.readUInt16LE(p + 30), clen = buf.readUInt16LE(p + 32);
        const local = buf.readUInt32LE(p + 42);
        const name = buf.toString('utf8', p + 46, p + 46 + nlen);
        p += 46 + nlen + xlen + clen;
        if (name.endsWith('/')) continue;
        if (buf.readUInt32LE(local) !== 0x04034b50) die(`${what}: bad local header for ${name}`);
        const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
        const raw = buf.subarray(start, start + csize);
        let data;
        if (method === 0) data = raw;
        else if (method !== 8) die(`${what}: ${name} uses compression method ${method}`);
        else try { data = zlib.inflateRawSync(raw); } catch (err) { die(`${what}: ${name} does not inflate (${err.message})`); }
        if (data.length !== usize || crc32(data) !== crc) die(`${what}: ${name} does not match its size or CRC`);
        if (files.has(name)) die(`${what} holds ${name} twice`);
        files.set(name, data);
    }
    return files;
}

// ---- ELF: what a shared library links, exports and was compiled with
function elf(buf, what) {
    if (buf.readUInt32BE(0) !== 0x7f454c46 || buf[4] !== 2 || buf[5] !== 1) die(`${what} is not a 64-bit little-endian ELF file`);
    const machine = buf.readUInt16LE(18);
    const shoff = Number(buf.readBigUInt64LE(0x28)), shentsize = buf.readUInt16LE(0x3a);
    const shnum = buf.readUInt16LE(0x3c), shstrndx = buf.readUInt16LE(0x3e);
    const sh = [];
    for (let i = 0; i < shnum; i++) {
        const o = shoff + i * shentsize;
        sh.push({
            name: buf.readUInt32LE(o), type: buf.readUInt32LE(o + 4),
            offset: Number(buf.readBigUInt64LE(o + 0x18)), size: Number(buf.readBigUInt64LE(o + 0x20)),
            link: buf.readUInt32LE(o + 0x28),
        });
    }
    const str = (s, off) => {
        const at = sh[s].offset + off;
        return buf.toString('latin1', at, buf.indexOf(0, at));
    };
    const section = (n) => sh.find((s) => str(shstrndx, s.name) === n);
    const r = { machine, needed: [], soname: null, exports: new Set(), comment: [] };
    const dyn = sh.find((s) => s.type === 6) || die(`${what} has no dynamic section`);
    for (let o = dyn.offset; o < dyn.offset + dyn.size; o += 16) {
        const tag = Number(buf.readBigInt64LE(o)), val = Number(buf.readBigUInt64LE(o + 8));
        if (tag === 0) break;
        if (tag === 1) r.needed.push(str(dyn.link, val));
        if (tag === 14) r.soname = str(dyn.link, val);
    }
    const sym = sh.find((s) => s.type === 11) || die(`${what} has no dynamic symbol table`);
    for (let o = sym.offset; o < sym.offset + sym.size; o += 24) {
        const name = buf.readUInt32LE(o), shndx = buf.readUInt16LE(o + 6);
        if (name && shndx !== 0) r.exports.add(str(sym.link, name));
    }
    const cm = section('.comment');
    if (cm) r.comment = [...new Set(buf.toString('latin1', cm.offset, cm.offset + cm.size).split('\0').filter(Boolean))];
    return r;
}
// A version string, whole: "libcurl/8.11.1" must not be the start of "libcurl/8.11.10".
const carries = (buf, marker) => {
    const m = Buffer.from(marker, 'latin1');
    for (let i = buf.indexOf(m); i >= 0; i = buf.indexOf(m, i + 1)) {
        const next = buf[i + m.length];
        if (next === undefined || !/[0-9.]/.test(String.fromCharCode(next))) return true;
    }
    return false;
};

const aarBuf = fs.readFileSync(aarPath);
const aar = unzip(aarBuf, path.basename(aarPath));
const soNames = ['libVES.so', 'libVESjni.so'];
const soPath = (so) => `jni/${abi}/${so}`;
const expected = ['AndroidManifest.xml', 'R.txt', 'classes.jar', 'proguard.txt',
    'META-INF/com/android/build/gradle/aar-metadata.properties'].concat(soNames.map(soPath));
for (const f of aar.keys()) if (!expected.includes(f)) die(`the .aar holds ${f}, which this SBOM does not describe`);
for (const f of expected) if (!aar.has(f)) die(`the .aar has no ${f}`);

const jar = unzip(aar.get('classes.jar'), 'classes.jar');
const classes = [...jar.keys()].filter((f) => f !== 'META-INF/MANIFEST.MF');
const foreign = classes.filter((f) => !/^com\/vesvault\/libves\/[^/]+\.class$/.test(f));
if (foreign.length) die(`classes.jar holds code that is not com.vesvault.libves: ${foreign.slice(0, 5).join(' ')}`);
if (!classes.length) die('classes.jar holds no classes');

const so = {};
for (const n of soNames) {
    const e = so[n] = elf(aar.get(soPath(n)), n);
    if (abi === 'arm64-v8a' && e.machine !== 183) die(`${n} is not an AArch64 library (e_machine ${e.machine})`);
    if (e.soname !== n) die(`${n} has the soname ${e.soname}`);
    for (const d of e.needed) {
        if (!soNames.includes(d) && !inputs.platform.includes(d)) die(`${n} needs ${d}, which is neither in the .aar nor a platform library`);
    }
    const other = e.comment.filter((c) => !inputs.toolchain.comment.includes(c));
    if (other.length) die(`${n} holds code from a toolchain build-inputs.json does not name: ${other.join(' | ')}`);
}
const core = aar.get(soPath('libVES.so'));
const platformUsed = [...new Set(soNames.flatMap((n) => so[n].needed).filter((d) => !soNames.includes(d)))].sort();

// ---- each component against the .aar and its prebuilt
for (const c of libs) {
    if (c.marker && !carries(core, c.marker)) die(`libVES.so does not carry "${c.marker}" (${c.name} ${c.version})`);
    if (c.header) {
        const h = fs.readFileSync(path.join(depsDir, c.header.file), 'latin1');
        const v = (h.match(new RegExp(`#\\s*define\\s+${c.header.define}\\s+"([^"]*)"`)) || [])[1];
        if (v !== c.header.value) die(`${c.header.file} defines ${c.header.define} as ${v}, not ${c.header.value}`);
    }
    for (const [f, want] of Object.entries(c.prebuilt || {})) {
        const got = sha256(fs.readFileSync(path.join(depsDir, f)));
        if (got !== want) die(`the prebuilt ${f} is ${got}, build-inputs.json pins ${want}`);
    }
    if (c.kems) {
        const want = [...c.kems].sort().join(' ');
        const exported = [...so['libVES.so'].exports].map((s) => (s.match(/^OQS_KEM_(\w+)_keypair$/) || [])[1])
            .filter(Boolean).sort().join(' ');
        const cfg = fs.readFileSync(path.join(depsDir, c.header.file), 'latin1');
        const enabled = [...cfg.matchAll(/#define\s+OQS_ENABLE_KEM_([a-z0-9_]+)\s+1/g)].map((x) => x[1]).sort().join(' ');
        if (exported !== want) die(`libVES.so exports the KEMs ${exported}, build-inputs.json lists ${want}`);
        if (enabled !== want) die(`oqsconfig.h enables the KEMs ${enabled}, build-inputs.json lists ${want}`);
    }
}

// ---- the document
const hashes = (buf) => [{ alg: 'SHA-256', content: sha256(buf) }];
const licenses = (expr) => (/^[A-Za-z0-9.+-]+$/.test(expr) ? [{ license: { id: expr } }] : [{ expression: expr }]);
const prop = (pairs) => pairs.filter(([, v]) => v).map(([name, value]) => ({ name, value }));
const component = (c) => {
    const r = { 'bom-ref': c.purl, type: 'library', name: c.name, version: c.version, purl: c.purl };
    if (c.cpe) r.cpe = c.cpe;
    if (c.license) r.licenses = licenses(c.license);
    r.externalReferences = [{ type: /github\.com/.test(c.url) ? 'vcs' : 'website', url: c.url }];
    if (c.source) r.externalReferences.push({ type: 'source-distribution', url: c.source.url, hashes: [{ alg: 'SHA-256', content: c.source.sha256 }] });
    if (c.commit) r.pedigree = { commits: [{ uid: c.commit, url: `${c.url}/commit/${c.commit}` }] };
    const props = prop([['libves:in', c.in && c.in.split(' ').map(soPath).join(' ')], ['libves:build', c.build],
        ['libves:kems', c.kems && c.kems.join(' ')], ['libves:licenseNote', c.licenseNote]]);
    if (props.length) r.properties = props;
    if (c.components) r.components = c.components.map(component);
    return r;
};
const product = `pkg:github/vesvault/libVES-jvm@v${version}`;
const aarName = pubName || `libVES-jvm-${version}.aar`;
const aarRef = 'file:' + aarName;
const inner = ['classes.jar'].concat(soNames.map(soPath));
const minSdk = (aar.get('AndroidManifest.xml').toString('utf8').match(/minSdkVersion="(\d+)"/) || [])[1];
const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
        tools: { components: [{ type: 'application', name: 'libVES-jvm etc/aar-sbom.js', version }] },
        component: {
            'bom-ref': product, type: 'library', name: 'libVES-jvm', version, purl: product,
            supplier: { name: 'VESvault Corp', url: ['https://vesvault.com'] },
            licenses: licenses('Apache-2.0'),
            externalReferences: [{ type: 'vcs', url: 'https://github.com/vesvault/libVES-jvm' }],
            pedigree: { commits: [{ uid: revision, url: `https://github.com/vesvault/libVES-jvm/commit/${revision}` }] },
        },
        properties: prop([['libves:abi', abi], ['libves:minSdk', minSdk],
            ['libves:platform-libraries', `${platformUsed.join(' ')} (the device's, not in the .aar)`],
            ['libves:toolchain', `Android NDK ${inputs.toolchain.ndk}: ${inputs.toolchain.comment.join('; ')}`],
            ['libves:java', `${classes.length} classes, all com.vesvault.libves; no runtime dependencies`]]),
    },
    components: [{
        'bom-ref': aarRef, type: 'file', name: aarName, hashes: hashes(aarBuf),
        components: inner.map((f) => ({ 'bom-ref': 'file:' + f, type: 'file', name: f, hashes: hashes(aar.get(f)) })),
    }].concat(libs.map(component)),
};
const ndkParts = (c) => (c.components || []).map((s) => s.purl);
const within = (n) => libs.filter((c) => c.in.split(' ').includes(n));
bom.dependencies = [
    { ref: product, dependsOn: [aarRef] },
    { ref: aarRef, dependsOn: inner.map((f) => 'file:' + f) },
].concat(soNames.map((n) => ({
    ref: 'file:' + soPath(n),
    dependsOn: so[n].needed.filter((d) => soNames.includes(d)).map((d) => 'file:' + soPath(d))
        .concat(within(n).flatMap((c) => (c.components ? ndkParts(c) : [c.purl]))),
}))).concat(libs.filter((c) => c.dependsOn).map((c) => ({ ref: c.purl, dependsOn: c.dependsOn.map((d) => lib(d).purl) })));
// Known vulnerabilities in a component that do not affect this build, with the reason (VEX).
if (inputs.vex && inputs.vex.length) bom.vulnerabilities = inputs.vex.map((v) => ({
    'bom-ref': 'vex:' + v.id, id: v.id,
    source: { name: v.source, url: v.url },
    analysis: { state: v.state, justification: v.justification, detail: v.detail },
    affects: [{ ref: v.affects }],
}));
const id = sha256(JSON.stringify(bom));
const uuid = `${id.slice(0, 8)}-${id.slice(8, 12)}-5${id.slice(13, 16)}-`
    + `${(8 | (parseInt(id[16], 16) & 3)).toString(16)}${id.slice(17, 20)}-${id.slice(20, 32)}`;
const text = JSON.stringify(Object.assign({ bomFormat: bom.bomFormat, specVersion: bom.specVersion,
    serialNumber: 'urn:uuid:' + uuid }, bom), null, 2) + '\n';
if (!outPath) process.stdout.write(text);
else {
    fs.mkdirSync(path.dirname(path.resolve(outPath)), { recursive: true });
    fs.writeFileSync(outPath + '.tmp', text);
    fs.renameSync(outPath + '.tmp', outPath);
}
