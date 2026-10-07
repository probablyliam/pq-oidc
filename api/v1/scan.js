import { lookup } from "node:dns/promises";
import net from "node:net";
import http from "node:http";
import https from "node:https";
import crypto, { randomBytes } from "node:crypto";
//#region packages/scan-core/src/net/address.ts
const IPV4_BLOCKED = [
	["0.0.0.0/8", "this network"],
	["10.0.0.0/8", "private"],
	["100.64.0.0/10", "carrier-grade NAT"],
	["127.0.0.0/8", "loopback"],
	["169.254.0.0/16", "link-local, including cloud metadata services"],
	["172.16.0.0/12", "private"],
	["192.0.0.0/24", "IETF protocol assignments"],
	["192.0.2.0/24", "documentation"],
	["192.88.99.0/24", "deprecated 6to4 relay"],
	["192.168.0.0/16", "private"],
	["198.18.0.0/15", "benchmarking"],
	["198.51.100.0/24", "documentation"],
	["203.0.113.0/24", "documentation"],
	["224.0.0.0/4", "multicast"],
	["240.0.0.0/4", "reserved, including broadcast"]
];
const IPV6_BLOCKED = [
	["::/128", "unspecified"],
	["::1/128", "loopback"],
	["::/96", "deprecated IPv4-compatible"],
	["64:ff9b:1::/48", "local-use NAT64"],
	["100::/64", "discard-only"],
	["2001::/23", "IETF protocol assignments, including Teredo"],
	["2001:db8::/32", "documentation"],
	["3fff::/20", "documentation"],
	["5f00::/16", "segment routing"],
	["fc00::/7", "unique local, including cloud metadata services"],
	["fe80::/10", "link-local"],
	["fec0::/10", "deprecated site-local"],
	["ff00::/8", "multicast"]
];
/** IPv6 prefixes that wrap an IPv4 address, and where in the 16 bytes it sits. */
const IPV6_EMBEDS_IPV4 = [
	[
		"::ffff:0:0/96",
		"IPv4-mapped",
		12
	],
	[
		"64:ff9b::/96",
		"NAT64",
		12
	],
	[
		"2002::/16",
		"6to4",
		2
	]
];
/** Strict dotted decimal: four octets, no leading zeros, nothing else. */
function parseIpv4(text) {
	const parts = text.split(".");
	if (parts.length !== 4) return void 0;
	const bytes = /* @__PURE__ */ new Uint8Array(4);
	for (const [i, part] of parts.entries()) {
		if (!/^(0|[1-9]\d{0,2})$/.test(part)) return void 0;
		const value = Number(part);
		if (value > 255) return void 0;
		bytes[i] = value;
	}
	return bytes;
}
/** RFC 4291 text forms, including `::` and a dotted IPv4 tail. Zone IDs are refused. */
function parseIpv6(text) {
	if (!/^[0-9a-fA-F:.]+$/.test(text) || !text.includes(":")) return void 0;
	const halves = text.split("::");
	if (halves.length > 2) return void 0;
	const groups = (part) => {
		if (part === "") return [];
		const out = [];
		const pieces = part.split(":");
		for (const [i, piece] of pieces.entries()) if (piece.includes(".")) {
			const v4 = i === pieces.length - 1 ? parseIpv4(piece) : void 0;
			if (!v4) return void 0;
			out.push(v4[0] << 8 | v4[1], v4[2] << 8 | v4[3]);
		} else {
			if (!/^[0-9a-fA-F]{1,4}$/.test(piece)) return void 0;
			out.push(parseInt(piece, 16));
		}
		return out;
	};
	const head = groups(halves[0]);
	const tail = halves.length === 2 ? groups(halves[1]) : [];
	if (!head || !tail) return void 0;
	if (halves.length === 2 && halves[0].includes(".")) return void 0;
	const missing = 8 - head.length - tail.length;
	if (halves.length === 1 ? missing !== 0 : missing < 1) return void 0;
	const all = [
		...head,
		...new Array(halves.length === 2 ? missing : 0).fill(0),
		...tail
	];
	const bytes = /* @__PURE__ */ new Uint8Array(16);
	for (const [i, group] of all.entries()) {
		bytes[i * 2] = group >> 8;
		bytes[i * 2 + 1] = group & 255;
	}
	return bytes;
}
function parsePrefix(cidr) {
	const [address = "", bits = ""] = cidr.split("/");
	const bytes = parseIpv4(address) ?? parseIpv6(address);
	if (!bytes) throw new Error(`Bad prefix ${cidr}`);
	return {
		bytes,
		bits: Number(bits)
	};
}
function inPrefix(address, prefix) {
	if (address.length !== prefix.bytes.length) return false;
	const whole = prefix.bits >> 3;
	for (let i = 0; i < whole; i++) if (address[i] !== prefix.bytes[i]) return false;
	const rest = prefix.bits & 7;
	if (rest === 0) return true;
	const mask = 255 << 8 - rest;
	return (address[whole] & mask) === (prefix.bytes[whole] & mask);
}
const V4_TABLE = IPV4_BLOCKED.map(([cidr, name]) => ({
	cidr,
	name,
	prefix: parsePrefix(cidr)
}));
const V6_TABLE = IPV6_BLOCKED.map(([cidr, name]) => ({
	cidr,
	name,
	prefix: parsePrefix(cidr)
}));
const V6_EMBED_TABLE = IPV6_EMBEDS_IPV4.map(([cidr, name, offset]) => ({
	cidr,
	name,
	offset,
	prefix: parsePrefix(cidr)
}));
const GLOBAL_UNICAST = parsePrefix("2000::/3");
function blockedIpv4(bytes) {
	const hit = V4_TABLE.find((row) => inPrefix(bytes, row.prefix));
	return hit && `${hit.name} (${hit.cidr})`;
}
/**
* Classifies one address. Anything that isn't a well-formed IPv4 or IPv6
* address is refused, so a caller can't be tricked by a form this code reads
* differently from the operating system.
*/
function classifyAddress(input) {
	const text = input.startsWith("[") && input.endsWith("]") ? input.slice(1, -1) : input;
	const v4 = parseIpv4(text);
	if (v4) {
		const reason = blockedIpv4(v4);
		return {
			address: text,
			family: 4,
			allowed: !reason,
			reason
		};
	}
	const v6 = parseIpv6(text);
	if (!v6) return {
		address: text,
		family: 6,
		allowed: false,
		reason: "not a valid IP address"
	};
	const address = text.toLowerCase();
	for (const row of V6_EMBED_TABLE) {
		if (!inPrefix(v6, row.prefix)) continue;
		const inner = v6.slice(row.offset, row.offset + 4);
		const embeddedIpv4 = inner.join(".");
		const reason = blockedIpv4(inner);
		return {
			address,
			family: 6,
			allowed: !reason,
			embeddedIpv4,
			reason: reason && `${row.name} address for ${embeddedIpv4}: ${reason}`
		};
	}
	const hit = V6_TABLE.find((row) => inPrefix(v6, row.prefix));
	if (hit) return {
		address,
		family: 6,
		allowed: false,
		reason: `${hit.name} (${hit.cidr})`
	};
	if (!inPrefix(v6, GLOBAL_UNICAST)) return {
		address,
		family: 6,
		allowed: false,
		reason: "outside global unicast space (2000::/3)"
	};
	return {
		address,
		family: 6,
		allowed: true
	};
}
/** 4, 6, or 0 when `text` is not an IP literal (brackets allowed around IPv6). */
function ipFamily(text) {
	if (parseIpv4(text)) return 4;
	return parseIpv6(text.startsWith("[") && text.endsWith("]") ? text.slice(1, -1) : text) ? 6 : 0;
}
//#endregion
//#region packages/scan-core/src/net/policy.ts
/**
* Turns what a user typed into a target the scanner is willing to look at.
*
* Everything here is syntax: scheme, port, credentials, and hosts that are
* plainly internal. It runs in the API (to refuse a request before queuing it)
* and again in the worker. The decision that actually matters, which address
* the name resolves to, is made in resolve.ts.
*
* No Node APIs: the web app uses the same function to explain a refusal
* before sending anything.
*/
/** A target the scanner refused, with a code tests and the UI can switch on. */
var TargetRejected = class extends Error {
	code;
	constructor(code, message) {
		super(message);
		this.name = "TargetRejected";
		this.code = code;
	}
};
const DEFAULT_POLICY = {
	allowedPorts: [443, 8443],
	labOrigins: []
};
const MAX_URL_LENGTH = 2048;
/** Names that only mean something inside a private network (RFC 6761, RFC 6762, RFC 8375, RFC 9476 and common practice). */
const INTERNAL_SUFFIXES = [
	"localhost",
	"local",
	"internal",
	"intranet",
	"lan",
	"home",
	"corp",
	"home.arpa",
	"localdomain",
	"svc"
];
/**
* Parses and checks a target. Throws TargetRejected with the reason.
* `input` may omit the scheme ("example.com/login" means https).
*/
function parseTarget(input, policy = DEFAULT_POLICY) {
	const text = input.trim();
	if (!text || text.length > MAX_URL_LENGTH) throw new TargetRejected("invalid-url", "Enter the address of a login page or sign-in service.");
	let url;
	try {
		url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `https://${text}`);
	} catch {
		throw new TargetRejected("invalid-url", "That is not a valid address.");
	}
	url.hash = "";
	const isLab = policy.labOrigins.includes(url.origin);
	const hostname = url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
	const port = url.port ? Number(url.port) : url.protocol === "http:" ? 80 : 443;
	const hostFamily = ipFamily(hostname);
	const target = {
		url,
		origin: url.origin,
		hostname,
		port,
		hostFamily,
		isLab
	};
	if (url.username || url.password) throw new TargetRejected("credentials-in-url", "Remove the username and password from the address.");
	if (!isLab && url.protocol !== "https:") throw new TargetRejected("scheme-not-allowed", `Only https:// addresses can be scanned, not ${url.protocol}//.`);
	if (!hostname) throw new TargetRejected("invalid-url", "That address has no host name.");
	if (isLab) return target;
	if (!policy.allowedPorts.includes(port)) throw new TargetRejected("port-not-allowed", `Port ${port} is not allowed. Allowed ports: ${policy.allowedPorts.join(", ")}.`);
	if (hostFamily) {
		const verdict = classifyAddress(hostname);
		if (!verdict.allowed) throw new TargetRejected("address-not-allowed", `${hostname} is not a public address: ${verdict.reason}.`);
		return target;
	}
	if (!hostname.includes(".")) throw new TargetRejected("hostname-not-allowed", `"${hostname}" is not a public host name.`);
	if (INTERNAL_SUFFIXES.some((suffix) => hostname.endsWith(`.${suffix}`))) throw new TargetRejected("hostname-not-allowed", `"${hostname}" is a private or special-use name.`);
	return target;
}
//#endregion
//#region packages/scan-core/src/net/resolve.ts
/**
* Resolves a target's host name once, checks every address it returned, and
* pins one. All later connections for that target go to the pinned address;
* nothing resolves the name again. That single rule is the defence against
* DNS rebinding (ADR 0007).
*/
const systemLookup = async (hostname) => {
	return (await lookup(hostname, {
		all: true,
		verbatim: true
	})).map((r) => ({
		address: r.address,
		family: r.family === 6 ? 6 : 4
	}));
};
async function resolveTarget(target, options = {}) {
	const { hostname, port, isLab } = target;
	const base = {
		hostname,
		port,
		isLab
	};
	if (target.hostFamily) {
		const verdict = classifyAddress(hostname);
		if (!verdict.allowed && !isLab) throw new TargetRejected("address-not-allowed", `${hostname} is not a public address: ${verdict.reason}.`);
		return {
			...base,
			address: hostname,
			family: target.hostFamily,
			resolved: [verdict],
			hasHostname: false
		};
	}
	const lookup = options.lookup ?? systemLookup;
	let answers;
	try {
		answers = await withTimeout(lookup(hostname), options.timeoutMs ?? 4e3);
	} catch (error) {
		throw new TargetRejected("dns-failure", `Could not resolve ${hostname}: ${dnsReason(error)}.`);
	}
	answers = answers.filter((a) => net.isIP(a.address) !== 0);
	if (answers.length === 0) throw new TargetRejected("dns-failure", `${hostname} did not resolve to any address.`);
	const resolved = answers.map((a) => classifyAddress(a.address));
	if (!isLab) {
		const bad = resolved.find((v) => !v.allowed);
		if (bad) throw new TargetRejected("address-not-allowed", `${hostname} resolves to ${bad.address}, which is not a public address: ${bad.reason}.`);
	}
	const chosen = resolved.find((v) => v.family === 4) ?? resolved[0];
	return {
		...base,
		address: chosen.address,
		family: chosen.family,
		resolved,
		hasHostname: true
	};
}
function withTimeout(promise, ms) {
	return new Promise((resolve, reject) => {
		const timer = setTimeout(() => reject(/* @__PURE__ */ new Error("timed out")), ms);
		promise.then((value) => {
			clearTimeout(timer);
			resolve(value);
		}, (error) => {
			clearTimeout(timer);
			reject(error instanceof Error ? error : new Error(String(error)));
		});
	});
}
function dnsReason(error) {
	const code = error.code;
	if (code === "ENOTFOUND") return "no such host";
	if (code === "EAI_AGAIN") return "the DNS server did not answer";
	return error instanceof Error ? error.message : "lookup failed";
}
//#endregion
//#region packages/scan-core/src/report.ts
/** Bump when findings would change for the same observations. Stored with every report. */
const ENGINE_VERSION = "1.2.0";
//#endregion
//#region packages/scan-core/src/tls/registry.ts
const group = (id, name, kex, components, draft) => ({
	id,
	name,
	kex,
	components,
	draft
});
const GROUP = {
	secp256r1: 23,
	secp384r1: 24,
	secp521r1: 25,
	x25519: 29,
	x448: 30,
	ffdhe2048: 256,
	ffdhe3072: 257,
	MLKEM512: 512,
	MLKEM768: 513,
	MLKEM1024: 514,
	SecP256r1MLKEM768: 4587,
	X25519MLKEM768: 4588,
	SecP384r1MLKEM1024: 4589,
	X25519Kyber768Draft00: 25497
};
const GROUPS = Object.fromEntries([
	group(GROUP.secp256r1, "secp256r1", "classical", ["ECDH P-256"]),
	group(GROUP.secp384r1, "secp384r1", "classical", ["ECDH P-384"]),
	group(GROUP.secp521r1, "secp521r1", "classical", ["ECDH P-521"]),
	group(GROUP.x25519, "x25519", "classical", ["X25519"]),
	group(GROUP.x448, "x448", "classical", ["X448"]),
	group(GROUP.ffdhe2048, "ffdhe2048", "classical", ["Finite-field DH 2048-bit"]),
	group(GROUP.ffdhe3072, "ffdhe3072", "classical", ["Finite-field DH 3072-bit"]),
	group(258, "ffdhe4096", "classical", ["Finite-field DH 4096-bit"]),
	group(GROUP.MLKEM512, "MLKEM512", "pq", ["ML-KEM-512"]),
	group(GROUP.MLKEM768, "MLKEM768", "pq", ["ML-KEM-768"]),
	group(GROUP.MLKEM1024, "MLKEM1024", "pq", ["ML-KEM-1024"]),
	group(GROUP.SecP256r1MLKEM768, "SecP256r1MLKEM768", "hybrid", ["ECDH P-256", "ML-KEM-768"]),
	group(GROUP.X25519MLKEM768, "X25519MLKEM768", "hybrid", ["X25519", "ML-KEM-768"]),
	group(GROUP.SecP384r1MLKEM1024, "SecP384r1MLKEM1024", "hybrid", ["ECDH P-384", "ML-KEM-1024"]),
	group(4590, "curveSM2MLKEM768", "hybrid", ["SM2", "ML-KEM-768"]),
	group(GROUP.X25519Kyber768Draft00, "X25519Kyber768Draft00", "hybrid", ["X25519", "Kyber-768 (round 3)"], true),
	group(25498, "SecP256r1Kyber768Draft00", "hybrid", ["ECDH P-256", "Kyber-768 (round 3)"], true)
].map((g) => [g.id, g]));
function groupName(id) {
	return GROUPS[id]?.name ?? `unknown group 0x${id.toString(16).padStart(4, "0")}`;
}
/** The post-quantum and hybrid groups the scanner asks about one by one. */
const PQ_GROUPS_TO_ENUMERATE = [
	GROUP.X25519MLKEM768,
	GROUP.SecP256r1MLKEM768,
	GROUP.SecP384r1MLKEM1024,
	GROUP.MLKEM768,
	GROUP.MLKEM1024
];
const suite13 = (id, name, cipher, keyBits, hash) => ({
	id,
	name,
	protocol: "1.3",
	cipher,
	keyBits,
	aead: true,
	hash
});
function suite12(id, name) {
	const [left = "", right = ""] = name.replace(/^TLS_/, "").split("_WITH_");
	const [kex, auth] = left.split("_");
	const keyExchange = kex === "ECDHE" ? "ECDHE" : kex === "DHE" ? "DHE" : "RSA";
	const aead = /GCM|POLY1305|CCM/.test(right);
	return {
		id,
		name,
		protocol: "1.2",
		keyExchange,
		authentication: (auth ?? kex) === "ECDSA" ? "ECDSA" : "RSA",
		cipher: right.replace(/_SHA\d*$/, "").replaceAll("_", "-"),
		keyBits: /AES_256|CHACHA20/.test(right) ? 256 : /3DES/.test(right) ? 112 : 128,
		aead,
		hash: right.endsWith("SHA384") ? "sha384" : aead || right.endsWith("SHA256") ? "sha256" : "sha1"
	};
}
const CIPHER_SUITES = Object.fromEntries([
	suite13(4865, "TLS_AES_128_GCM_SHA256", "AES-128-GCM", 128, "sha256"),
	suite13(4866, "TLS_AES_256_GCM_SHA384", "AES-256-GCM", 256, "sha384"),
	suite13(4867, "TLS_CHACHA20_POLY1305_SHA256", "CHACHA20-POLY1305", 256, "sha256"),
	suite12(49195, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
	suite12(49196, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
	suite12(49199, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
	suite12(49200, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
	suite12(52392, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
	suite12(52393, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
	suite12(49161, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
	suite12(49162, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
	suite12(49171, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
	suite12(49172, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
	suite12(49191, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"),
	suite12(49192, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"),
	suite12(158, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
	suite12(159, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
	suite12(51, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
	suite12(57, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"),
	suite12(156, "TLS_RSA_WITH_AES_128_GCM_SHA256"),
	suite12(157, "TLS_RSA_WITH_AES_256_GCM_SHA384"),
	suite12(47, "TLS_RSA_WITH_AES_128_CBC_SHA"),
	suite12(53, "TLS_RSA_WITH_AES_256_CBC_SHA"),
	suite12(60, "TLS_RSA_WITH_AES_128_CBC_SHA256"),
	suite12(61, "TLS_RSA_WITH_AES_256_CBC_SHA256")
].map((s) => [s.id, s]));
const TLS13_SUITES = [
	4866,
	4865,
	4867
];
/** Offered to TLS 1.2 servers, forward-secret suites first, RSA key transport last. */
const TLS12_SUITES = [
	49196,
	49200,
	49195,
	49199,
	52393,
	52392,
	159,
	158,
	49162,
	49172,
	49161,
	49171,
	49192,
	49191,
	57,
	51,
	157,
	156,
	61,
	60,
	53,
	47
];
function cipherSuiteName(id) {
	return CIPHER_SUITES[id]?.name ?? `unknown suite 0x${id.toString(16).padStart(4, "0")}`;
}
const scheme = (id, name, family, extra = {}) => ({
	id,
	name,
	family,
	quantumSafe: family === "ML-DSA",
	...extra
});
const SIGNATURE_SCHEMES = Object.fromEntries([
	scheme(2308, "mldsa44", "ML-DSA"),
	scheme(2309, "mldsa65", "ML-DSA"),
	scheme(2310, "mldsa87", "ML-DSA"),
	scheme(1027, "ecdsa_secp256r1_sha256", "ECDSA", {
		hash: "sha256",
		curve: "prime256v1"
	}),
	scheme(1283, "ecdsa_secp384r1_sha384", "ECDSA", {
		hash: "sha384",
		curve: "secp384r1"
	}),
	scheme(1539, "ecdsa_secp521r1_sha512", "ECDSA", {
		hash: "sha512",
		curve: "secp521r1"
	}),
	scheme(2055, "ed25519", "EdDSA"),
	scheme(2056, "ed448", "EdDSA"),
	scheme(2052, "rsa_pss_rsae_sha256", "RSA", {
		hash: "sha256",
		padding: "pss"
	}),
	scheme(2053, "rsa_pss_rsae_sha384", "RSA", {
		hash: "sha384",
		padding: "pss"
	}),
	scheme(2054, "rsa_pss_rsae_sha512", "RSA", {
		hash: "sha512",
		padding: "pss"
	}),
	scheme(2057, "rsa_pss_pss_sha256", "RSA", {
		hash: "sha256",
		padding: "pss"
	}),
	scheme(2058, "rsa_pss_pss_sha384", "RSA", {
		hash: "sha384",
		padding: "pss"
	}),
	scheme(2059, "rsa_pss_pss_sha512", "RSA", {
		hash: "sha512",
		padding: "pss"
	}),
	scheme(1025, "rsa_pkcs1_sha256", "RSA", {
		hash: "sha256",
		padding: "pkcs1"
	}),
	scheme(1281, "rsa_pkcs1_sha384", "RSA", {
		hash: "sha384",
		padding: "pkcs1"
	}),
	scheme(1537, "rsa_pkcs1_sha512", "RSA", {
		hash: "sha512",
		padding: "pkcs1"
	}),
	scheme(513, "rsa_pkcs1_sha1", "RSA", {
		hash: "sha1",
		padding: "pkcs1"
	}),
	scheme(515, "ecdsa_sha1", "ECDSA", { hash: "sha1" })
].map((s) => [s.id, s]));
/** What a client that understands ML-DSA offers, most preferred first. */
const SIGNATURE_SCHEMES_WITH_PQ = [
	2309,
	2308,
	2310,
	1027,
	1283,
	1539,
	2055,
	2056,
	2052,
	2053,
	2054,
	2057,
	2058,
	2059,
	1025,
	1281,
	1537
];
/** What a client without post-quantum support offers. SHA-1 schemes come last so a server using one is seen, not hidden. */
const SIGNATURE_SCHEMES_CLASSICAL = [
	1027,
	1283,
	1539,
	2055,
	2056,
	2052,
	2053,
	2054,
	2057,
	2058,
	2059,
	1025,
	1281,
	1537,
	515,
	513
];
function signatureSchemeName(id) {
	return SIGNATURE_SCHEMES[id]?.name ?? `unknown scheme 0x${id.toString(16).padStart(4, "0")}`;
}
const ALERTS = {
	0: "close_notify",
	10: "unexpected_message",
	20: "bad_record_mac",
	22: "record_overflow",
	40: "handshake_failure",
	42: "bad_certificate",
	43: "unsupported_certificate",
	45: "certificate_expired",
	46: "certificate_unknown",
	47: "illegal_parameter",
	48: "unknown_ca",
	49: "access_denied",
	50: "decode_error",
	51: "decrypt_error",
	70: "protocol_version",
	71: "insufficient_security",
	80: "internal_error",
	86: "inappropriate_fallback",
	90: "user_canceled",
	109: "missing_extension",
	110: "unsupported_extension",
	112: "unrecognized_name",
	116: "certificate_required",
	120: "no_application_protocol"
};
function alertName(description) {
	return ALERTS[description] ?? `alert ${description}`;
}
const VERSIONS = {
	772: "1.3",
	771: "1.2",
	770: "1.1",
	769: "1.0",
	768: "SSL 3.0"
};
function versionName(id) {
	return VERSIONS[id] ?? `0x${id.toString(16).padStart(4, "0")}`;
}
//#endregion
//#region packages/scan-core/src/assess.ts
const hex = (id) => `0x${id.toString(16).padStart(4, "0")}`;
const list = (items) => items.length <= 1 ? items[0] ?? "" : `${items.slice(0, -1).join(", ")} and ${items.at(-1)}`;
/** The probe got far enough to show a ServerHello. */
const answered = (probe) => probe !== void 0 && probe.version !== void 0 && (probe.outcome === "handshake" || probe.outcome === "server-hello");
/**
* The server turned the probe down before any ServerHello: a TLS alert, or a connection cut the same way on
* two attempts. A timeout, or a connection cut once, was neither an answer nor a refusal: something in between
* may have caused it.
*/
const refused = (probe) => probe !== void 0 && (probe.outcome === "alert" || probe.outcome === "closed" && probe.confirmed === true);
const ifAnswered = (probe) => answered(probe) ? probe : void 0;
/** How a completed handshake established its keys. */
function keyExchange(probe) {
	if (probe.version === 772 || probe.group !== void 0) {
		const info = probe.group === void 0 ? void 0 : GROUPS[probe.group];
		if (!info) return {
			label: probe.group === void 0 ? "an unreported group" : groupName(probe.group),
			kind: "unknown",
			parts: []
		};
		return {
			label: info.name,
			kind: info.kex,
			parts: info.components
		};
	}
	const suite = CIPHER_SUITES[probe.cipherSuite ?? -1];
	if (suite?.keyExchange === "RSA") return {
		label: "RSA key transport",
		kind: "rsa-transport",
		parts: ["RSA encryption"]
	};
	if (suite?.keyExchange === "DHE") return {
		label: `finite-field Diffie-Hellman${probe.dhPrimeBits ? ` (${probe.dhPrimeBits}-bit)` : ""}`,
		kind: "classical",
		parts: ["Finite-field DH"]
	};
	return {
		label: "an unidentified key exchange",
		kind: "unknown",
		parts: []
	};
}
const unanswered = (probe) => probe.alert ? `alert ${probe.alert}` : `${probe.detail ?? probe.outcome}${probe.confirmed ? ", on two attempts" : ""}`;
const helloEvidence = (probe) => [
	{
		label: "Scanner offered",
		value: `${list(probe.offered.groups.map(groupName))}; key shares for ${list(probe.offered.keyShares.map(groupName)) || "none"}`
	},
	{
		label: "ServerHello",
		value: `TLS ${versionName(probe.version)}, ${cipherSuiteName(probe.cipherSuite)}${probe.group === void 0 ? "" : `, group ${hex(probe.group)} ${groupName(probe.group)}`}`
	},
	...probe.finishedValid === void 0 ? [] : [{
		label: "Finished MAC",
		value: probe.finishedValid ? "verified: the scanner derived the same keys as the server" : "did not verify"
	}],
	...probe.retried ? [{
		label: "Note",
		value: "the server first asked for a different key share (HelloRetryRequest)"
	}] : []
];
function assess(seen) {
	const findings = [];
	const layers = [];
	const add = (finding) => findings.push(finding);
	const layer = (id, name, headline, exposure, tone) => layers.push({
		id,
		name,
		headline,
		exposure,
		tone
	});
	if (!seen.reachable) {
		add({
			id: "net.unreachable",
			layer: "key-establishment",
			kind: "undetermined",
			tone: "neutral",
			title: "Nothing could be observed: the server did not accept a connection",
			detail: seen.probes[0]?.detail ?? "No TCP connection could be made."
		});
		for (const [id, name] of LAYER_NAMES) layer(id, name, "Could not determine", "undetermined", "neutral");
		return {
			layers,
			findings
		};
	}
	const main = seen.probes.find((p) => p.id === "pq-capable-client");
	const classicalClient = seen.probes.find((p) => p.id === "classical-client");
	const legacy = seen.probes.find((p) => p.id === "tls12-client");
	/** The handshake the rest of the report describes: the capable client's if it worked, otherwise whichever did. */
	const best = ifAnswered(main) ?? ifAnswered(classicalClient) ?? ifAnswered(legacy);
	assessKeyEstablishment();
	function assessKeyEstablishment() {
		if (!best) {
			const outcomes = [
				main,
				classicalClient,
				legacy
			].filter((p) => p !== void 0).map((p) => `${p.id}: ${p.alert ?? p.detail ?? p.outcome}`);
			add({
				id: "kex.undetermined",
				layer: "key-establishment",
				kind: "undetermined",
				tone: "neutral",
				title: "No TLS handshake could be completed",
				detail: "The server accepted a connection but none of the scanner’s handshakes got a usable answer, so the key exchange could not be observed.",
				evidence: outcomes.map((value, i) => ({
					label: `Attempt ${i + 1}`,
					value
				}))
			});
			return layer("key-establishment", "TLS key establishment", "Could not determine", "undetermined", "neutral");
		}
		const mainAnswered = answered(main);
		const kex = keyExchange(best);
		const quantumSafe = kex.kind === "hybrid" || kex.kind === "pq";
		const tls12 = best.version !== 772;
		add({
			id: "kex.negotiated",
			layer: "key-establishment",
			kind: "observation",
			tone: quantumSafe ? "good" : kex.kind === "rsa-transport" ? "bad" : "caution",
			title: kex.kind === "hybrid" ? `Key exchange: ${kex.label}, a hybrid of ${list(kex.parts)}` : kex.kind === "pq" ? `Key exchange: ${kex.label}, post-quantum with no classical part` : kex.kind === "rsa-transport" ? "Key exchange: RSA key transport, with no forward secrecy" : `Key exchange: ${kex.label}, classical${tls12 ? ` (TLS ${versionName(best.version)})` : ""}`,
			detail: kex.kind === "hybrid" ? "Negotiated by a client that offers post-quantum key exchange. The session keys depend on both parts, so they stay secret unless both are broken." : kex.kind === "pq" ? "Negotiated by a client that offers post-quantum key exchange. The session keys depend on ML-KEM alone." : kex.kind === "rsa-transport" ? "The client encrypts the session secret to the certificate’s RSA key. Anyone who later obtains that one private key can decrypt every session recorded before." : !mainAnswered ? "This is what a client without post-quantum support negotiated. The handshake that offered post-quantum key exchange was not completed." : tls12 ? "The server chose TLS 1.2 although TLS 1.3 was offered. TLS 1.2 has no post-quantum key exchange." : "The scanner offered X25519MLKEM768 first and sent a key share for it. The server chose a classical group instead.",
			evidence: helloEvidence(best),
			learn: {
				view: "login",
				landmark: "key-establishment",
				mode: quantumSafe ? "hybrid" : "classical"
			}
		});
		const kexOnly = seen.probes.find((p) => p.id === "classical-kex-client");
		const kexRefused = main?.leafKey?.quantumSafe ? refused(kexOnly) : refused(classicalClient);
		const classicalAnswer = ifAnswered(classicalClient) ?? ifAnswered(kexOnly);
		if (main && !mainAnswered && classicalAnswer && [
			"timeout",
			"closed",
			"malformed"
		].includes(main.outcome)) add({
			id: "kex.large-hello",
			layer: "key-establishment",
			kind: "inference",
			tone: "bad",
			title: "The server, or something in front of it, drops handshakes that carry a post-quantum key share",
			detail: "A ClientHello that carries an ML-KEM-768 key share is larger than one network packet usually holds (the key share alone is about 1,200 bytes), so it is normally split across two. This server answered the small classical ClientHello but not the large one, which is the pattern of a load balancer or firewall that cannot handle a ClientHello split across packets. Clients that offer post-quantum key exchange may fail to connect.",
			basedOn: ["kex.negotiated"],
			evidence: [{
				label: "Post-quantum-capable ClientHello",
				value: main.detail ?? main.outcome
			}, {
				label: "Classical ClientHello",
				value: `answered with TLS ${versionName(classicalAnswer.version)}`
			}]
		});
		const fallback = classicalAnswer ? keyExchange(classicalAnswer) : void 0;
		if (quantumSafe && classicalClient) {
			const attempts = [{
				label: "ClientHello with classical groups and classical signatures",
				value: unanswered(classicalClient)
			}, ...kexOnly ? [{
				label: "ClientHello with classical groups and ML-DSA signatures",
				value: answered(kexOnly) ? `answered with TLS ${versionName(kexOnly.version)}` : unanswered(kexOnly)
			}] : []];
			add(fallback && classicalAnswer ? classicalAnswer === kexOnly ? {
				id: "kex.classical-client",
				layer: "key-establishment",
				kind: "observation",
				tone: "neutral",
				title: `A client that accepts the post-quantum certificate can still connect with classical key exchange (${fallback.label})`,
				detail: `The handshake that offered only classical groups and classical signature schemes ${refused(classicalClient) ? "was refused" : "got no answer"}, but one that kept ML-DSA signatures and offered only classical groups completed.${refused(classicalClient) ? " So what stopped the first was the certificate, not the key exchange." : ""} Sessions from such clients get classical key exchange.`,
				evidence: [...attempts, ...helloEvidence(classicalAnswer)]
			} : {
				id: "kex.classical-client",
				layer: "key-establishment",
				kind: "observation",
				tone: "neutral",
				title: `Clients without post-quantum support still connect, using ${fallback.label}`,
				detail: "This keeps older browsers, libraries and devices working. Their sessions get classical key exchange.",
				evidence: helloEvidence(classicalAnswer)
			} : kexRefused ? {
				id: "kex.classical-client",
				layer: "key-establishment",
				kind: "observation",
				tone: "neutral",
				title: "TLS 1.3 clients without post-quantum key exchange are refused",
				detail: "A ClientHello offering only classical groups was rejected. Clients that cannot use post-quantum key exchange are locked out of TLS 1.3 here.",
				evidence: attempts
			} : {
				id: "kex.classical-client",
				layer: "key-establishment",
				kind: "undetermined",
				tone: "neutral",
				title: "What clients without post-quantum key exchange get could not be determined",
				detail: "The handshake that would show it neither completed nor was clearly refused, so whether such clients can connect, and with what key exchange, is not known.",
				evidence: attempts
			});
		}
		if (legacy && best.version === 772) {
			const legacyKex = answered(legacy) ? keyExchange(legacy) : void 0;
			add(legacyKex ? {
				id: "kex.tls12",
				layer: "key-establishment",
				kind: "observation",
				tone: legacyKex.kind === "rsa-transport" ? "bad" : "neutral",
				title: `TLS 1.2 is still accepted (${legacyKex.label})`,
				detail: legacyKex.kind === "rsa-transport" ? "A TLS 1.2 client gets RSA key transport, which has no forward secrecy even against today’s attackers." : "A client that only speaks TLS 1.2 gets classical key exchange; post-quantum groups exist only in TLS 1.3. TLS 1.3 has downgrade protection, so an attacker on the network cannot make a client that supports 1.3 settle for 1.2.",
				evidence: [{
					label: "ServerHello",
					value: `TLS ${versionName(legacy.version)}, ${cipherSuiteName(legacy.cipherSuite)}`
				}]
			} : refused(legacy) ? {
				id: "kex.tls12",
				layer: "key-establishment",
				kind: "observation",
				tone: "good",
				title: "TLS 1.2 is not accepted",
				detail: "A TLS 1.2 ClientHello was refused, so every connection uses TLS 1.3.",
				evidence: [{
					label: "TLS 1.2 ClientHello",
					value: unanswered(legacy)
				}]
			} : {
				id: "kex.tls12",
				layer: "key-establishment",
				kind: "undetermined",
				tone: "neutral",
				title: "Whether TLS 1.2 is accepted could not be determined",
				detail: "The TLS 1.2 handshake neither completed nor was clearly refused.",
				evidence: [{
					label: "TLS 1.2 ClientHello",
					value: unanswered(legacy)
				}]
			});
		}
		const accepted = seen.groupSupport.filter((g) => g.supported === true);
		const unknown = seen.groupSupport.filter((g) => g.supported === void 0);
		if (seen.groupSupport.length > 0) add({
			id: "kex.groups",
			layer: "key-establishment",
			kind: "observation",
			tone: accepted.length > 0 ? "good" : "neutral",
			title: accepted.length > 0 ? `Post-quantum groups accepted: ${list(accepted.map((g) => g.name))}` : unknown.length > 0 ? "No post-quantum key-exchange group was seen to be accepted" : "No post-quantum key-exchange group is accepted",
			detail: `The scanner asked about each of ${seen.groupSupport.length} hybrid and ML-KEM groups separately.${unknown.length > 0 ? ` ${unknown.length} gave no usable answer.` : ""} A group it did not ask about cannot be detected.`,
			evidence: seen.groupSupport.map((g) => ({
				label: g.name,
				value: `${g.supported === void 0 ? "unknown" : g.supported ? "accepted" : "not accepted"}: ${g.evidence}`
			}))
		});
		const basedOn = [
			"kex.negotiated",
			"kex.classical-client",
			"kex.tls12"
		].filter((id) => findings.some((f) => f.id === id));
		const fallbackSeen = fallback !== void 0 || answered(legacy);
		const noFallback = !fallbackSeen && kexRefused && (legacy === void 0 || refused(legacy));
		if (quantumSafe && noFallback) {
			add({
				id: "kex.exposure",
				layer: "key-establishment",
				kind: "inference",
				tone: "good",
				title: "Traffic recorded today cannot be decrypted later by a quantum computer",
				detail: "Every client that can connect negotiates ML-KEM (FIPS 203), for which no quantum attack is known. An attacker who stores this traffic gains nothing from a future quantum computer.",
				basedOn,
				learn: {
					view: "login",
					landmark: "harvest",
					mode: "hybrid",
					attacker: "quantum"
				}
			});
			layer("key-establishment", "TLS key establishment", `${kex.kind === "hybrid" ? "Hybrid" : "Post-quantum"}: ${kex.label}`, "no-known-attack", "good");
		} else if (quantumSafe && !fallbackSeen) {
			add({
				id: "kex.exposure",
				layer: "key-establishment",
				kind: "inference",
				tone: "caution",
				title: "Sessions that negotiate ML-KEM are protected; what other clients get is not known",
				detail: "Sessions that negotiate ML-KEM cannot be decrypted later by a quantum computer. A handshake without post-quantum key exchange neither completed nor was clearly refused, so the scanner could not establish whether such clients are turned away or fall back to classical key exchange.",
				basedOn,
				learn: {
					view: "login",
					landmark: "harvest",
					mode: "hybrid",
					attacker: "quantum"
				}
			});
			layer("key-establishment", "TLS key establishment", `${kex.kind === "hybrid" ? "Hybrid" : "Post-quantum"}: ${kex.label}, other clients not determined`, "depends-on-client", "caution");
		} else if (quantumSafe) {
			add({
				id: "kex.exposure",
				layer: "key-establishment",
				kind: "inference",
				tone: "caution",
				title: "Recorded traffic is protected only for clients that support post-quantum key exchange",
				detail: "Sessions that negotiate ML-KEM cannot be decrypted later by a quantum computer. Sessions from clients that fall back to classical key exchange can: an attacker who records them now can decrypt them once a large quantum computer exists (\"harvest now, decrypt later\"). Which of your clients fall back is not visible from outside.",
				basedOn,
				learn: {
					view: "login",
					landmark: "harvest",
					mode: "hybrid",
					attacker: "quantum"
				}
			});
			layer("key-establishment", "TLS key establishment", `${kex.kind === "hybrid" ? "Hybrid" : "Post-quantum"}: ${kex.label}, with classical fallback`, "depends-on-client", "caution");
		} else if (kex.kind === "unknown") {
			add({
				id: "kex.exposure",
				layer: "key-establishment",
				kind: "undetermined",
				tone: "neutral",
				title: "The key-exchange group is not one the scanner knows",
				detail: `The server selected ${kex.label}. Without knowing what it is, nothing can be said about its resistance to a quantum computer.`
			});
			layer("key-establishment", "TLS key establishment", kex.label, "undetermined", "neutral");
		} else {
			add({
				id: "kex.exposure",
				layer: "key-establishment",
				kind: "inference",
				tone: "bad",
				title: "Traffic recorded today could be decrypted later by a quantum computer",
				detail: kex.kind === "rsa-transport" ? "The session secret is encrypted to an RSA key. Shor’s algorithm recovers an RSA private key from the public key, so an attacker who stores this traffic can decrypt all of it once a large enough quantum computer exists. A stolen private key does the same today." : `The session keys come from ${kex.label} alone. Shor’s algorithm recovers the private value behind the public key share sent in the handshake, so an attacker who stores this traffic can decrypt it once a large enough quantum computer exists ("harvest now, decrypt later"). No such computer is known to exist. This is the most urgent quantum risk because the recording can happen now.`,
				basedOn,
				learn: {
					view: "login",
					landmark: "harvest",
					mode: "classical",
					attacker: "quantum"
				}
			});
			layer("key-establishment", "TLS key establishment", `Classical: ${kex.label}`, "harvest-now-decrypt-later", "bad");
		}
	}
	assessServerAuthentication();
	function assessServerAuthentication() {
		const leaf = seen.certificates[0];
		if (!leaf) {
			add({
				id: "auth.undetermined",
				layer: "server-authentication",
				kind: "undetermined",
				tone: "neutral",
				title: "The server’s certificate could not be read",
				detail: best ? "A ServerHello was received, but the rest of the server’s handshake could not be read or decrypted." : "No handshake was completed."
			});
			return layer("server-authentication", "TLS server authentication", "Could not determine", "undetermined", "neutral");
		}
		add({
			id: "auth.certificate",
			layer: "server-authentication",
			kind: "observation",
			tone: leaf.key.quantumSafe ? "good" : "neutral",
			title: `Certificate key: ${leaf.key.algorithm}`,
			detail: `Issued to ${leaf.names[0] ?? leaf.subject} by "${leaf.issuer}", valid until ${leaf.notAfter.slice(0, 10)}. The server sent ${seen.certificates.length} certificate${seen.certificates.length === 1 ? "" : "s"}.`,
			evidence: seen.certificates.map((c) => ({
				label: c.position === 0 ? "Leaf" : `Chain #${c.position}`,
				value: `${c.subject}; key ${c.key.algorithm}; signed by "${c.issuer}" with ${c.signature.algorithm}`
			})),
			learn: {
				view: "login",
				landmark: "secure-channel",
				mode: leaf.key.quantumSafe ? "pq" : "classical"
			}
		});
		if (leaf.expired || leaf.notYetValid) add({
			id: "auth.validity",
			layer: "server-authentication",
			kind: "observation",
			tone: "bad",
			title: leaf.expired ? `The certificate expired on ${leaf.notAfter.slice(0, 10)}` : `The certificate is not valid until ${leaf.notBefore.slice(0, 10)}`,
			detail: "Browsers refuse this certificate regardless of its algorithms.",
			evidence: [{
				label: "Validity",
				value: `${leaf.notBefore} to ${leaf.notAfter}`
			}]
		});
		const proof = best?.signatureScheme === void 0 ? void 0 : SIGNATURE_SCHEMES[best.signatureScheme];
		if (best?.signatureScheme !== void 0) {
			const message = best.version === 772 ? "CertificateVerify, a signature over the handshake transcript" : "ServerKeyExchange, a signature over the key-exchange parameters";
			add({
				id: "auth.proof",
				layer: "server-authentication",
				kind: "observation",
				tone: best.signatureValid === false ? "bad" : "neutral",
				title: best.signatureValid === false ? "The server’s proof of key possession did not verify" : `The server proved it holds that key with ${signatureSchemeName(best.signatureScheme)}`,
				detail: best.signatureValid === true ? `The scanner checked ${message} against the leaf certificate’s public key. It is valid.` : best.signatureValid === false ? `${message} did not verify against the leaf certificate’s public key. That should never happen with a working server.` : `${message} uses a scheme or key type the scanner cannot check.`,
				evidence: [{
					label: "Signature scheme",
					value: `${hex(best.signatureScheme)} ${signatureSchemeName(best.signatureScheme)}`
				}]
			});
		} else if (best) add({
			id: "auth.proof",
			layer: "server-authentication",
			kind: "undetermined",
			tone: "neutral",
			title: "The scanner did not see the server prove it holds the certificate key",
			detail: "With RSA key transport the proof is implicit: the server shows it can decrypt the client’s secret. The scanner stops before that step."
		});
		const sigOnly = seen.probes.find((p) => p.id === "classical-sig-client");
		const leaves = [
			{
				probe: main,
				offering: "Handshake offering ML-DSA signatures"
			},
			{
				probe: classicalClient,
				offering: "Handshake offering classical signatures only"
			},
			{
				probe: sigOnly,
				offering: "Handshake with post-quantum key exchange offering classical signatures only"
			},
			{
				probe: legacy,
				offering: "TLS 1.2 handshake"
			}
		].flatMap(({ probe, offering }) => probe?.leafFingerprint ? [{
			offering,
			fingerprint: probe.leafFingerprint,
			key: probe.leafKey
		}] : []);
		const recognised = (key) => key !== void 0 && key.family !== "unknown";
		const keyName = (key) => recognised(key) ? key.algorithm : "a key type the scanner does not recognise";
		const differ = new Set(leaves.map((l) => l.fingerprint)).size > 1;
		const offeredMlDsa = main?.leafKey;
		/** A classical certificate that a handshake without ML-DSA received. While clients accept one, it can be forged. */
		const classicalVariant = [
			classicalClient?.leafKey,
			sigOnly?.leafKey,
			legacy?.leafKey
		].find((key) => recognised(key) && !key.quantumSafe);
		const choseByOffer = differ && classicalVariant !== void 0 && recognised(offeredMlDsa) && offeredMlDsa.quantumSafe;
		if (differ) {
			const kinds = [...new Set(leaves.map((l) => keyName(l.key)))];
			const keysSentence = !leaves.every((l) => recognised(l.key)) ? "" : kinds.length === 1 ? `They carry the same kind of key (${kinds[0]}). ` : `Their keys are ${list(kinds)}. `;
			add({
				id: "auth.variant",
				layer: "server-authentication",
				kind: "observation",
				tone: "neutral",
				title: choseByOffer ? "The scanner’s handshakes received certificates of different kinds" : "The scanner’s handshakes received different certificates",
				detail: choseByOffer ? `The certificate sent to the handshake that offered ML-DSA signature schemes has a different kind of key (${offeredMlDsa.algorithm}) from the one sent to a handshake that offered only classical schemes (${classicalVariant.algorithm}). That is what a server holding both, and choosing by what the client offers, looks like. This report’s certificate details describe the first.` : `${keysSentence}A service run on several machines behind one address can hand out different certificates for the same name, so this alone does not show that the server chooses by what the client offers. This report’s certificate details describe the certificate from the first handshake that received one.`,
				evidence: leaves.map((l) => ({
					label: l.offering,
					value: `${keyName(l.key)}, leaf SHA-256 ${l.fingerprint.slice(0, 16)}…`
				}))
			});
		}
		if (seen.trust.checked) add({
			id: "auth.trust",
			layer: "server-authentication",
			kind: "observation",
			tone: seen.trust.trusted ? "good" : seen.lab ? "neutral" : "bad",
			title: seen.trust.trusted ? "The certificate chain is publicly trusted and matches the host name" : `The certificate chain is not trusted: ${seen.trust.error ?? "unknown reason"}`,
			detail: seen.trust.trusted ? `Validated by OpenSSL against ${seen.trust.store}.` : `Checked by OpenSSL against ${seen.trust.store}.${seen.lab ? " Expected for a lab server: its certificate authority exists only on this machine." : ""}`
		});
		const issued = seen.certificates.filter((c) => !c.selfSigned);
		const chainSignatures = (wanted) => [...new Set(issued.filter(wanted).map((c) => c.signature.algorithm))].map((a) => `a chain signature (${a})`);
		const classicalParts = [
			...leaf.key.quantumSafe || leaf.key.family === "unknown" ? [] : [`the certificate key (${leaf.key.algorithm})`],
			...proof && !proof.quantumSafe && leaf.key.quantumSafe ? [`the handshake signature (${proof.name})`] : [],
			...chainSignatures((c) => !c.signature.quantumSafe && c.signature.family !== "unknown")
		];
		const unknownParts = [...leaf.key.family === "unknown" ? [`the certificate key (${leaf.key.algorithm})`] : [], ...chainSignatures((c) => c.signature.family === "unknown")];
		const pqParts = seen.certificates.filter((c) => c.key.quantumSafe || c.signature.quantumSafe).length;
		const basedOn = ["auth.certificate", "auth.proof"].filter((id) => findings.some((f) => f.id === id && f.kind === "observation"));
		if (classicalParts.length > 0) {
			add({
				id: "auth.exposure",
				layer: "server-authentication",
				kind: "inference",
				tone: "caution",
				title: "A quantum computer could impersonate this server, but only at the time of an attack",
				detail: `The server’s identity rests on ${list(classicalParts)}. Shor’s algorithm recovers such private keys from the public keys, which would let an attacker present this identity. Unlike key exchange, this cannot be used on recorded traffic: the forgery has to be made, with a working quantum computer, during a live connection while the certificate is still valid.${pqParts > 0 ? " Part of the chain is already post-quantum, but a chain is as strong as its weakest signature." : ""}${unknownParts.length > 0 ? ` The chain also includes ${list(unknownParts)}, which the scanner does not recognise.` : ""} A public site cannot change this alone: it needs a certificate authority that browsers trust to issue post-quantum certificates, and the exposure lasts while browsers also accept classical ones.`,
				basedOn,
				learn: {
					view: "login",
					landmark: "forgery",
					mode: "classical",
					attacker: "quantum"
				}
			});
			layer("server-authentication", "TLS server authentication", `Classical: ${leaf.key.algorithm} certificate`, "forgery-once-quantum", "caution");
		} else if (classicalVariant) {
			add({
				id: "auth.exposure",
				layer: "server-authentication",
				kind: "inference",
				tone: "caution",
				title: "A quantum computer could still impersonate this server to clients that accept its classical certificate",
				detail: `The chain this report describes ${unknownParts.length === 0 ? "is post-quantum throughout" : "has no classical part the scanner recognises"}, but a handshake that did not offer ML-DSA signatures received a certificate with a classical key (${classicalVariant.algorithm}). While clients accept a classical certificate for this name, an attacker who can forge one can present this identity to them. That takes a working quantum computer during a live connection; it cannot be used on recorded traffic.`,
				basedOn: [...basedOn, ...differ ? ["auth.variant"] : []],
				learn: {
					view: "login",
					landmark: "forgery",
					mode: "classical",
					attacker: "quantum"
				}
			});
			layer("server-authentication", "TLS server authentication", leaf.key.quantumSafe ? `Migrating: ${leaf.key.algorithm} and ${classicalVariant.algorithm}` : `Classical: ${classicalVariant.algorithm} certificate, for some clients`, "forgery-once-quantum", "caution");
		} else if (unknownParts.length > 0) {
			add({
				id: "auth.exposure",
				layer: "server-authentication",
				kind: "undetermined",
				tone: "neutral",
				title: "The server’s identity uses an algorithm the scanner does not recognise",
				detail: `The server’s identity rests in part on ${list(unknownParts)}. Without knowing what ${unknownParts.length === 1 ? "that is" : "these are"}, nothing can be said about how it stands against a quantum computer.`
			});
			layer("server-authentication", "TLS server authentication", leaf.key.family === "unknown" ? "Unrecognised certificate key" : `${leaf.key.algorithm} certificate, unrecognised chain signature`, "undetermined", "neutral");
		} else {
			const families = [...new Set(seen.certificates.flatMap((c) => [c.key, c.signature]).filter((part) => part.quantumSafe).map((part) => part.family))];
			add({
				id: "auth.exposure",
				layer: "server-authentication",
				kind: "inference",
				tone: "good",
				title: "No known quantum attack on the certificate chain this server sent",
				detail: `The certificate key and every signature on the chain the server sent are post-quantum (${list(families)}), and no quantum algorithm is known that forges them. That protects clients that accept only such certificates for this name: a client that also accepts a classical certificate could be shown a forged one, and what clients accept is not visible to a scan.`,
				basedOn,
				learn: {
					view: "login",
					landmark: "forgery",
					mode: "pq",
					attacker: "quantum"
				}
			});
			layer("server-authentication", "TLS server authentication", `Post-quantum: ${leaf.key.algorithm}`, "no-known-attack", "good");
		}
	}
	assessRecordProtection();
	function assessRecordProtection() {
		const suite = best?.cipherSuite === void 0 ? void 0 : CIPHER_SUITES[best.cipherSuite];
		if (!best || !suite) {
			add({
				id: "cipher.undetermined",
				layer: "record-protection",
				kind: "undetermined",
				tone: "neutral",
				title: "The cipher could not be determined",
				detail: best ? `The server chose cipher suite ${hex(best.cipherSuite ?? 0)}, which is not in the scanner’s registry.` : "No handshake was completed."
			});
			return layer("record-protection", "Encryption of the data itself", "Could not determine", "undetermined", "neutral");
		}
		add({
			id: "cipher.negotiated",
			layer: "record-protection",
			kind: "observation",
			tone: suite.aead ? "neutral" : "caution",
			title: `Data is encrypted with ${suite.cipher}${suite.aead ? "" : ", an older non-AEAD construction"}`,
			detail: `Cipher suite ${suite.name}. The key for it comes out of the key exchange above; the cipher itself uses no public-key cryptography.`,
			evidence: [{
				label: "Cipher suite",
				value: `${hex(suite.id)} ${suite.name}`
			}],
			learn: {
				view: "login",
				landmark: "authentication",
				mode: "classical"
			}
		});
		const strong = suite.keyBits >= 256;
		add({
			id: "cipher.exposure",
			layer: "record-protection",
			kind: "inference",
			tone: strong ? "good" : "neutral",
			title: strong ? "The cipher is not at risk from a quantum computer" : `A ${suite.keyBits}-bit key keeps a reduced margin against a quantum computer`,
			detail: strong ? "Quantum computers do not break symmetric ciphers. Grover’s algorithm at best halves the effective key length, which leaves a 256-bit key with about 128 bits of security." : `Quantum computers do not break symmetric ciphers. Grover’s algorithm could in theory search a ${suite.keyBits}-bit key in about 2^${suite.keyBits / 2} steps, but the steps cannot be spread across machines the way a classical search can, and NIST treats AES-128 as its baseline security category. Guidance that plans decades ahead, such as CNSA 2.0, asks for AES-256.`,
			basedOn: ["cipher.negotiated"]
		});
		layer("record-protection", "Encryption of the data itself", suite.cipher, "reduced-margin", strong ? "good" : "neutral");
	}
	assessTransport();
	function assessTransport() {
		const { transport } = seen;
		const first = transport.hops[0];
		if (!first || first.status === void 0) {
			add({
				id: "http.undetermined",
				layer: "transport-policy",
				kind: "undetermined",
				tone: "neutral",
				title: "The page could not be fetched over HTTPS",
				detail: first?.error ?? "No HTTP request was made."
			});
			return layer("transport-policy", "Is HTTPS enforced?", "Could not determine", "not-applicable", "neutral");
		}
		if (transport.hops.length > 1 || transport.blockedRedirect) add({
			id: "http.redirects",
			layer: "transport-policy",
			kind: "observation",
			tone: "neutral",
			title: transport.blockedRedirect ? "The page redirects somewhere the scanner will not go" : `The page redirects ${transport.hops.length - 1} time${transport.hops.length === 2 ? "" : "s"}`,
			detail: transport.blockedRedirect ? `Not followed: ${transport.blockedRedirect.reason}` : "Each hop was checked against the scanner’s target rules before it was followed.",
			evidence: [...transport.hops.map((hop, i) => ({
				label: `Hop ${i + 1}`,
				value: `${hop.url} → ${hop.status ?? hop.error}${hop.location ? ` → ${hop.location}` : ""}`
			})), ...transport.blockedRedirect ? [{
				label: "Refused",
				value: `${transport.blockedRedirect.location} (${transport.blockedRedirect.code})`
			}] : []]
		});
		const { hsts, plainHttp } = transport;
		const days = hsts?.maxAge === void 0 ? void 0 : Math.floor(hsts.maxAge / 86400);
		const hstsUseful = hsts !== void 0 && (hsts.maxAge ?? 0) > 0;
		add({
			id: "http.hsts",
			layer: "transport-policy",
			kind: "observation",
			tone: hstsUseful ? "good" : "caution",
			title: hstsUseful ? `HSTS tells browsers to use HTTPS only, for ${days} day${days === 1 ? "" : "s"}` : hsts ? "HSTS is present but switched off (max-age=0)" : "No HSTS header",
			detail: hstsUseful ? "A browser that has seen this header refuses to talk to the site over plain HTTP until it expires." : "Without Strict-Transport-Security a browser will use plain HTTP if a link or an attacker sends it there.",
			evidence: hsts ? [{
				label: "Strict-Transport-Security",
				value: hsts.raw
			}] : [{
				label: "Response headers",
				value: "no Strict-Transport-Security header"
			}]
		});
		if (plainHttp) {
			const served = plainHttp.status !== void 0 && !plainHttp.upgradesToHttps;
			add({
				id: "http.plain",
				layer: "transport-policy",
				kind: "observation",
				tone: plainHttp.upgradesToHttps ? "good" : served ? "caution" : "neutral",
				title: plainHttp.upgradesToHttps ? "Plain HTTP redirects to HTTPS" : served ? `Plain HTTP answers with ${plainHttp.status} instead of redirecting to HTTPS` : "Plain HTTP is not answered",
				detail: plainHttp.upgradesToHttps ? "A request to port 80 is sent to the HTTPS site." : served ? "A request to port 80 is answered without being sent to HTTPS." : "Port 80 gave no HTTP answer, so there is no plain-HTTP site to fall back to.",
				evidence: [{
					label: "GET http://…:80/",
					value: plainHttp.error ?? `${plainHttp.status}${plainHttp.location ? ` → ${plainHttp.location}` : ""}`
				}]
			});
		}
		const insecure = transport.cookies.filter((c) => !c.secure);
		if (transport.cookies.length > 0) add({
			id: "http.cookies",
			layer: "transport-policy",
			kind: "observation",
			tone: insecure.length > 0 ? "caution" : "good",
			title: insecure.length > 0 ? `Cookie ${list(insecure.map((c) => c.name))} can be sent over plain HTTP` : `Cookies set by this page are restricted to HTTPS`,
			detail: insecure.length > 0 ? "A cookie without the Secure attribute is sent on plain-HTTP requests too, where anyone on the network path can read it. Whether that matters depends on what the cookie is for, which a scan cannot tell: for a session cookie it means the session can be stolen." : "Every cookie has the Secure attribute.",
			evidence: transport.cookies.map((c) => ({
				label: c.name,
				value: [
					c.secure ? "Secure" : "not Secure",
					c.httpOnly ? "HttpOnly" : "readable by scripts",
					c.sameSite ? `SameSite=${c.sameSite}` : "no SameSite"
				].join(", ")
			}))
		});
		if (!hstsUseful) add({
			id: "http.exposure",
			layer: "transport-policy",
			kind: "inference",
			tone: "caution",
			title: "An attacker on the network can keep a first-time visitor off HTTPS",
			detail: "With no HSTS, a browser that is sent to the plain-HTTP address makes that request in the clear. An attacker on the path can answer it and never let the TLS handshake happen. The strength of the key exchange is irrelevant to a connection that was never encrypted. This is a classical attack, not a quantum one.",
			basedOn: ["http.hsts", ...plainHttp ? ["http.plain"] : []]
		});
		layer("transport-policy", "Is HTTPS enforced?", hstsUseful ? "HSTS set" : "No HSTS", "not-applicable", hstsUseful && insecure.length === 0 ? "good" : "caution");
	}
	assessTokenSigning();
	function assessTokenSigning() {
		const { oidc } = seen;
		if (!oidc.found) {
			add({
				id: "token.undetermined",
				layer: "token-signing",
				kind: "undetermined",
				tone: "neutral",
				title: "Unable to determine the application-level token signing algorithm",
				detail: "No OpenID Connect or OAuth metadata is published at this address. A service can issue signed tokens without saying how; from outside that is only visible in a token itself. If this system gives you a token, paste it into the token analyzer.",
				evidence: oidc.tried.map((t) => ({
					label: t.url,
					value: t.result
				})),
				learn: { view: "token" }
			});
			return layer("token-signing", "Application token signing", "Could not determine", "undetermined", "neutral");
		}
		const algs = oidc.idTokenAlgs ?? [];
		add({
			id: "token.metadata",
			layer: "token-signing",
			kind: "observation",
			tone: algs.some((a) => a.toLowerCase() === "none") ? "bad" : "neutral",
			title: algs.length > 0 ? `Sign-in tokens are signed with ${list(algs)}` : "OpenID Connect metadata is published, without a list of signing algorithms",
			detail: `Read from the service’s own metadata. This is the application’s signature on a token, separate from anything TLS does.${algs.some((a) => a.toLowerCase() === "none") ? " The list includes \"none\": unsigned tokens." : ""}`,
			evidence: [
				{
					label: "Metadata",
					value: oidc.discoveryUrl ?? ""
				},
				{
					label: "issuer",
					value: `${oidc.issuer}${oidc.issuerMatches ? "" : " (does not match the URL it was served from)"}`
				},
				{
					label: "id_token_signing_alg_values_supported",
					value: algs.join(", ") || "(absent)"
				}
			],
			learn: {
				view: "login",
				landmark: "success",
				mode: "classical"
			}
		});
		/** Without keys to read, the algorithms the service lists are all there is to go on. True when every one is a classical signature. */
		const classicalByMetadata = () => {
			const signed = algs.filter((a) => a.toLowerCase() !== "none");
			if (signed.length === 0 || !signed.every((a) => CLASSICAL_JWS.test(a))) return false;
			add({
				id: "token.exposure",
				layer: "token-signing",
				kind: "inference",
				tone: "caution",
				title: "A quantum computer could forge this service’s tokens once it exists",
				detail: `The service’s metadata says it signs tokens with ${list(signed)}, which Shor’s algorithm breaks. No signing keys could be read, so this rests on the metadata alone.`,
				basedOn: ["token.metadata"],
				learn: {
					view: "login",
					landmark: "forgery",
					mode: "classical",
					attacker: "quantum"
				}
			});
			layer("token-signing", "Application token signing", `Classical: ${list(signed)}`, "forgery-once-quantum", "caution");
			return true;
		};
		if (!oidc.keys) {
			add({
				id: "token.keys",
				layer: "token-signing",
				kind: "undetermined",
				tone: "neutral",
				title: "The signing keys could not be read",
				detail: oidc.jwksError ?? "The key set was not available.",
				evidence: oidc.jwksUri ? [{
					label: "jwks_uri",
					value: oidc.jwksUri
				}] : void 0
			});
			if (classicalByMetadata()) return;
			return layer("token-signing", "Application token signing", algs.join(", ") || "Metadata without keys", "undetermined", "neutral");
		}
		const kindsOf = (keys) => [...new Set(keys.map((k) => k.strength))];
		const kinds = kindsOf(oidc.keys);
		const safe = oidc.keys.filter((k) => k.quantumSafe);
		const classical = oidc.keys.filter((k) => !k.quantumSafe && [
			"RSA",
			"EC",
			"OKP"
		].includes(k.kty));
		const unrecognised = oidc.keys.filter((k) => !k.quantumSafe && ![
			"RSA",
			"EC",
			"OKP"
		].includes(k.kty));
		add({
			id: "token.keys",
			layer: "token-signing",
			kind: "observation",
			tone: safe.length === oidc.keys.length && safe.length > 0 ? "good" : "neutral",
			title: `Signing keys published: ${list(kinds) || "none"}`,
			detail: `${oidc.keys.length} key${oidc.keys.length === 1 ? "" : "s"} in the key set that apps use to check tokens.`,
			evidence: [{
				label: "jwks_uri",
				value: oidc.jwksUri ?? ""
			}, ...oidc.keys.map((k) => ({
				label: k.kid ?? "(no kid)",
				value: `${k.strength}${k.alg ? `, alg ${k.alg}` : ""}`
			}))]
		});
		const basedOn = ["token.metadata", "token.keys"];
		if (oidc.keys.length === 0) {
			if (!classicalByMetadata()) layer("token-signing", "Application token signing", "No signing keys published", "undetermined", "neutral");
		} else if (classical.length === 0 && unrecognised.length > 0) {
			const which = kindsOf(unrecognised);
			add({
				id: "token.exposure",
				layer: "token-signing",
				kind: "undetermined",
				tone: "neutral",
				title: "The signing keys include a type the scanner does not recognise",
				detail: `The key set has ${list(which)}. Without knowing what ${which.length === 1 ? "that is" : "these are"}, nothing can be said about how tokens signed with ${which.length === 1 ? "it" : "them"} stand against a quantum computer.`
			});
			layer("token-signing", "Application token signing", "Signing keys not recognised", "undetermined", "neutral");
		} else if (safe.length === oidc.keys.length) {
			add({
				id: "token.exposure",
				layer: "token-signing",
				kind: "inference",
				tone: "good",
				title: "No known quantum attack forges this service’s tokens",
				detail: `Every published signing key is post-quantum (${list(kinds)}). Apps check token signatures against these keys, so a signature made with any other public-key algorithm is refused by an app that verifies correctly.`,
				basedOn,
				learn: {
					view: "login",
					landmark: "forgery",
					mode: "pq",
					attacker: "quantum"
				}
			});
			layer("token-signing", "Application token signing", `Post-quantum: ${list(kinds)}`, "no-known-attack", "good");
		} else {
			const mixed = safe.length > 0;
			add({
				id: "token.exposure",
				layer: "token-signing",
				kind: "inference",
				tone: "caution",
				title: mixed ? "Tokens signed with the classical key could be forged once a quantum computer exists" : "A quantum computer could forge this service’s tokens once it exists",
				detail: `${mixed ? "The service publishes a post-quantum key next to a classical one, which is what a migration in progress looks like. Apps still receiving classically signed tokens remain exposed. " : ""}Shor’s algorithm recovers an RSA or elliptic-curve private key from the published public key; with it an attacker can sign a token for any user. A forged signature cannot be applied to the past, so there is nothing to record and attack later: the risk begins when such a computer exists.${unrecognised.length > 0 ? ` The key set also has ${list(kindsOf(unrecognised))}, which the scanner does not recognise.` : ""}`,
				basedOn,
				learn: {
					view: "login",
					landmark: "forgery",
					mode: "classical",
					attacker: "quantum"
				}
			});
			layer("token-signing", "Application token signing", mixed ? `Migrating: ${list(kindsOf([...safe, ...classical]))}` : `Classical: ${list(kindsOf(classical))}`, "forgery-once-quantum", "caution");
		}
	}
	if (seen.related.length > 0) add({
		id: "deps.related",
		layer: "dependencies",
		kind: "observation",
		tone: "neutral",
		title: `This sign-in also depends on ${seen.related.length} other origin${seen.related.length === 1 ? "" : "s"}`,
		detail: "They were not scanned. Each has its own TLS configuration and keys, and the sign-in is only as strong as the weakest of them.",
		evidence: seen.related.map((r) => ({
			label: r.origin,
			value: r.role
		}))
	});
	add({
		id: "deps.internal",
		layer: "dependencies",
		kind: "undetermined",
		tone: "neutral",
		title: "Internal dependencies cannot be observed from outside",
		detail: "Connections between your own services, databases, key storage, vendor APIs and the devices your users connect from all use cryptography too. None of it is visible to an external scan. Finding it is the first step of a migration."
	});
	layer("dependencies", "Dependencies", seen.related.length > 0 ? `${seen.related.length} related origin${seen.related.length === 1 ? "" : "s"} found; internal ones not observable` : "Internal dependencies not observable", "undetermined", "neutral");
	return {
		layers,
		findings
	};
}
/** JOSE signature algorithms built on RSA or elliptic curves, which Shor’s algorithm breaks: the names token-kit’s jose.ts classifies that way. */
const CLASSICAL_JWS = /^(?:RS|PS|ES)(?:256|384|512)$|^ES256K$|^EdDSA$|^Ed(?:25519|448)$/;
const LAYER_NAMES = [
	["key-establishment", "TLS key establishment"],
	["server-authentication", "TLS server authentication"],
	["record-protection", "Encryption of the data itself"],
	["transport-policy", "Is HTTPS enforced?"],
	["token-signing", "Application token signing"],
	["dependencies", "Dependencies"]
];
//#endregion
//#region packages/scan-core/src/net/connect.ts
/** A network failure in a form the report can show. */
var ConnectError = class extends Error {
	code;
	constructor(code, message) {
		super(message);
		this.name = "ConnectError";
		this.code = code;
	}
};
/**
* Opens a TCP connection to the pinned address. `host` is always an IP
* literal, so Node never performs a DNS lookup here; the `lookup` override
* turns any future mistake into an error instead of a second resolution.
*/
function connectPinned(pinned, timeoutMs) {
	if (net.isIP(pinned.address) === 0) return Promise.reject(new ConnectError("not-pinned", "Refusing to connect: the target is not pinned to an IP address."));
	return new Promise((resolve, reject) => {
		const socket = net.connect({
			host: pinned.address,
			port: pinned.port,
			family: pinned.family,
			lookup: () => {
				throw new ConnectError("not-pinned", "Unexpected DNS lookup for a pinned target.");
			}
		});
		socket.setNoDelay(true);
		const timer = setTimeout(() => {
			socket.destroy();
			reject(new ConnectError("connect-timeout", `No answer from ${pinned.address}:${pinned.port} within ${timeoutMs} ms.`));
		}, timeoutMs);
		socket.once("connect", () => {
			clearTimeout(timer);
			resolve(socket);
		});
		socket.once("error", (error) => {
			clearTimeout(timer);
			reject(new ConnectError(error.code ?? "connect-failed", describe(error, pinned)));
		});
	});
}
function describe(error, pinned) {
	const where = `${pinned.address}:${pinned.port}`;
	switch (error.code) {
		case "ECONNREFUSED": return `${where} refused the connection.`;
		case "ECONNRESET": return `${where} reset the connection.`;
		case "EHOSTUNREACH":
		case "ENETUNREACH": return `${where} is unreachable from here.`;
		default: return `Could not connect to ${where}: ${error.message}`;
	}
}
//#endregion
//#region packages/scan-core/src/http/fetch.ts
/**
* HTTP GET for the scanner. Every request goes to a pinned address (ADR 0007):
* the host name is used for SNI and the Host header only. Redirects are never
* followed by the HTTP client; each Location is parsed, checked and resolved
* again as if a user had typed it.
*
* TLS here is Node's (OpenSSL). The certificate is not required to be valid,
* because a scanner wants to look at broken sites too, but whether it
* validated is recorded. No credentials, cookies or request bodies are sent.
*/
const USER_AGENT = "pq-oidc-scanner/1.0 (+https://github.com/probablyliam/pq-oidc)";
/** Every group Node's OpenSSL can negotiate, so this connection succeeds wherever one of the scanner's own handshakes did. */
const NODE_TLS_GROUPS = "X25519MLKEM768:X25519:P-256:P-384:SecP256r1MLKEM768:SecP384r1MLKEM1024:MLKEM768:MLKEM1024";
/** A request that did not produce an HTTP response. */
var FetchError = class extends Error {
	code;
	constructor(code, message) {
		super(message);
		this.name = "FetchError";
		this.code = code;
	}
};
function fetchPinned(url, pinned, options = {}) {
	const timeoutMs = Math.min(options.timeoutMs ?? 8e3, (options.deadline ?? Infinity) - Date.now());
	const maxBytes = options.maxBytes ?? 65536;
	const secure = url.protocol === "https:";
	if (timeoutMs <= 0) return Promise.reject(new FetchError("timeout", "The scan ran out of time before this request."));
	return new Promise((resolve, reject) => {
		const request = (secure ? https : http).request({
			host: pinned.address,
			family: pinned.family,
			port: pinned.port,
			servername: secure && pinned.hasHostname ? pinned.hostname : void 0,
			path: `${url.pathname}${url.search}`,
			method: "GET",
			headers: {
				host: url.host,
				"user-agent": USER_AGENT,
				accept: "text/html,application/json;q=0.9,*/*;q=0.5",
				"accept-encoding": "identity",
				connection: "close"
			},
			agent: false,
			rejectUnauthorized: false,
			ecdhCurve: NODE_TLS_GROUPS,
			lookup: () => {
				throw new ConnectError("not-pinned", "Unexpected DNS lookup for a pinned target.");
			}
		});
		let settled = false;
		const fail = (code, message) => {
			if (settled) return;
			settled = true;
			clearTimeout(deadline);
			request.destroy();
			reject(new FetchError(code, message));
		};
		const deadline = setTimeout(() => fail("timeout", `No complete response from ${url.host} within ${timeoutMs} ms.`), timeoutMs);
		request.on("error", (error) => fail(error.code ?? "network", `Request to ${url.host} failed: ${error.message}`));
		request.on("response", (response) => {
			const socket = response.socket;
			const tls = secure ? {
				authorized: socket.authorized,
				authorizationError: socket.authorizationError ? String(socket.authorizationError) : void 0
			} : void 0;
			const chunks = [];
			let size = 0;
			const done = (truncated) => {
				if (settled) return;
				settled = true;
				clearTimeout(deadline);
				request.destroy();
				resolve({
					url: url.href,
					status: response.statusCode ?? 0,
					headers: response.headers,
					body: Buffer.concat(chunks),
					truncated,
					tls
				});
			};
			response.on("data", (chunk) => {
				const room = maxBytes - size;
				if (chunk.length >= room) {
					chunks.push(chunk.subarray(0, room));
					size = maxBytes;
					done(true);
				} else {
					chunks.push(chunk);
					size += chunk.length;
				}
			});
			response.on("end", () => done(false));
			response.on("error", (error) => fail("network", `Reading from ${url.host} failed: ${error.message}`));
		});
		request.end();
	});
}
const REDIRECTS = /* @__PURE__ */ new Set([
	301,
	302,
	303,
	307,
	308
]);
/**
* GETs `start` and follows redirects by hand. A redirect to a new origin is
* treated exactly like a new target: parsed against the policy, resolved once,
* every address checked, then pinned. Anything refused ends the chain and is
* reported, never fetched.
*/
async function fetchFollowingRedirects(start, startPinned, policy, options = {}) {
	const maxRedirects = options.maxRedirects ?? 5;
	const pins = /* @__PURE__ */ new Map([[start.origin, startPinned]]);
	const result = {
		hops: [],
		responses: []
	};
	let target = start;
	for (let hop = 0;; hop++) {
		const pinned = pins.get(target.origin);
		let response;
		try {
			response = await fetchPinned(target.url, pinned, options);
		} catch (error) {
			if (!(error instanceof FetchError)) throw error;
			result.hops.push({
				url: target.url.href,
				error: error.message
			});
			return result;
		}
		result.responses.push({
			target,
			pinned,
			response
		});
		const location = REDIRECTS.has(response.status) ? response.headers.location : void 0;
		result.hops.push({
			url: target.url.href,
			status: response.status,
			location
		});
		if (!location) return result;
		if (hop >= maxRedirects) {
			result.blockedRedirect = {
				location,
				code: "too-many-redirects",
				reason: `Stopped after ${maxRedirects} redirects.`
			};
			return result;
		}
		try {
			const next = parseTarget(new URL(location, target.url).href, policy);
			if (!pins.has(next.origin)) pins.set(next.origin, await resolveTarget(next, { lookup: options.lookup }));
			target = next;
		} catch (error) {
			if (!(error instanceof TargetRejected) && !(error instanceof TypeError)) throw error;
			result.blockedRedirect = {
				location,
				code: error instanceof TargetRejected ? error.code : "invalid-url",
				reason: error.message
			};
			return result;
		}
	}
}
//#endregion
//#region packages/scan-core/src/http/page.ts
/** The first password input in an HTML document, as written there, or undefined. */
function findPasswordField(html) {
	for (const [tag] of html.matchAll(/<input\b[^>]*>/gi)) if (/\btype\s*=\s*["']?password["'\s/>]/i.test(tag) || /\bautocomplete\s*=\s*["'][^"']*\b(?:current|new)-password\b/i.test(tag)) return tag.slice(0, 160);
}
/** The first visible username, login or email input: the first step of a two-step sign-in. */
function findUsernameField(html) {
	for (const [tag] of html.matchAll(/<input\b[^>]*>/gi)) {
		if (/\btype\s*=\s*["']?hidden\b/i.test(tag)) continue;
		if (/\bautocomplete\s*=\s*["'][^"']*\busername\b/i.test(tag) || /\btype\s*=\s*["']?email\b/i.test(tag) || /\bname\s*=\s*["']?(?:username|user|login|loginfmt|identifier|email)\b/i.test(tag)) return tag.slice(0, 160);
	}
}
const ENTITIES = {
	amp: "&",
	lt: "<",
	gt: ">",
	quot: "\"",
	"#39": "'",
	"#x27": "'"
};
/** The usual places a sign-in lives, tried in this order when a page does not link to one. */
const SIGN_IN_PATHS = [
	"/login",
	"/signin",
	"/sign-in",
	"/account/login",
	"/auth/login",
	"/users/sign_in"
];
/**
* Links on a page that lead to a sign-in, best first: one that says "sign in"
* or "log in" outranks one whose address merely looks like it. Only https
* links are returned, resolved against the page's address; whoever follows
* them puts each through the policy first.
*/
function findSignInLinks(html, base, limit = 3) {
	const scored = /* @__PURE__ */ new Map();
	for (const [, attrs = "", inner = ""] of html.matchAll(/<a\b([^>]*)>([\s\S]{0,2000}?)<\/a>/gi)) {
		const href = /\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs);
		const raw = (href?.[1] ?? href?.[2] ?? href?.[3] ?? "").trim().replace(/&(amp|lt|gt|quot|#39|#x27);/g, (_, e) => ENTITIES[e] ?? _);
		if (!raw || /^(?:javascript|mailto|tel):|^#/i.test(raw)) continue;
		let url;
		try {
			url = new URL(raw, base);
		} catch {
			continue;
		}
		if (url.protocol !== "https:") continue;
		url.hash = "";
		const label = `${inner.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim()} ${/\baria-label\s*=\s*"([^"]*)"/i.exec(attrs)?.[1] ?? ""} ${/\btitle\s*=\s*"([^"]*)"/i.exec(attrs)?.[1] ?? ""}`;
		const byText = /\b(?:sign|log)\s?-?in\b/i.test(label) ? 2 : /\b(?:my )?account\b/i.test(label) ? 1 : 0;
		const byPath = /(?:^|\/)(?:sign-?in|log-?in|login|auth|account)(?:\/|$)/i.test(url.pathname) ? 1 : 0;
		if (byText + byPath === 0) continue;
		const score = byText * 2 + byPath;
		scored.set(url.href, Math.max(scored.get(url.href) ?? 0, score));
	}
	return [...scored.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit).map(([href]) => href);
}
/** A path that is a sign-in endpoint by convention: OAuth's authorize endpoint, or the usual names. */
function signInPath(url) {
	return /(?:^|\/)(?:authorize|signin|sign-in|login|log-in|sso|saml2?)(?:\/|$)/i.test(url.pathname) ? url.pathname : void 0;
}
function summarizePage(follow, targetOrigin, oidc) {
	const last = follow.responses.at(-1);
	const leadsTo = last && last.target.origin !== targetOrigin ? last.target.origin : void 0;
	const contentType = String(last?.response.headers["content-type"] ?? "");
	const html = last && /html/i.test(contentType) ? last.response.body.toString("utf8") : "";
	const password = findPasswordField(html);
	const username = password ? void 0 : findUsernameField(html);
	const path = last ? signInPath(new URL(last.response.url)) : void 0;
	const metadataAt = oidc.found && oidc.discoveryUrl ? new URL(oidc.discoveryUrl).origin : void 0;
	const evidence = [];
	if (last) {
		const size = html ? `${last.response.body.length.toLocaleString("en-US")} bytes of HTML${last.response.truncated ? ", cut short" : ""}` : contentType || "no content type";
		evidence.push({
			label: "Page read",
			value: `${last.response.url} (${last.response.status}, ${size})`
		});
	}
	if (metadataAt) evidence.push({
		label: "OpenID Connect metadata",
		value: oidc.discoveryUrl
	});
	if (password) evidence.push({
		label: "Password field",
		value: password
	});
	if (username) evidence.push({
		label: "Username field",
		value: username
	});
	if (path) evidence.push({
		label: "Sign-in address",
		value: path
	});
	const how = password ? "password-field" : username ? "username-field" : path ? "address" : void 0;
	if (metadataAt === targetOrigin) return {
		kind: "sign-in-service",
		how: "metadata",
		evidence
	};
	if (how && !leadsTo) return {
		kind: "sign-in-page",
		how,
		evidence
	};
	if (leadsTo && (how || metadataAt === leadsTo)) return {
		kind: "leads-to-sign-in",
		how: metadataAt === leadsTo ? "metadata" : how,
		leadsTo,
		evidence
	};
	return {
		kind: "other",
		leadsTo,
		evidence
	};
}
//#endregion
//#region packages/scan-core/src/http/transport.ts
/**
* The HTTP-level facts that decide whether the TLS underneath is actually
* used: does the site force HTTPS, and are its cookies restricted to it?
* A strong key exchange protects nothing for a visitor who was left on HTTP.
*
* Deliberately not a header linter: CSP, framing and the rest are application
* security, not cryptographic posture.
*/
function parseHsts(value) {
	const directives = value.split(";").map((d) => d.trim().toLowerCase());
	const maxAge = directives.map((d) => /^max-age\s*=\s*"?(\d+)"?$/.exec(d)?.[1]).find(Boolean);
	return {
		raw: value,
		maxAge: maxAge === void 0 ? void 0 : Number(maxAge),
		includeSubDomains: directives.includes("includesubdomains"),
		preload: directives.includes("preload")
	};
}
/** Name and flags only. Cookie values are never kept: they may be someone's session. */
function parseSetCookie(header) {
	const [pair = "", ...attributes] = header.split(";");
	const flags = attributes.map((a) => a.trim().toLowerCase());
	return {
		name: pair.slice(0, Math.max(0, pair.indexOf("="))).trim() || "(unnamed)",
		secure: flags.includes("secure"),
		httpOnly: flags.includes("httponly"),
		sameSite: flags.find((f) => f.startsWith("samesite="))?.slice(9)
	};
}
function summarizeTransport(follow, targetOrigin, plainHttp) {
	const own = follow.responses.filter((r) => r.target.origin === targetOrigin).map((r) => r.response);
	const hstsHeader = own.map((r) => r.headers["strict-transport-security"]).find((h) => typeof h === "string");
	const cookies = /* @__PURE__ */ new Map();
	for (const response of own) for (const header of response.headers["set-cookie"] ?? []) {
		const cookie = parseSetCookie(header);
		cookies.set(cookie.name, cookie);
	}
	const server = own[0]?.headers.server;
	return {
		hops: follow.hops,
		blockedRedirect: follow.blockedRedirect,
		hsts: hstsHeader ? parseHsts(hstsHeader) : void 0,
		cookies: [...cookies.values()],
		plainHttp,
		serverHeader: typeof server === "string" ? server.slice(0, 120) : void 0
	};
}
/**
* Asks port 80 on the already-validated address what it does with plain HTTP.
* The request line and headers are fixed; only the status line and Location
* header of the answer are read.
*/
function checkPlainHttp(pinned, timeoutMs = 4e3) {
	return new Promise((resolve) => {
		const socket = net.connect({
			host: pinned.address,
			family: pinned.family,
			port: 80
		});
		let data = "";
		const finish = (result) => {
			clearTimeout(timer);
			socket.destroy();
			resolve(result);
		};
		const timer = setTimeout(() => finish({
			upgradesToHttps: false,
			error: "no answer on port 80"
		}), timeoutMs);
		socket.on("error", (error) => finish({
			upgradesToHttps: false,
			error: error.code === "ECONNREFUSED" ? "port 80 is closed" : `port 80: ${error.message}`
		}));
		socket.on("connect", () => {
			const host = pinned.family === 6 && !pinned.hasHostname ? `[${pinned.hostname}]` : pinned.hostname;
			socket.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: ${USER_AGENT}\r\nAccept: */*\r\nConnection: close\r\n\r\n`);
		});
		const parse = () => {
			const head = data.split("\r\n\r\n")[0] ?? "";
			const status = Number(/^HTTP\/1\.[01] (\d{3})/.exec(head)?.[1]);
			if (!status) return finish({
				upgradesToHttps: false,
				error: "port 80 did not answer with HTTP"
			});
			const location = /^location:\s*(.+)$/im.exec(head)?.[1]?.trim();
			finish({
				status,
				location,
				upgradesToHttps: status >= 300 && status < 400 && Boolean(location?.toLowerCase().startsWith("https://"))
			});
		};
		socket.on("data", (chunk) => {
			data += chunk.toString("latin1");
			if (data.includes("\r\n\r\n") || data.length > 16384) parse();
		});
		socket.on("end", parse);
	});
}
//#endregion
//#region packages/token-kit/src/algorithms.ts
const ALGORITHMS = {
	ES256: {
		alg: "ES256",
		scheme: "ECDSA with P-256 and SHA-256",
		standard: "FIPS 186-5 / RFC 7518",
		signatureBytes: 64,
		publicKeyBytes: 64,
		quantumSafe: false,
		nistCategory: null
	},
	RS256: {
		alg: "RS256",
		scheme: "RSASSA-PKCS1-v1_5 (2048-bit) with SHA-256",
		standard: "RFC 8017 / RFC 7518",
		signatureBytes: 256,
		publicKeyBytes: 256,
		quantumSafe: false,
		nistCategory: null
	},
	"ML-DSA-44": {
		alg: "ML-DSA-44",
		scheme: "Module-Lattice-Based Digital Signature Algorithm, parameter set 44",
		standard: "FIPS 204 / RFC 9964",
		signatureBytes: 2420,
		publicKeyBytes: 1312,
		quantumSafe: true,
		nistCategory: 2
	},
	"ML-DSA-65": {
		alg: "ML-DSA-65",
		scheme: "Module-Lattice-Based Digital Signature Algorithm, parameter set 65",
		standard: "FIPS 204 / RFC 9964",
		signatureBytes: 3309,
		publicKeyBytes: 1952,
		quantumSafe: true,
		nistCategory: 3
	},
	"ML-DSA-87": {
		alg: "ML-DSA-87",
		scheme: "Module-Lattice-Based Digital Signature Algorithm, parameter set 87",
		standard: "FIPS 204 / RFC 9964",
		signatureBytes: 4627,
		publicKeyBytes: 2592,
		quantumSafe: true,
		nistCategory: 5
	}
};
//#endregion
//#region packages/token-kit/src/limits.ts
/** Length of unpadded base64url for `n` raw bytes. */
function base64urlLength(n) {
	return Math.ceil(n * 4 / 3);
}
//#endregion
//#region packages/token-kit/src/readiness.ts
/**
* Post-quantum readiness report for any OpenID Connect provider, built from its
* public discovery document and JWKS. Pure functions: the browser lab and the
* CLI (scripts/check-issuer.ts) both fetch the documents and call analyzeProvider.
*/
/** Post-quantum signature algorithms with registered or proposed JOSE names. */
function isQuantumSafeAlg(alg) {
	return typeof alg === "string" && /^(ML-DSA|SLH-DSA|FN-DSA)/i.test(alg);
}
/**
* Shared-secret (HMAC) algorithms. Shor's algorithm does not apply to them, so a
* quantum computer can't forge them, but they aren't public-key signatures:
* every app that verifies the token holds the secret and could mint one too.
*/
function isSymmetricAlg(alg) {
	return typeof alg === "string" && /^HS\d+$/.test(alg);
}
/** Public-key signature algorithms that Shor's algorithm breaks (RSA and elliptic curves). */
function isQuantumVulnerableAlg(alg) {
	return typeof alg === "string" && alg.toLowerCase() !== "none" && !isQuantumSafeAlg(alg) && !isSymmetricAlg(alg);
}
const EC_CURVES = {
	"P-256": "P-256",
	"P-384": "P-384",
	"P-521": "P-521"
};
function describeKey$1(jwk) {
	const kty = String(jwk.kty ?? "?");
	const alg = typeof jwk.alg === "string" ? jwk.alg : void 0;
	let strength = kty;
	if (kty === "RSA" && typeof jwk.n === "string") {
		const bytes = Math.floor(jwk.n.replace(/=+$/, "").length * 3 / 4);
		strength = `RSA ${Math.round(bytes * 8 / 256) * 256}-bit`;
	} else if (kty === "EC") strength = EC_CURVES[String(jwk.crv)] ?? `EC ${String(jwk.crv)}`;
	else if (kty === "OKP") strength = String(jwk.crv ?? "OKP");
	else if (kty === "AKP") strength = alg ?? "AKP";
	else if (kty === "oct") strength = "Shared secret";
	return {
		kid: typeof jwk.kid === "string" ? jwk.kid : void 0,
		kty,
		alg,
		use: typeof jwk.use === "string" ? jwk.use : void 0,
		strength,
		quantumSafe: kty === "AKP" && isQuantumSafeAlg(alg),
		jsonBytes: JSON.stringify(jwk).length
	};
}
/** Size of a published ML-DSA-65 JWK: the base64url public key plus {"kty","use","kid" (43-char thumbprint),"alg"} (104 bytes). */
const ML_DSA_65_JWK_BYTES = base64urlLength(ALGORITHMS["ML-DSA-65"].publicKeyBytes) + 104;
function analyzeProvider(discovery, jwks, jwksBytes) {
	const idTokenAlgs = Array.isArray(discovery.id_token_signing_alg_values_supported) ? discovery.id_token_signing_alg_values_supported.map(String) : [];
	const keys = (Array.isArray(jwks.keys) ? jwks.keys : []).map(describeKey$1);
	const signingKeys = keys.filter((k) => k.use !== "enc");
	const pqAlgs = idTokenAlgs.filter(isQuantumSafeAlg);
	const vulnerableAlgs = idTokenAlgs.filter(isQuantumVulnerableAlg);
	const symmetricAlgs = idTokenAlgs.filter(isSymmetricAlg);
	const pqKeys = signingKeys.filter((k) => k.quantumSafe);
	const verdict = pqAlgs.length > 0 && pqKeys.length > 0 ? signingKeys.every((k) => k.quantumSafe) ? "ready" : "partial" : "not-ready";
	const checks = [];
	checks.push(pqAlgs.length > 0 ? {
		id: "pq-algs",
		status: "pass",
		label: "Offers post-quantum ID token signatures",
		detail: pqAlgs.join(", ")
	} : {
		id: "pq-algs",
		status: "fail",
		label: "No post-quantum ID token signatures",
		detail: vulnerableAlgs.length > 0 ? `Its public-key signatures (${vulnerableAlgs.join(", ")}) can be forged with a large quantum computer.${symmetricAlgs.length > 0 ? ` It also lists ${symmetricAlgs.join(", ")}, a shared-secret method that quantum computers don't break but that only works when the app holds the provider's secret.` : ""}` : `Lists ${idTokenAlgs.join(", ") || "no algorithms"}; none is a post-quantum signature.`
	});
	checks.push(pqKeys.length > 0 ? {
		id: "pq-keys",
		status: "pass",
		label: "Publishes post-quantum keys",
		detail: `${pqKeys.length} of ${signingKeys.length} signing keys are post-quantum (${[...new Set(pqKeys.map((k) => k.strength))].join(", ")}).`
	} : {
		id: "pq-keys",
		status: "fail",
		label: "No post-quantum keys in the JWKS",
		detail: `All ${signingKeys.length} signing keys are classical (${[...new Set(signingKeys.map((k) => k.strength))].join(", ")}).`
	});
	if (typeof discovery.authorization_endpoint === "string") {
		const pkce = discovery.code_challenge_methods_supported;
		checks.push(Array.isArray(pkce) && pkce.includes("S256") ? {
			id: "pkce",
			status: "pass",
			label: "Advertises PKCE (S256)",
			detail: "Authorization servers must support PKCE (RFC 9700, section 2.1.1)."
		} : {
			id: "pkce",
			status: "warn",
			label: "PKCE (S256) not advertised",
			detail: "code_challenge_methods_supported is missing or lacks S256, so this document does not show that PKCE is supported. Authorization servers must support it and give clients a way to detect that; publishing this field is the recommended way (RFC 9700, section 2.1.1)."
		});
		const implicit = (Array.isArray(discovery.response_types_supported) ? discovery.response_types_supported.map(String) : []).filter((t) => t.split(" ").includes("token"));
		checks.push(implicit.length === 0 ? {
			id: "implicit",
			status: "pass",
			label: "No implicit flow",
			detail: "Access tokens are never returned in the URL."
		} : {
			id: "implicit",
			status: "warn",
			label: "Still offers the implicit flow",
			detail: `response_types_supported includes ${implicit.map((t) => `"${t}"`).join(", ")}, which RFC 9700 (section 2.1.2) says clients should not use.`
		});
	} else checks.push({
		id: "no-browser-flow",
		status: "info",
		label: "Machine-identity issuer",
		detail: "No authorization endpoint: this issuer mints tokens for workloads, not browser sign-ins."
	});
	if (idTokenAlgs.some((a) => a.toLowerCase() === "none")) checks.push({
		id: "alg-none",
		status: "fail",
		label: "Allows unsigned ID tokens",
		detail: "\"none\" is listed in id_token_signing_alg_values_supported."
	});
	return {
		issuer: String(discovery.issuer ?? ""),
		idTokenAlgs,
		vulnerableAlgs,
		keys,
		verdict,
		jwksBytes,
		jwksBytesWithMlDsa65: jwksBytes + ML_DSA_65_JWK_BYTES + 1,
		checks
	};
}
//#endregion
//#region packages/scan-core/src/oidc/discover.ts
/**
* Looks for OpenID Connect (or OAuth authorization server) metadata, and if it
* is there, reads the keys the service signs tokens with. This is the only way
* an outside scan can learn anything about token signing; when nothing is
* published, the answer is "could not determine", not a guess.
*
* Every URL in the metadata is attacker-controlled input. `jwks_uri` is put
* through the same policy, resolution and pinning as a user-supplied target.
*/
/**
* Where metadata might live for a URL. An issuer may have a path
* (https://idp.example/realms/a), so each path prefix is tried, deepest
* first, then the OAuth well-known name at the root.
*/
function discoveryCandidates(url, includeFullPath) {
	const segments = url.pathname.split("/").filter(Boolean);
	if (segments.at(-1) === "openid-configuration" && segments.at(-2) === ".well-known") return [`${url.origin}${url.pathname}`];
	if (!includeFullPath) segments.pop();
	const candidates = [];
	for (let depth = segments.length; depth >= 0 && candidates.length < 4; depth--) {
		const prefix = segments.slice(0, depth).join("/");
		candidates.push(`${url.origin}${prefix ? `/${prefix}` : ""}/.well-known/openid-configuration`);
	}
	if (!candidates.includes(`${url.origin}/.well-known/openid-configuration`)) candidates.push(`${url.origin}/.well-known/openid-configuration`);
	candidates.push(`${url.origin}/.well-known/oauth-authorization-server`);
	return candidates;
}
function parseJson(body) {
	try {
		const value = JSON.parse(body.toString("utf8"));
		return typeof value === "object" && value !== null && !Array.isArray(value) ? value : void 0;
	} catch {
		return;
	}
}
const originOf = (value) => {
	try {
		return typeof value === "string" ? new URL(value).origin : void 0;
	} catch {
		return;
	}
};
async function discoverOidc(url, pinned, policy, options) {
	const summary = {
		found: false,
		tried: []
	};
	const related = [];
	let metadata;
	const candidates = options.exactIssuer ? [`${url.origin}${url.pathname.replace(/\/$/, "")}/.well-known/openid-configuration`] : discoveryCandidates(url, options.includeFullPath);
	for (const candidate of candidates) {
		if (options.skip?.has(candidate)) continue;
		try {
			const response = await fetchPinned(new URL(candidate), pinned, {
				...options,
				maxBytes: 262144
			});
			const json = response.status === 200 ? parseJson(response.body) : void 0;
			if (json && typeof json.issuer === "string") {
				summary.tried.push({
					url: candidate,
					result: "HTTP 200, metadata found"
				});
				summary.discoveryUrl = candidate;
				metadata = json;
				break;
			}
			summary.tried.push({
				url: candidate,
				result: response.status === 200 ? "HTTP 200, but not a metadata document" : `HTTP ${response.status}`
			});
		} catch (error) {
			if (!(error instanceof FetchError)) throw error;
			summary.tried.push({
				url: candidate,
				result: error.message
			});
		}
	}
	if (!metadata || !summary.discoveryUrl) return {
		summary,
		related
	};
	summary.found = true;
	summary.issuer = String(metadata.issuer);
	const servedFrom = summary.discoveryUrl.replace(/\/\.well-known\/(openid-configuration|oauth-authorization-server)$/, "");
	summary.issuerMatches = summary.issuer.replace(/\/$/, "") === servedFrom;
	summary.idTokenAlgs = Array.isArray(metadata.id_token_signing_alg_values_supported) ? metadata.id_token_signing_alg_values_supported.map(String) : [];
	for (const [field, role] of [
		["authorization_endpoint", "authorization endpoint named in the metadata"],
		["token_endpoint", "token endpoint named in the metadata"],
		["jwks_uri", "publishes the token signing keys"]
	]) {
		const origin = originOf(metadata[field]);
		if (origin && origin !== url.origin && !related.some((r) => r.origin === origin)) related.push({
			origin,
			role
		});
	}
	if (typeof metadata.jwks_uri !== "string") {
		summary.jwksError = "The metadata has no jwks_uri.";
		return {
			summary,
			related
		};
	}
	summary.jwksUri = metadata.jwks_uri;
	try {
		const jwksTarget = parseTarget(metadata.jwks_uri, policy);
		const jwksPinned = jwksTarget.origin === url.origin ? pinned : await resolveTarget(jwksTarget, { lookup: options.lookup });
		const response = await fetchPinned(jwksTarget.url, jwksPinned, {
			...options,
			maxBytes: 524288
		});
		const jwks = response.status === 200 && !response.truncated ? parseJson(response.body) : void 0;
		if (!jwks || !Array.isArray(jwks.keys)) summary.jwksError = response.truncated ? "The key set is larger than 512 kB." : `The key set could not be read (HTTP ${response.status}).`;
		else {
			summary.keys = analyzeProvider(metadata, jwks, response.body.length).keys.filter((k) => k.use !== "enc");
			return {
				summary,
				related,
				jwks
			};
		}
	} catch (error) {
		if (error instanceof TargetRejected) summary.jwksError = `The scanner will not fetch jwks_uri: ${error.message}`;
		else if (error instanceof FetchError) summary.jwksError = error.message;
		else throw error;
	}
	return {
		summary,
		related
	};
}
//#endregion
//#region packages/scan-core/src/x509/summary.ts
/**
* Summarises the certificates a server sent: who they name, how long they are
* valid, the type of key they carry and the algorithm their issuer signed
* them with. Parsing is OpenSSL's (through Node); nothing here decides trust.
*/
const RSA = "1.2.840.113549.1.1";
const ECDSA = "1.2.840.10045.4";
const NIST_SIG = "2.16.840.1.101.3.4.3";
const SIGNATURE_OIDS = {
	[`${RSA}.4`]: {
		name: "RSA PKCS#1 v1.5 with MD5",
		family: "RSA",
		hash: "MD5"
	},
	[`${RSA}.5`]: {
		name: "RSA PKCS#1 v1.5 with SHA-1",
		family: "RSA",
		hash: "SHA-1"
	},
	[`${RSA}.11`]: {
		name: "RSA PKCS#1 v1.5 with SHA-256",
		family: "RSA",
		hash: "SHA-256"
	},
	[`${RSA}.12`]: {
		name: "RSA PKCS#1 v1.5 with SHA-384",
		family: "RSA",
		hash: "SHA-384"
	},
	[`${RSA}.13`]: {
		name: "RSA PKCS#1 v1.5 with SHA-512",
		family: "RSA",
		hash: "SHA-512"
	},
	[`${RSA}.10`]: {
		name: "RSASSA-PSS",
		family: "RSA"
	},
	[`${ECDSA}.1`]: {
		name: "ECDSA with SHA-1",
		family: "ECDSA",
		hash: "SHA-1"
	},
	[`${ECDSA}.3.2`]: {
		name: "ECDSA with SHA-256",
		family: "ECDSA",
		hash: "SHA-256"
	},
	[`${ECDSA}.3.3`]: {
		name: "ECDSA with SHA-384",
		family: "ECDSA",
		hash: "SHA-384"
	},
	[`${ECDSA}.3.4`]: {
		name: "ECDSA with SHA-512",
		family: "ECDSA",
		hash: "SHA-512"
	},
	"1.3.101.112": {
		name: "Ed25519",
		family: "EdDSA"
	},
	"1.3.101.113": {
		name: "Ed448",
		family: "EdDSA"
	},
	[`${NIST_SIG}.17`]: {
		name: "ML-DSA-44",
		family: "ML-DSA"
	},
	[`${NIST_SIG}.18`]: {
		name: "ML-DSA-65",
		family: "ML-DSA"
	},
	[`${NIST_SIG}.19`]: {
		name: "ML-DSA-87",
		family: "ML-DSA"
	}
};
function signatureAlgorithm(oid, text) {
	const known = SIGNATURE_OIDS[oid];
	if (known) return known;
	const last = Number(oid.startsWith(`${NIST_SIG}.`) ? oid.slice(21) : NaN);
	if (last >= 20 && last <= 31) return {
		name: text || "SLH-DSA",
		family: "SLH-DSA"
	};
	return {
		name: text || oid,
		family: "unknown"
	};
}
const quantumSafe = (family) => family === "ML-DSA" || family === "SLH-DSA";
const CURVES = {
	prime256v1: "P-256",
	secp384r1: "P-384",
	secp521r1: "P-521"
};
function describeKey(certificate) {
	let key;
	try {
		key = certificate.publicKey;
	} catch {
		return {
			algorithm: "unrecognised key type",
			family: "unknown",
			quantumSafe: false
		};
	}
	const type = String(key.asymmetricKeyType);
	const details = key.asymmetricKeyDetails;
	if (type === "rsa" || type === "rsa-pss") return {
		algorithm: `RSA ${details?.modulusLength}-bit`,
		family: "RSA",
		bits: details?.modulusLength,
		quantumSafe: false
	};
	if (type === "ec") {
		const curve = CURVES[details?.namedCurve ?? ""] ?? details?.namedCurve ?? "unknown curve";
		return {
			algorithm: `ECDSA ${curve}`,
			family: "ECDSA",
			curve,
			quantumSafe: false
		};
	}
	if (type === "ed25519" || type === "ed448") return {
		algorithm: type === "ed25519" ? "Ed25519" : "Ed448",
		family: "EdDSA",
		quantumSafe: false
	};
	if (type.startsWith("ml-dsa")) return {
		algorithm: type.toUpperCase(),
		family: "ML-DSA",
		quantumSafe: true
	};
	if (type.startsWith("slh-dsa")) return {
		algorithm: type.toUpperCase(),
		family: "SLH-DSA",
		quantumSafe: true
	};
	return {
		algorithm: type,
		family: "unknown",
		quantumSafe: false
	};
}
function altNames(certificate) {
	return (certificate.subjectAltName ?? "").split(", ").filter(Boolean).map((entry) => entry.replace(/^(DNS|IP Address|URI|email):/, ""));
}
function isSelfSigned(certificate) {
	if (certificate.subject !== certificate.issuer) return false;
	try {
		return certificate.verify(certificate.publicKey);
	} catch {
		return false;
	}
}
/** Distinguished names come back one attribute per line; a report wants one line. */
const oneLine = (name) => name.split("\n").reverse().join(", ");
function summarizeCertificate(der, position, now = /* @__PURE__ */ new Date()) {
	const certificate = new crypto.X509Certificate(der);
	const notBefore = new Date(certificate.validFrom);
	const notAfter = new Date(certificate.validTo);
	const signature = signatureAlgorithm(certificate.signatureAlgorithmOid ?? "", certificate.signatureAlgorithm ?? "");
	return {
		position,
		subject: oneLine(certificate.subject),
		issuer: oneLine(certificate.issuer),
		serialNumber: certificate.serialNumber,
		notBefore: notBefore.toISOString(),
		notAfter: notAfter.toISOString(),
		expired: notAfter < now,
		notYetValid: notBefore > now,
		selfSigned: isSelfSigned(certificate),
		isCa: certificate.ca,
		names: altNames(certificate),
		key: describeKey(certificate),
		signature: {
			algorithm: signature.name,
			oid: certificate.signatureAlgorithmOid ?? "",
			family: signature.family,
			hash: signature.hash,
			quantumSafe: quantumSafe(signature.family)
		},
		fingerprint256: crypto.createHash("sha256").update(der).digest("hex"),
		pem: certificate.toString()
	};
}
/** Summarises a chain, skipping anything that does not parse as a certificate. */
function summarizeChain(chain, now = /* @__PURE__ */ new Date()) {
	const out = [];
	for (const [position, der] of chain.entries()) try {
		out.push(summarizeCertificate(der, position, now));
	} catch {}
	return out;
}
//#endregion
//#region packages/scan-core/src/tls/wire.ts
/**
* Reading and writing TLS's wire format: big-endian integers and
* length-prefixed vectors. The reader is used on bytes from untrusted servers,
* so every read is bounds-checked and a short buffer is an error, never a
* silent truncation.
*/
/** The peer sent something that is not well-formed TLS. */
var WireError = class extends Error {
	constructor(message) {
		super(message);
		this.name = "WireError";
	}
};
var Reader = class {
	data;
	offset = 0;
	constructor(data) {
		this.data = data;
	}
	get remaining() {
		return this.data.length - this.offset;
	}
	need(n) {
		if (n > this.remaining) throw new WireError(`needed ${n} more bytes, ${this.remaining} left`);
	}
	u8() {
		this.need(1);
		return this.data[this.offset++];
	}
	u16() {
		this.need(2);
		const value = this.data.readUInt16BE(this.offset);
		this.offset += 2;
		return value;
	}
	u24() {
		this.need(3);
		const value = this.data.readUIntBE(this.offset, 3);
		this.offset += 3;
		return value;
	}
	bytes(n) {
		this.need(n);
		const out = this.data.subarray(this.offset, this.offset + n);
		this.offset += n;
		return out;
	}
	/** A vector whose length is given by a prefix of 1, 2 or 3 bytes. */
	vector(prefixBytes) {
		const length = prefixBytes === 1 ? this.u8() : prefixBytes === 2 ? this.u16() : this.u24();
		return this.bytes(length);
	}
	rest() {
		return this.bytes(this.remaining);
	}
};
var Writer = class Writer {
	parts = [];
	u8(value) {
		this.parts.push(Buffer.from([value & 255]));
		return this;
	}
	u16(value) {
		const b = Buffer.alloc(2);
		b.writeUInt16BE(value);
		this.parts.push(b);
		return this;
	}
	u24(value) {
		const b = Buffer.alloc(3);
		b.writeUIntBE(value, 0, 3);
		this.parts.push(b);
		return this;
	}
	bytes(value) {
		this.parts.push(Buffer.from(value));
		return this;
	}
	vector(prefixBytes, value) {
		let body;
		if (typeof value === "function") {
			const inner = new Writer();
			value(inner);
			body = inner.finish();
		} else body = value;
		if (body.length >= 2 ** (8 * prefixBytes)) throw new RangeError("vector too long for its length prefix");
		if (prefixBytes === 1) this.u8(body.length);
		else if (prefixBytes === 2) this.u16(body.length);
		else this.u24(body.length);
		return this.bytes(body);
	}
	finish() {
		return Buffer.concat(this.parts);
	}
};
const CONTENT_TYPE = {
	changeCipherSpec: 20,
	alert: 21,
	handshake: 22,
	applicationData: 23
};
const HANDSHAKE_TYPE = {
	clientHello: 1,
	serverHello: 2,
	newSessionTicket: 4,
	encryptedExtensions: 8,
	certificate: 11,
	serverKeyExchange: 12,
	certificateRequest: 13,
	serverHelloDone: 14,
	certificateVerify: 15,
	finished: 20,
	certificateStatus: 22
};
/** A plaintext record may carry 2^14 bytes; a protected one 2^14 + 256 (RFC 8446 §5.2). */
const MAX_FRAGMENT = 16640;
/** Splits a TCP byte stream into TLS records. */
var RecordReader = class {
	pending = Buffer.alloc(0);
	push(chunk) {
		this.pending = this.pending.length ? Buffer.concat([this.pending, chunk]) : chunk;
	}
	/** The next complete record, or undefined if more bytes are needed. */
	next() {
		if (this.pending.length < 5) return void 0;
		const type = this.pending[0];
		const version = this.pending.readUInt16BE(1);
		const length = this.pending.readUInt16BE(3);
		if (type < CONTENT_TYPE.changeCipherSpec || type > CONTENT_TYPE.applicationData || version >> 8 !== 3) throw new WireError("the server did not answer with TLS");
		if (length > MAX_FRAGMENT) throw new WireError(`record of ${length} bytes exceeds the TLS limit`);
		if (this.pending.length < 5 + length) return void 0;
		const record = {
			type,
			version,
			header: this.pending.subarray(0, 5),
			fragment: this.pending.subarray(5, 5 + length)
		};
		this.pending = this.pending.subarray(5 + length);
		return record;
	}
};
/** A sane ceiling for one handshake message; certificate chains with ML-DSA keys run to tens of kilobytes. */
const MAX_HANDSHAKE_MESSAGE = 262144;
/** Reassembles handshake messages, which may be split across records or share one. */
var HandshakeReader = class {
	pending = Buffer.alloc(0);
	push(fragment) {
		this.pending = this.pending.length ? Buffer.concat([this.pending, fragment]) : fragment;
	}
	next() {
		if (this.pending.length < 4) return void 0;
		const length = this.pending.readUIntBE(1, 3);
		if (length > MAX_HANDSHAKE_MESSAGE) throw new WireError(`handshake message of ${length} bytes is larger than this scanner accepts`);
		if (this.pending.length < 4 + length) return void 0;
		const raw = this.pending.subarray(0, 4 + length);
		this.pending = this.pending.subarray(4 + length);
		return {
			type: raw[0],
			body: raw.subarray(4),
			raw
		};
	}
	get hasPartial() {
		return this.pending.length > 0;
	}
};
function record(type, version, fragment) {
	return new Writer().u8(type).u16(version).vector(2, fragment).finish();
}
function handshakeMessage(type, body) {
	return new Writer().u8(type).vector(3, body).finish();
}
//#endregion
//#region packages/scan-core/src/tls/keyshare.ts
/**
* Client key shares for the groups the scanner can complete a handshake with,
* using Node's own crypto (OpenSSL 3.5: X25519, P-256, P-384, ML-KEM).
*
* Hybrid groups concatenate the two shares, and the two shared secrets, in an
* order fixed per group (RFC 10024 §4):
*
*   X25519MLKEM768      share: ML-KEM key ‖ X25519      secret: ML-KEM ‖ X25519
*   SecP256r1MLKEM768   share: P-256 point ‖ ML-KEM key secret: ECDH ‖ ML-KEM
*   SecP384r1MLKEM1024  share: P-384 point ‖ ML-KEM key secret: ECDH ‖ ML-KEM
*/
const PKCS8_X25519_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
function x25519Part(privateBytes) {
	const privateKey = privateBytes ? crypto.createPrivateKey({
		key: Buffer.concat([PKCS8_X25519_PREFIX, privateBytes]),
		format: "der",
		type: "pkcs8"
	}) : crypto.generateKeyPairSync("x25519").privateKey;
	const jwk = crypto.createPublicKey(privateKey).export({ format: "jwk" });
	return {
		publicBytes: Buffer.from(jwk.x, "base64url"),
		serverShareBytes: 32,
		sharedSecret(serverShare) {
			const publicKey = crypto.createPublicKey({
				key: {
					kty: "OKP",
					crv: "X25519",
					x: serverShare.toString("base64url")
				},
				format: "jwk"
			});
			return crypto.diffieHellman({
				privateKey,
				publicKey
			});
		}
	};
}
function ecdhPart(curve) {
	const ecdh = crypto.createECDH(curve);
	const publicBytes = ecdh.generateKeys();
	return {
		publicBytes,
		serverShareBytes: publicBytes.length,
		sharedSecret: (serverShare) => ecdh.computeSecret(serverShare)
	};
}
function mlKemPart(parameterSet) {
	const { publicKey, privateKey } = crypto.generateKeyPairSync(parameterSet);
	const sizes = parameterSet === "ml-kem-768" ? {
		key: 1184,
		ciphertext: 1088
	} : {
		key: 1568,
		ciphertext: 1568
	};
	const spki = publicKey.export({
		type: "spki",
		format: "der"
	});
	return {
		publicBytes: spki.subarray(spki.length - sizes.key),
		serverShareBytes: sizes.ciphertext,
		sharedSecret: (ciphertext) => crypto.decapsulate(privateKey, ciphertext)
	};
}
/** Builds a share from parts in the order given; the secret is the parts' secrets in the same order. */
function combine(group, parts) {
	const expected = parts.reduce((n, p) => n + p.serverShareBytes, 0);
	return {
		group,
		publicBytes: Buffer.concat(parts.map((p) => p.publicBytes)),
		sharedSecret(serverShare) {
			if (serverShare.length !== expected) throw new WireError(`server key share is ${serverShare.length} bytes; this group requires ${expected}`);
			let offset = 0;
			try {
				return Buffer.concat(parts.map((part) => {
					const slice = serverShare.subarray(offset, offset + part.serverShareBytes);
					offset += part.serverShareBytes;
					return part.sharedSecret(slice);
				}));
			} catch (error) {
				throw new WireError(`server key share was rejected: ${error instanceof Error ? error.message : String(error)}`);
			}
		}
	};
}
const BUILDERS = {
	[GROUP.x25519]: () => [x25519Part()],
	[GROUP.secp256r1]: () => [ecdhPart("prime256v1")],
	[GROUP.secp384r1]: () => [ecdhPart("secp384r1")],
	[GROUP.MLKEM768]: () => [mlKemPart("ml-kem-768")],
	[GROUP.MLKEM1024]: () => [mlKemPart("ml-kem-1024")],
	[GROUP.X25519MLKEM768]: () => [mlKemPart("ml-kem-768"), x25519Part()],
	[GROUP.SecP256r1MLKEM768]: () => [ecdhPart("prime256v1"), mlKemPart("ml-kem-768")],
	[GROUP.SecP384r1MLKEM1024]: () => [ecdhPart("secp384r1"), mlKemPart("ml-kem-1024")]
};
/** Can the scanner complete a key exchange in this group (rather than only recognise it)? */
function canGenerateKeyShare(group) {
	return group in BUILDERS;
}
function generateKeyShare(group) {
	const build = BUILDERS[group];
	if (!build) throw new Error(`No key share implementation for group 0x${group.toString(16)}`);
	return combine(group, build());
}
//#endregion
//#region packages/scan-core/src/tls/clienthello.ts
/**
* Builds the ClientHello the scanner sends. What a server reveals depends on
* what it is offered, so each probe is a different spec: which versions, which
* groups, which of those groups come with a key share, and which signature
* schemes.
*/
const EXTENSION = {
	serverName: 0,
	supportedGroups: 10,
	ecPointFormats: 11,
	signatureAlgorithms: 13,
	alpn: 16,
	extendedMasterSecret: 23,
	supportedVersions: 43,
	keyShare: 51,
	renegotiationInfo: 65281
};
function buildClientHello(spec) {
	const offers13 = spec.versions.includes("1.3");
	const offers12 = spec.versions.includes("1.2");
	const random = spec.random ?? randomBytes(32);
	const suites = [...offers13 ? TLS13_SUITES : [], ...offers12 ? TLS12_SUITES : []];
	const extensions = new Writer();
	const extension = (type, body) => extensions.u16(type).vector(2, body);
	if (spec.serverName) extension(EXTENSION.serverName, (w) => w.vector(2, (list) => list.u8(0).vector(2, Buffer.from(spec.serverName, "ascii"))));
	extension(EXTENSION.supportedGroups, (w) => w.vector(2, (list) => spec.groups.forEach((g) => list.u16(g))));
	extension(EXTENSION.signatureAlgorithms, (w) => w.vector(2, (list) => spec.signatureSchemes.forEach((s) => list.u16(s))));
	if (spec.alpn?.length) extension(EXTENSION.alpn, (w) => w.vector(2, (list) => spec.alpn.forEach((name) => list.vector(1, Buffer.from(name, "ascii")))));
	if (offers12) {
		extension(EXTENSION.ecPointFormats, (w) => w.vector(1, Buffer.from([0])));
		extension(EXTENSION.extendedMasterSecret, () => {});
		extension(EXTENSION.renegotiationInfo, (w) => w.vector(1, Buffer.alloc(0)));
	}
	if (offers13) {
		extension(EXTENSION.supportedVersions, (w) => w.vector(1, (list) => {
			list.u16(772);
			if (offers12) list.u16(771);
		}));
		extension(EXTENSION.keyShare, (w) => w.vector(2, (shares) => spec.keyShares.forEach((share) => shares.u16(share.group).vector(2, share.publicBytes))));
	}
	const body = new Writer().u16(771).bytes(random).vector(1, spec.sessionId ?? randomBytes(32)).vector(2, (w) => suites.forEach((s) => w.u16(s))).vector(1, Buffer.from([0])).vector(2, extensions.finish()).finish();
	return {
		message: handshakeMessage(HANDSHAKE_TYPE.clientHello, body),
		random
	};
}
//#endregion
//#region node_modules/@noble/hashes/utils.js
/**
* Checks if something is Uint8Array. Be careful: nodejs Buffer will return true.
* @param a - value to test
* @returns `true` when the value is a Uint8Array-compatible view.
* @example
* Check whether a value is a Uint8Array-compatible view.
* ```ts
* isBytes(new Uint8Array([1, 2, 3]));
* ```
*/
function isBytes(a) {
	return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
const atitle = (title) => title ? `"${title}" ` : "";
/**
* Asserts something is a non-negative integer.
* @param n - number to validate
* @param title - label included in thrown errors
* @returns The validated number.
* @throws On wrong argument types. {@link TypeError}
* @throws On wrong argument ranges or values. {@link RangeError}
* @example
* Validate a non-negative integer option.
* ```ts
* anumber(32, 'length');
* ```
*/
function anumber(n, title = "") {
	if (typeof n !== "number") throw new TypeError(atitle(title) + "expected number, got " + typeof n);
	if (!Number.isSafeInteger(n) || n < 0) throw new RangeError(atitle(title) + "expected integer >= 0, got " + n);
	return n;
}
/**
* Asserts something is Uint8Array.
* @param value - value to validate
* @param length - optional exact length constraint
* @param title - label included in thrown errors
* @returns The validated byte array.
* @throws On wrong argument types. {@link TypeError}
* @throws On wrong argument ranges or values. {@link RangeError}
* @example
* Validate that a value is a byte array.
* ```ts
* abytes(new Uint8Array([1, 2, 3]));
* ```
*/
function abytes(value, length, title = "") {
	if (isBytes(value) && (length === void 0 || value.length === length)) return value;
	if (length !== void 0) anumber(length, "length");
	const bytes = isBytes(value);
	const ofLen = length !== void 0 ? ` of length ${length}` : "";
	const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
	const message = atitle(title) + "expected Uint8Array" + ofLen + ", got " + got;
	if (!bytes) throw new TypeError(message);
	throw new RangeError(message);
}
/**
* Asserts something is a wrapped hash constructor.
* @param h - hash constructor to validate
* @throws On wrong argument types or invalid hash wrapper shape. {@link TypeError}
* @throws On invalid hash metadata ranges or values. {@link RangeError}
* @throws If the hash metadata allows empty outputs or block sizes. {@link Error}
* @example
* Validate a callable hash wrapper.
* ```ts
* import { ahash } from '@noble/hashes/utils.js';
* import { sha256 } from '@noble/hashes/sha2.js';
* ahash(sha256);
* ```
*/
function ahash(h) {
	if (typeof h !== "function" || typeof h.create !== "function") throw new TypeError("expected hash wrapped by utils.createHasher");
	anumber(h.outputLen);
	anumber(h.blockLen);
	if (h.outputLen < 1 || h.blockLen < 1) throw new Error("hash blockLen / outputLen must be >= 1");
}
const aobject = (value, label) => {
	if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError((label === "object" ? "" : `"${label}" `) + "expected object, got type=" + typeof value);
};
const aopts = (value, label) => {
	aobject(value, label);
	const proto = Object.getPrototypeOf(value);
	if (proto !== Object.prototype && proto !== null) throw new TypeError(`"${label}" expected plain object`);
	if (Object.hasOwn(value, "__proto__")) throw new TypeError(`"${label}.__proto__" is not allowed`);
};
/**
* Asserts a hash instance has not been destroyed or finished.
* @param instance - hash instance to validate
* @param checkFinished - whether to reject finalized instances
* @throws If the hash instance has already been destroyed or finalized. {@link Error}
* @example
* Validate that a hash instance is still usable.
* ```ts
* import { aexists } from '@noble/hashes/utils.js';
* import { sha256 } from '@noble/hashes/sha2.js';
* const hash = sha256.create();
* aexists(hash);
* ```
*/
function aexists(instance, checkFinished = true) {
	if (instance.destroyed) throw new Error("hash was destroyed");
	if (checkFinished && instance.finished) throw new Error("digest() was already called");
}
/**
* Asserts output is a sufficiently-sized byte array.
* @param out - destination buffer
* @param instance - hash instance providing output length
* Oversized buffers are allowed; downstream code only promises to fill the first `outputLen` bytes.
* @throws On wrong argument types. {@link TypeError}
* @throws On wrong argument ranges or values. {@link RangeError}
* @example
* Validate a caller-provided digest buffer.
* ```ts
* import { aoutput } from '@noble/hashes/utils.js';
* import { sha256 } from '@noble/hashes/sha2.js';
* const hash = sha256.create();
* aoutput(new Uint8Array(hash.outputLen), hash);
* ```
*/
function aoutput(out, instance) {
	abytes(out, void 0, "output");
	const min = instance.outputLen;
	if (!(out.length >= min)) throw new RangeError("\"output\" expected length >= " + min);
}
/**
* Zeroizes typed arrays in place. Warning: JS provides no guarantees.
* @param arrays - arrays to overwrite with zeros
* @example
* Zeroize sensitive buffers in place.
* ```ts
* clean(new Uint8Array([1, 2, 3]));
* ```
*/
function clean(...arrays) {
	for (let i = 0; i < arrays.length; i++) arrays[i].fill(0);
}
/**
* Creates a DataView for byte-level manipulation.
* @param arr - source typed array
* @returns DataView over the same buffer region.
* @example
* Create a DataView over an existing buffer.
* ```ts
* createView(new Uint8Array(4));
* ```
*/
function createView(arr) {
	return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
/**
* Rotate-right operation for uint32 values.
* @param word - source word
* @param shift - shift amount in bits
* @returns Rotated word.
* @example
* Rotate a 32-bit word to the right.
* ```ts
* rotr(0x12345678, 8);
* ```
*/
function rotr(word, shift) {
	return word << 32 - shift | word >>> shift;
}
/**
* Merges default options and passed options.
* @param defaults - base option object
* @param opts - user overrides
* @param title - label included in thrown override errors
* @returns Fresh merged option object with a null prototype.
* @throws On wrong argument types. {@link TypeError}
* @example
* Merge user overrides onto default options.
* ```ts
* checkOpts({ dkLen: 32 }, { asyncTick: 10 });
* ```
*/
function checkOpts(defaults, opts, title = "opts") {
	aopts(defaults, "defaults");
	if (opts !== void 0) aopts(opts, title);
	return Object.assign(Object.create(null), defaults, opts);
}
/**
* Creates a callable hash function from a stateful class constructor.
* @param hashCons - hash constructor or factory
* @param info - optional metadata such as DER OID
* @returns Frozen callable hash wrapper with `.create()`.
*   Wrapper construction eagerly calls `hashCons(undefined)` once to read
*   `outputLen` / `blockLen`, so constructor side effects happen at module
*   init time.
* @throws On wrong argument types. {@link TypeError}
* @example
* Wrap a stateful hash constructor into a callable helper.
* ```ts
* import { createHasher } from '@noble/hashes/utils.js';
* import { sha256 } from '@noble/hashes/sha2.js';
* const wrapped = createHasher(sha256.create, { oid: sha256.oid });
* wrapped(new Uint8Array([1]));
* ```
*/
function createHasher(hashCons, info = {}) {
	if (typeof hashCons !== "function") throw new TypeError("\"hashCons\" expected function, got type=" + typeof hashCons);
	info = checkOpts({}, info, "info");
	const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
	const tmp = hashCons(void 0);
	hashC.outputLen = tmp.outputLen;
	hashC.blockLen = tmp.blockLen;
	hashC.canXOF = tmp.canXOF;
	hashC.create = (opts) => hashCons(opts);
	Object.assign(hashC, info);
	return Object.freeze(hashC);
}
/**
* Creates OID metadata for NIST hashes with prefix `06 09 60 86 48 01 65 03 04 02`.
* @param suffix - final OID byte for the selected hash.
*   The helper accepts any byte even though only the documented NIST hash
*   suffixes are meaningful downstream.
* @returns Object containing the DER-encoded OID.
* @example
* Build OID metadata for a NIST hash.
* ```ts
* oidNist(0x01);
* ```
*/
const oidNist = (suffix) => ({ oid: Uint8Array.from([
	6,
	9,
	96,
	134,
	72,
	1,
	101,
	3,
	4,
	2,
	suffix
]) });
//#endregion
//#region node_modules/@noble/hashes/hmac.js
/**
* HMAC: RFC2104 message authentication code.
* @module
*/
/**
* Internal class for HMAC.
* Accepts any byte key, although RFC 2104 §3 recommends keys at least
* `HashLen` bytes long.
*/
var _HMAC = class {
	oHash;
	iHash;
	blockLen;
	outputLen;
	canXOF = false;
	finished = false;
	destroyed = false;
	constructor(hash, key) {
		ahash(hash);
		abytes(key, void 0, "key");
		this.iHash = hash.create();
		if (typeof this.iHash.update !== "function") throw new Error("expected Hash instance");
		this.blockLen = this.iHash.blockLen;
		this.outputLen = this.iHash.outputLen;
		const blockLen = this.blockLen;
		const pad = new Uint8Array(blockLen);
		pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
		for (let i = 0; i < pad.length; i++) pad[i] ^= 54;
		this.iHash.update(pad);
		this.oHash = hash.create();
		for (let i = 0; i < pad.length; i++) pad[i] ^= 106;
		this.oHash.update(pad);
		clean(pad);
	}
	update(buf) {
		aexists(this);
		this.iHash.update(buf);
		return this;
	}
	digestInto(out) {
		aexists(this);
		aoutput(out, this);
		this.finished = true;
		const buf = out.subarray(0, this.outputLen);
		this.iHash.digestInto(buf);
		this.oHash.update(buf);
		this.oHash.digestInto(buf);
		this.destroy();
	}
	digest() {
		const out = new Uint8Array(this.oHash.outputLen);
		this.digestInto(out);
		return out;
	}
	_cloneInto(to) {
		to ||= Object.create(Object.getPrototypeOf(this), {});
		const { oHash, iHash, finished, destroyed, blockLen, outputLen, canXOF } = this;
		to = to;
		to.finished = finished;
		to.destroyed = destroyed;
		to.blockLen = blockLen;
		to.outputLen = outputLen;
		to.canXOF = canXOF;
		to.oHash = oHash._cloneInto(to.oHash);
		to.iHash = iHash._cloneInto(to.iHash);
		return to;
	}
	clone() {
		return this._cloneInto();
	}
	destroy() {
		this.destroyed = true;
		this.oHash.destroy();
		this.iHash.destroy();
	}
};
const hmac = /* @__PURE__ */ (() => {
	const hmac_ = ((hash, key, message) => new _HMAC(hash, key).update(message).digest());
	hmac_.create = (hash, key) => new _HMAC(hash, key);
	return hmac_;
})();
//#endregion
//#region node_modules/@noble/hashes/hkdf.js
/**
* HKDF (RFC 5869): extract + expand in one step.
* See {@link https://soatok.blog/2021/11/17/understanding-hkdf/}.
* @module
*/
/**
* HKDF-extract from spec. Less important part. `HKDF-Extract(IKM, salt) -> PRK`
* Arguments position differs from spec (IKM is first one, since it is not optional)
* Local validation only checks `hash`; `ikm` / `salt` byte validation is delegated to `hmac()`.
* @param hash - hash function that would be used (e.g. sha256)
* @param ikm - input keying material, the initial key
* @param salt - optional salt value (a non-secret random value)
* @returns Pseudorandom key derived from input keying material.
* @example
* Run the HKDF extract step.
* ```ts
* import { extract } from '@noble/hashes/hkdf.js';
* import { sha256 } from '@noble/hashes/sha2.js';
* extract(sha256, new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6]));
* ```
*/
function extract(hash, ikm, salt) {
	ahash(hash);
	if (salt === void 0) salt = new Uint8Array(hash.outputLen);
	return hmac(hash, salt, ikm);
}
const HKDF_COUNTER = /* @__PURE__ */ Uint8Array.of(0);
const EMPTY_BUFFER = /* @__PURE__ */ Uint8Array.of();
/**
* HKDF-expand from the spec. The most important part. `HKDF-Expand(PRK, info, L) -> OKM`
* @param hash - hash function that would be used (e.g. sha256)
* @param prk - a pseudorandom key of at least HashLen octets
*   (usually, the output from the extract step)
* @param info - optional context and application specific information (can be a zero-length string)
* @param length - length of output keying material in bytes.
*   RFC 5869 §2.3 allows `0..255*HashLen`, so `0` returns an empty OKM.
* @param _recycled - Internal destroyed extract hashes owned by the combined `hkdf()` call.
* @returns Output keying material with the requested length.
* @throws If the requested output length exceeds the HKDF limit
*   for the selected hash. {@link Error}
* @example
* Run the HKDF expand step.
* ```ts
* import { expand } from '@noble/hashes/hkdf.js';
* import { sha256 } from '@noble/hashes/sha2.js';
* expand(sha256, new Uint8Array(32), new Uint8Array([1, 2, 3]), 16);
* ```
*/
function expand(hash, prk, info, length = 32, _recycled) {
	ahash(hash);
	anumber(length, "length");
	abytes(prk, void 0, "prk");
	const olen = hash.outputLen;
	if (prk.length < olen) throw new Error("\"prk\" must be at least HashLen octets");
	if (length > 255 * olen) throw new Error("Length must be <= 255*HashLen");
	const blocks = Math.ceil(length / olen);
	if (info === void 0) info = EMPTY_BUFFER;
	else abytes(info, void 0, "info");
	if (!blocks) {
		if (_recycled) clean(prk);
		return /* @__PURE__ */ new Uint8Array();
	}
	const okm = _recycled && blocks === 1 ? prk : new Uint8Array(blocks * olen);
	const { iHash, oHash } = hmac.create(hash, prk);
	const T = _recycled ? prk : new Uint8Array(olen);
	const worker = blocks > 1 ? _recycled?.iHash || hash.create() : void 0;
	for (let counter = 0; counter < blocks - 1; counter++) {
		HKDF_COUNTER[0] = counter + 1;
		const iWork = iHash._cloneInto(worker);
		if (counter) iWork.update(T);
		iWork.update(info).update(HKDF_COUNTER).digestInto(T);
		oHash._cloneInto(worker).update(T).digestInto(T);
		okm.set(T, olen * counter);
	}
	HKDF_COUNTER[0] = blocks;
	if (blocks > 1) iHash.update(T);
	iHash.update(info).update(HKDF_COUNTER).digestInto(T);
	oHash.update(T).digestInto(T);
	okm.set(T, olen * (blocks - 1));
	iHash.destroy();
	oHash.destroy();
	worker?.destroy();
	if (T !== okm) clean(T);
	clean(HKDF_COUNTER);
	if (length === okm.length) return okm;
	const res = okm.slice(0, length);
	clean(okm);
	return res;
}
//#endregion
//#region node_modules/@noble/hashes/_u64.js
const U32_MASK64 = /* @__PURE__ */ (() => BigInt(2 ** 32 - 1))();
const _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
	if (le) return {
		h: Number(n & U32_MASK64),
		l: Number(n >> _32n & U32_MASK64)
	};
	return {
		h: Number(n >> _32n & U32_MASK64) | 0,
		l: Number(n & U32_MASK64) | 0
	};
}
function split(lst, le = false) {
	const len = lst.length;
	let Ah = new Uint32Array(len);
	let Al = new Uint32Array(len);
	for (let i = 0; i < len; i++) {
		const { h, l } = fromBig(lst[i], le);
		[Ah[i], Al[i]] = [h, l];
	}
	return [Ah, Al];
}
const fromNumH = (n) => n / 2 ** 32 | 0;
const fromNumL = (n) => n >>> 0;
function setU64FromNum(view, byteOffset, n, isLE) {
	const h = fromNumH(n);
	const l = fromNumL(n);
	view.setUint32(byteOffset, isLE ? l : h, isLE);
	view.setUint32(byteOffset + 4, isLE ? h : l, isLE);
}
const shrSH = (h, _l, s) => h >>> s;
const shrSL = (h, l, s) => h << 32 - s | l >>> s;
const rotrSH = (h, l, s) => h >>> s | l << 32 - s;
const rotrSL = (h, l, s) => h << 32 - s | l >>> s;
const rotrBH = (h, l, s) => h << 64 - s | l >>> s - 32;
const rotrBL = (h, l, s) => h >>> s - 32 | l << 64 - s;
function add(Ah, Al, Bh, Bl) {
	const l = (Al >>> 0) + (Bl >>> 0);
	return {
		h: Ah + Bh + (l / 2 ** 32 | 0) | 0,
		l: l | 0
	};
}
const add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
const add3H = (low, Ah, Bh, Ch) => Ah + Bh + Ch + (low / 2 ** 32 | 0) | 0;
const add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
const add4H = (low, Ah, Bh, Ch, Dh) => Ah + Bh + Ch + Dh + (low / 2 ** 32 | 0) | 0;
const add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
const add5H = (low, Ah, Bh, Ch, Dh, Eh) => Ah + Bh + Ch + Dh + Eh + (low / 2 ** 32 | 0) | 0;
//#endregion
//#region node_modules/@noble/hashes/_md.js
/**
* Internal Merkle-Damgard hash utils.
* @module
*/
/**
* Shared 32-bit conditional boolean primitive reused by SHA-256, SHA-1, and MD5 `F`.
* Returns bits from `b` when `a` is set, otherwise from `c`.
* The XOR form is equivalent to MD5's `F(X,Y,Z) = XY v not(X)Z` because the masked terms never
* set the same bit.
* @param a - selector word
* @param b - word chosen when selector bit is set
* @param c - word chosen when selector bit is clear
* @returns Mixed 32-bit word.
* @example
* Combine three words with the shared 32-bit choice primitive.
* ```ts
* Chi(0xffffffff, 0x12345678, 0x87654321);
* ```
*/
function Chi(a, b, c) {
	return a & b ^ ~a & c;
}
/**
* Shared 32-bit majority primitive reused by SHA-256 and SHA-1.
* Returns bits shared by at least two inputs.
* @param a - first input word
* @param b - second input word
* @param c - third input word
* @returns Mixed 32-bit word.
* @example
* Combine three words with the shared 32-bit majority primitive.
* ```ts
* Maj(0xffffffff, 0x12345678, 0x87654321);
* ```
*/
function Maj(a, b, c) {
	return a & b ^ a & c ^ b & c;
}
/**
* Merkle-Damgard hash construction base class.
* Could be used to create MD5, RIPEMD, SHA1, SHA2.
* Accepts only byte-aligned `Uint8Array` input, even when the underlying spec describes bit
* strings with partial-byte tails.
* @param blockLen - internal block size in bytes
* @param outputLen - digest size in bytes
* @param padOffset - trailing length field size in bytes
* @param isLE - whether length and state words are encoded in little-endian
* @example
* Use a concrete subclass to get the shared Merkle-Damgard update/digest flow.
* ```ts
* import { _SHA1 } from '@noble/hashes/legacy.js';
* const hash = new _SHA1();
* hash.update(new Uint8Array([97, 98, 99]));
* hash.digest();
* ```
*/
var HashMD = class {
	blockLen;
	outputLen;
	canXOF = false;
	padOffset;
	isLE;
	buffer;
	view;
	finished = false;
	length = 0;
	pos = 0;
	destroyed = false;
	constructor(blockLen, outputLen, padOffset, isLE) {
		this.blockLen = blockLen;
		this.outputLen = outputLen;
		this.padOffset = padOffset;
		this.isLE = isLE;
		this.buffer = new Uint8Array(blockLen);
		this.view = createView(this.buffer);
	}
	update(data) {
		aexists(this);
		abytes(data);
		const { view, buffer, blockLen } = this;
		const len = data.length;
		let processed = false;
		for (let pos = 0; pos < len;) {
			const take = Math.min(blockLen - this.pos, len - pos);
			if (take === blockLen) {
				const dataView = createView(data);
				for (; blockLen <= len - pos; pos += blockLen) this.process(dataView, pos);
				processed = true;
				continue;
			}
			buffer.set(pos === 0 && take === len ? data : data.subarray(pos, pos + take), this.pos);
			this.pos += take;
			pos += take;
			if (this.pos === blockLen) {
				this.process(view, 0);
				this.pos = 0;
				processed = true;
			}
		}
		this.length += data.length;
		if (processed) this.roundClean();
		return this;
	}
	digestInto(out) {
		aexists(this);
		aoutput(out, this);
		this.finished = true;
		const { buffer, view, blockLen, isLE } = this;
		let { pos } = this;
		buffer[pos++] = 128;
		buffer.fill(0, pos);
		if (this.padOffset > blockLen - pos) {
			this.process(view, 0);
			buffer.fill(0);
		}
		setU64FromNum(view, blockLen - 8, this.length * 8, isLE);
		this.process(view, 0);
		this.roundClean();
		const oview = out === buffer ? view : createView(out);
		const len = this.outputLen;
		const outLen = len / 4;
		const state = this.get();
		if (len % 4 || outLen > state.length) throw new Error("invalid outputLen");
		for (let i = 0; i < outLen; i++) oview.setUint32(4 * i, state[i], isLE);
	}
	digest() {
		const { buffer, outputLen } = this;
		this.digestInto(buffer);
		const res = buffer.slice(0, outputLen);
		this.destroy();
		return res;
	}
	_cloneIntoMeta(to) {
		const { buffer, length, finished, destroyed, pos } = this;
		to.destroyed = destroyed;
		to.finished = finished;
		to.length = length;
		to.pos = pos;
		if (pos) to.buffer.set(buffer);
		return to;
	}
	clone() {
		return this._cloneInto();
	}
};
/**
* Initial SHA-2 state: fractional parts of square roots of first 16 primes 2..53.
* Check out `test/misc/sha2-gen-iv.js` for recomputation guide.
*/
/** Initial SHA256 state from RFC 6234 §6.1: the first 32 bits of the fractional parts of the
* square roots of the first eight prime numbers. Exported as a shared table; callers must treat
* it as read-only because constructors copy words from it by index. */
const SHA256_IV = /* @__PURE__ */ Uint32Array.from([
	1779033703,
	3144134277,
	1013904242,
	2773480762,
	1359893119,
	2600822924,
	528734635,
	1541459225
]);
/** Initial SHA384 state from RFC 6234 §6.3: eight RFC 64-bit `H(0)` words stored as sixteen
* big-endian 32-bit halves. Derived from the fractional parts of the square roots of the ninth
* through sixteenth prime numbers. Exported as a shared table; callers must treat it as read-only
* because constructors copy halves from it by index. */
const SHA384_IV = /* @__PURE__ */ Uint32Array.from([
	3418070365,
	3238371032,
	1654270250,
	914150663,
	2438529370,
	812702999,
	355462360,
	4144912697,
	1731405415,
	4290775857,
	2394180231,
	1750603025,
	3675008525,
	1694076839,
	1203062813,
	3204075428
]);
//#endregion
//#region node_modules/@noble/hashes/sha2.js
/**
* SHA2 hash function. A.k.a. sha256, sha384, sha512, sha512_224, sha512_256.
* SHA256 is the fastest hash implementable in JS, even faster than Blake3.
* Check out {@link https://www.rfc-editor.org/rfc/rfc4634 | RFC 4634} and
* {@link https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf | FIPS 180-4}.
* @module
*/
/**
* SHA-224 / SHA-256 round constants from RFC 6234 §5.1: the first 32 bits
* of the cube roots of the first 64 primes (2..311).
*/
const SHA256_K = /* @__PURE__ */ Uint32Array.from([
	1116352408,
	1899447441,
	3049323471,
	3921009573,
	961987163,
	1508970993,
	2453635748,
	2870763221,
	3624381080,
	310598401,
	607225278,
	1426881987,
	1925078388,
	2162078206,
	2614888103,
	3248222580,
	3835390401,
	4022224774,
	264347078,
	604807628,
	770255983,
	1249150122,
	1555081692,
	1996064986,
	2554220882,
	2821834349,
	2952996808,
	3210313671,
	3336571891,
	3584528711,
	113926993,
	338241895,
	666307205,
	773529912,
	1294757372,
	1396182291,
	1695183700,
	1986661051,
	2177026350,
	2456956037,
	2730485921,
	2820302411,
	3259730800,
	3345764771,
	3516065817,
	3600352804,
	4094571909,
	275423344,
	430227734,
	506948616,
	659060556,
	883997877,
	958139571,
	1322822218,
	1537002063,
	1747873779,
	1955562222,
	2024104815,
	2227730452,
	2361852424,
	2428436474,
	2756734187,
	3204031479,
	3329325298
]);
/** Reusable SHA-224 / SHA-256 message schedule buffer `W_t` from RFC 6234 §6.2 step 1. */
const SHA256_W = /* @__PURE__ */ new Uint32Array(64);
/** Internal SHA-224 / SHA-256 compression engine from RFC 6234 §6.2. */
var SHA2_32B = class extends HashMD {
	A = 0;
	B = 0;
	C = 0;
	D = 0;
	E = 0;
	F = 0;
	G = 0;
	H = 0;
	constructor(outputLen, IV) {
		super(64, outputLen, 8, false);
		this.A = IV[0] | 0;
		this.B = IV[1] | 0;
		this.C = IV[2] | 0;
		this.D = IV[3] | 0;
		this.E = IV[4] | 0;
		this.F = IV[5] | 0;
		this.G = IV[6] | 0;
		this.H = IV[7] | 0;
	}
	get() {
		const { A, B, C, D, E, F, G, H } = this;
		return [
			A,
			B,
			C,
			D,
			E,
			F,
			G,
			H
		];
	}
	set(A, B, C, D, E, F, G, H) {
		this.A = A | 0;
		this.B = B | 0;
		this.C = C | 0;
		this.D = D | 0;
		this.E = E | 0;
		this.F = F | 0;
		this.G = G | 0;
		this.H = H | 0;
	}
	_cloneInto(to) {
		(to ||= new this.constructor()).set(...this.get());
		return this._cloneIntoMeta(to);
	}
	process(view, offset) {
		for (let i = 0; i < 16; i++, offset += 4) SHA256_W[i] = view.getUint32(offset, false);
		for (let i = 16; i < 64; i++) {
			const W15 = SHA256_W[i - 15];
			const W2 = SHA256_W[i - 2];
			const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
			const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
			SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
		}
		let { A, B, C, D, E, F, G, H } = this;
		for (let i = 0; i < 64; i++) {
			const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
			const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
			const T2 = (rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22)) + Maj(A, B, C) | 0;
			H = G;
			G = F;
			F = E;
			E = D + T1 | 0;
			D = C;
			C = B;
			B = A;
			A = T1 + T2 | 0;
		}
		A = A + this.A | 0;
		B = B + this.B | 0;
		C = C + this.C | 0;
		D = D + this.D | 0;
		E = E + this.E | 0;
		F = F + this.F | 0;
		G = G + this.G | 0;
		H = H + this.H | 0;
		this.set(A, B, C, D, E, F, G, H);
	}
	roundClean() {
		clean(SHA256_W);
	}
	destroy() {
		this.destroyed = true;
		this.set(0, 0, 0, 0, 0, 0, 0, 0);
		clean(this.buffer);
	}
};
/** Internal SHA-256 hash class grounded in RFC 6234 §6.2. */
var _SHA256 = class extends SHA2_32B {
	constructor() {
		super(32, SHA256_IV);
	}
};
const K512 = /* @__PURE__ */ (() => split([
	"0x428a2f98d728ae22",
	"0x7137449123ef65cd",
	"0xb5c0fbcfec4d3b2f",
	"0xe9b5dba58189dbbc",
	"0x3956c25bf348b538",
	"0x59f111f1b605d019",
	"0x923f82a4af194f9b",
	"0xab1c5ed5da6d8118",
	"0xd807aa98a3030242",
	"0x12835b0145706fbe",
	"0x243185be4ee4b28c",
	"0x550c7dc3d5ffb4e2",
	"0x72be5d74f27b896f",
	"0x80deb1fe3b1696b1",
	"0x9bdc06a725c71235",
	"0xc19bf174cf692694",
	"0xe49b69c19ef14ad2",
	"0xefbe4786384f25e3",
	"0x0fc19dc68b8cd5b5",
	"0x240ca1cc77ac9c65",
	"0x2de92c6f592b0275",
	"0x4a7484aa6ea6e483",
	"0x5cb0a9dcbd41fbd4",
	"0x76f988da831153b5",
	"0x983e5152ee66dfab",
	"0xa831c66d2db43210",
	"0xb00327c898fb213f",
	"0xbf597fc7beef0ee4",
	"0xc6e00bf33da88fc2",
	"0xd5a79147930aa725",
	"0x06ca6351e003826f",
	"0x142929670a0e6e70",
	"0x27b70a8546d22ffc",
	"0x2e1b21385c26c926",
	"0x4d2c6dfc5ac42aed",
	"0x53380d139d95b3df",
	"0x650a73548baf63de",
	"0x766a0abb3c77b2a8",
	"0x81c2c92e47edaee6",
	"0x92722c851482353b",
	"0xa2bfe8a14cf10364",
	"0xa81a664bbc423001",
	"0xc24b8b70d0f89791",
	"0xc76c51a30654be30",
	"0xd192e819d6ef5218",
	"0xd69906245565a910",
	"0xf40e35855771202a",
	"0x106aa07032bbd1b8",
	"0x19a4c116b8d2d0c8",
	"0x1e376c085141ab53",
	"0x2748774cdf8eeb99",
	"0x34b0bcb5e19b48a8",
	"0x391c0cb3c5c95a63",
	"0x4ed8aa4ae3418acb",
	"0x5b9cca4f7763e373",
	"0x682e6ff3d6b2b8a3",
	"0x748f82ee5defb2fc",
	"0x78a5636f43172f60",
	"0x84c87814a1f0ab72",
	"0x8cc702081a6439ec",
	"0x90befffa23631e28",
	"0xa4506cebde82bde9",
	"0xbef9a3f7b2c67915",
	"0xc67178f2e372532b",
	"0xca273eceea26619c",
	"0xd186b8c721c0c207",
	"0xeada7dd6cde0eb1e",
	"0xf57d4f7fee6ed178",
	"0x06f067aa72176fba",
	"0x0a637dc5a2c898a6",
	"0x113f9804bef90dae",
	"0x1b710b35131c471b",
	"0x28db77f523047d84",
	"0x32caab7b40c72493",
	"0x3c9ebe0a15c9bebc",
	"0x431d67c49c100d4c",
	"0x4cc5d4becb3e42b6",
	"0x597f299cfc657e2a",
	"0x5fcb6fab3ad6faec",
	"0x6c44198c4a475817"
].map((n) => BigInt(n))))();
const SHA512_Kh = /* @__PURE__ */ (() => K512[0])();
const SHA512_Kl = /* @__PURE__ */ (() => K512[1])();
const SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
const SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);
/** Internal SHA-384 / SHA-512 compression engine from RFC 6234 §6.4. */
var SHA2_64B = class extends HashMD {
	Ah = 0;
	Al = 0;
	Bh = 0;
	Bl = 0;
	Ch = 0;
	Cl = 0;
	Dh = 0;
	Dl = 0;
	Eh = 0;
	El = 0;
	Fh = 0;
	Fl = 0;
	Gh = 0;
	Gl = 0;
	Hh = 0;
	Hl = 0;
	constructor(outputLen, IV) {
		super(128, outputLen, 16, false);
		this.Ah = IV[0] | 0;
		this.Al = IV[1] | 0;
		this.Bh = IV[2] | 0;
		this.Bl = IV[3] | 0;
		this.Ch = IV[4] | 0;
		this.Cl = IV[5] | 0;
		this.Dh = IV[6] | 0;
		this.Dl = IV[7] | 0;
		this.Eh = IV[8] | 0;
		this.El = IV[9] | 0;
		this.Fh = IV[10] | 0;
		this.Fl = IV[11] | 0;
		this.Gh = IV[12] | 0;
		this.Gl = IV[13] | 0;
		this.Hh = IV[14] | 0;
		this.Hl = IV[15] | 0;
	}
	get() {
		const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
		return [
			Ah,
			Al,
			Bh,
			Bl,
			Ch,
			Cl,
			Dh,
			Dl,
			Eh,
			El,
			Fh,
			Fl,
			Gh,
			Gl,
			Hh,
			Hl
		];
	}
	set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
		this.Ah = Ah | 0;
		this.Al = Al | 0;
		this.Bh = Bh | 0;
		this.Bl = Bl | 0;
		this.Ch = Ch | 0;
		this.Cl = Cl | 0;
		this.Dh = Dh | 0;
		this.Dl = Dl | 0;
		this.Eh = Eh | 0;
		this.El = El | 0;
		this.Fh = Fh | 0;
		this.Fl = Fl | 0;
		this.Gh = Gh | 0;
		this.Gl = Gl | 0;
		this.Hh = Hh | 0;
		this.Hl = Hl | 0;
	}
	_cloneInto(to) {
		(to ||= new this.constructor()).set(...this.get());
		return this._cloneIntoMeta(to);
	}
	process(view, offset) {
		for (let i = 0; i < 16; i++, offset += 4) {
			SHA512_W_H[i] = view.getUint32(offset);
			SHA512_W_L[i] = view.getUint32(offset += 4);
		}
		for (let i = 16; i < 80; i++) {
			const W15h = SHA512_W_H[i - 15] | 0;
			const W15l = SHA512_W_L[i - 15] | 0;
			const s0h = rotrSH(W15h, W15l, 1) ^ rotrSH(W15h, W15l, 8) ^ shrSH(W15h, W15l, 7);
			const s0l = rotrSL(W15h, W15l, 1) ^ rotrSL(W15h, W15l, 8) ^ shrSL(W15h, W15l, 7);
			const W2h = SHA512_W_H[i - 2] | 0;
			const W2l = SHA512_W_L[i - 2] | 0;
			const s1h = rotrSH(W2h, W2l, 19) ^ rotrBH(W2h, W2l, 61) ^ shrSH(W2h, W2l, 6);
			const s1l = rotrSL(W2h, W2l, 19) ^ rotrBL(W2h, W2l, 61) ^ shrSL(W2h, W2l, 6);
			const SUMl = add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
			const SUMh = add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
			SHA512_W_H[i] = SUMh | 0;
			SHA512_W_L[i] = SUMl | 0;
		}
		let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
		for (let i = 0; i < 80; i++) {
			const sigma1h = rotrSH(Eh, El, 14) ^ rotrSH(Eh, El, 18) ^ rotrBH(Eh, El, 41);
			const sigma1l = rotrSL(Eh, El, 14) ^ rotrSL(Eh, El, 18) ^ rotrBL(Eh, El, 41);
			const CHIh = Eh & Fh ^ ~Eh & Gh;
			const CHIl = El & Fl ^ ~El & Gl;
			const T1ll = add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
			const T1h = add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
			const T1l = T1ll | 0;
			const sigma0h = rotrSH(Ah, Al, 28) ^ rotrBH(Ah, Al, 34) ^ rotrBH(Ah, Al, 39);
			const sigma0l = rotrSL(Ah, Al, 28) ^ rotrBL(Ah, Al, 34) ^ rotrBL(Ah, Al, 39);
			const MAJh = Ah & Bh ^ Ah & Ch ^ Bh & Ch;
			const MAJl = Al & Bl ^ Al & Cl ^ Bl & Cl;
			Hh = Gh | 0;
			Hl = Gl | 0;
			Gh = Fh | 0;
			Gl = Fl | 0;
			Fh = Eh | 0;
			Fl = El | 0;
			({h: Eh, l: El} = add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
			Dh = Ch | 0;
			Dl = Cl | 0;
			Ch = Bh | 0;
			Cl = Bl | 0;
			Bh = Ah | 0;
			Bl = Al | 0;
			const All = add3L(T1l, sigma0l, MAJl);
			Ah = add3H(All, T1h, sigma0h, MAJh);
			Al = All | 0;
		}
		({h: Ah, l: Al} = add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
		({h: Bh, l: Bl} = add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
		({h: Ch, l: Cl} = add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
		({h: Dh, l: Dl} = add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
		({h: Eh, l: El} = add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
		({h: Fh, l: Fl} = add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
		({h: Gh, l: Gl} = add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
		({h: Hh, l: Hl} = add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
		this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
	}
	roundClean() {
		clean(SHA512_W_H, SHA512_W_L);
	}
	destroy() {
		this.destroyed = true;
		clean(this.buffer);
		this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	}
};
/** Internal SHA-384 hash class grounded in RFC 6234 §6.3 and §6.4. */
var _SHA384 = class extends SHA2_64B {
	constructor() {
		super(48, SHA384_IV);
	}
};
//#endregion
//#region packages/scan-core/src/tls/keyschedule.ts
/**
* The TLS 1.3 key schedule (RFC 8446 §7.1) without PSKs.
*
*            0
*            |
*   0 ──► HKDF-Extract = Early Secret
*            |
*     Derive-Secret(., "derived", "")
*            |
*  (EC)DHE / KEM shared secret ──► HKDF-Extract = Handshake Secret
*            |    ├─► "c hs traffic"   protects the client's handshake messages
*            |    └─► "s hs traffic"   protects Certificate, CertificateVerify, Finished
*     Derive-Secret(., "derived", "")
*            |
*   0 ──► HKDF-Extract = Master Secret
*                 ├─► "c ap traffic"   protects what the client sends afterwards
*                 └─► "s ap traffic"   protects what the server sends afterwards
*
* The scanner uses this to decrypt a server's handshake flight; the learning
* pages use the same functions to show a login's keys being derived. It is
* checked against the RFC 8448 trace. Runs in Node and in browsers.
*/
const HASHES = {
	sha256: /* @__PURE__ */ createHasher(() => new _SHA256(), /* @__PURE__ */ oidNist(1)),
	sha384: /* @__PURE__ */ createHasher(() => new _SHA384(), /* @__PURE__ */ oidNist(2))
};
const HASH_LENGTH = {
	sha256: 32,
	sha384: 48
};
const encoder = new TextEncoder();
const EMPTY = /* @__PURE__ */ new Uint8Array(0);
function transcriptHash(hash, ...messages) {
	const h = HASHES[hash].create();
	for (const message of messages) h.update(message);
	return h.digest();
}
/** HKDF-Expand-Label (RFC 8446 §7.1): the label is prefixed with "tls13 " and bound to a context and length. */
function hkdfExpandLabel(hash, secret, label, context, length) {
	const fullLabel = encoder.encode(`tls13 ${label}`);
	const info = new Uint8Array(3 + fullLabel.length + 1 + context.length);
	info[0] = length >> 8;
	info[1] = length & 255;
	info[2] = fullLabel.length;
	info.set(fullLabel, 3);
	info[3 + fullLabel.length] = context.length;
	info.set(context, 4 + fullLabel.length);
	return expand(HASHES[hash], secret, info, length);
}
/** Derive-Secret(secret, label, messages) with the transcript hash already computed. */
function deriveSecret(hash, secret, label, transcript) {
	return hkdfExpandLabel(hash, secret, label, transcript, HASH_LENGTH[hash]);
}
/**
* @param sharedSecret what key establishment produced (for a hybrid group, the concatenation of both parts)
* @param helloHash    transcript hash of ClientHello..ServerHello
*/
function handshakeSecrets(hash, sharedSecret, helloHash) {
	const zeros = new Uint8Array(HASH_LENGTH[hash]);
	const emptyHash = transcriptHash(hash);
	const earlySecret = extract(HASHES[hash], zeros, zeros);
	const handshakeSecret = extract(HASHES[hash], sharedSecret, deriveSecret(hash, earlySecret, "derived", emptyHash));
	return {
		handshakeSecret,
		clientHandshakeTraffic: deriveSecret(hash, handshakeSecret, "c hs traffic", helloHash),
		serverHandshakeTraffic: deriveSecret(hash, handshakeSecret, "s hs traffic", helloHash)
	};
}
function trafficKeys(hash, trafficSecret, keyLength) {
	return {
		key: hkdfExpandLabel(hash, trafficSecret, "key", EMPTY, keyLength),
		iv: hkdfExpandLabel(hash, trafficSecret, "iv", EMPTY, 12)
	};
}
/** The value a Finished message must carry: an HMAC over the transcript, keyed from the sender's traffic secret. */
function finishedVerifyData(hash, trafficSecret, transcript) {
	const finishedKey = hkdfExpandLabel(hash, trafficSecret, "finished", EMPTY, HASH_LENGTH[hash]);
	return hmac(HASHES[hash], finishedKey, transcript);
}
/** Per-record nonce (RFC 8446 §5.3): the 64-bit record sequence number XORed into the end of the IV. */
function recordNonce(iv, sequence) {
	const nonce = Uint8Array.from(iv);
	let n = sequence;
	for (let i = nonce.length - 1; i >= 0 && n > 0; i--) {
		nonce[i] ^= n & 255;
		n = Math.floor(n / 256);
	}
	return nonce;
}
/** The bytes a server signs in CertificateVerify (RFC 8446 §4.4.3). */
function certificateVerifyInput(transcript) {
	const context = encoder.encode("TLS 1.3, server CertificateVerify");
	const out = new Uint8Array(64 + context.length + 1 + transcript.length);
	out.fill(32, 0, 64);
	out.set(context, 64);
	out.set(transcript, 64 + context.length + 1);
	return out;
}
//#endregion
//#region packages/scan-core/src/tls/handshake.ts
/**
* Reads a server's side of a TLS handshake and records what it shows.
*
* This is a measuring instrument (ADR 0006). It takes the bytes a server sent
* in reply to one ClientHello and extracts: the version, cipher suite and
* key-exchange group from the ServerHello; for TLS 1.3, the certificate chain
* and CertificateVerify from the encrypted flight, which it can read because
* it completed the key exchange; for TLS 1.2, the same from the plaintext
* Certificate and ServerKeyExchange. It checks the server's signature and
* Finished MAC, and never sends anything after the ClientHello.
*
* It does no I/O, so a recorded handshake can be replayed through it in tests.
*/
const HELLO_RETRY_RANDOM = Buffer.from("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c", "hex");
const AEAD = {
	"AES-128-GCM": {
		algorithm: "aes-128-gcm",
		keyLength: 16
	},
	"AES-256-GCM": {
		algorithm: "aes-256-gcm",
		keyLength: 32
	},
	"CHACHA20-POLY1305": {
		algorithm: "chacha20-poly1305",
		keyLength: 32
	}
};
var HandshakeObserver = class {
	observation = { outcome: "closed" };
	clientHello;
	keyShares;
	records = new RecordReader();
	plain = new HandshakeReader();
	decrypted = new HandshakeReader();
	transcript;
	state = "hello";
	sawBytes = false;
	serverRandom = Buffer.alloc(0);
	protection;
	constructor(clientHello, keyShares) {
		this.clientHello = clientHello;
		this.keyShares = keyShares;
		this.transcript = [clientHello.message];
	}
	get done() {
		return this.state === "done";
	}
	/** Feeds bytes from the server. Returns true once there is nothing more to learn from this connection. */
	push(chunk) {
		if (this.done) return true;
		try {
			this.records.push(chunk);
			for (let record = this.records.next(); record && !this.done; record = this.records.next()) {
				this.sawBytes = true;
				this.onRecord(record);
			}
		} catch (error) {
			const detail = error instanceof WireError ? error.message : `parser error: ${error instanceof Error ? error.message : String(error)}`;
			this.finish(this.sawBytes ? "malformed" : "not-tls", detail);
		}
		return this.done;
	}
	/** The connection ended (or the scanner gave up) before the handshake did. */
	end(reason, detail) {
		if (this.done) return;
		const waitedFor = this.state === "hello" ? void 0 : `after the ServerHello: ${detail ?? (reason === "timeout" ? "timed out" : "connection closed")}`;
		this.finish(waitedFor ? "server-hello" : reason, waitedFor ?? detail);
	}
	finish(outcome, detail) {
		this.observation.outcome = outcome;
		if (detail) this.observation.detail = detail;
		this.state = "done";
	}
	onRecord(record) {
		switch (record.type) {
			case CONTENT_TYPE.changeCipherSpec: return;
			case CONTENT_TYPE.alert: return this.onAlert(record.fragment);
			case CONTENT_TYPE.handshake:
				if (this.state === "tls13") throw new WireError("plaintext handshake record after a TLS 1.3 ServerHello");
				this.plain.push(record.fragment);
				for (let message = this.plain.next(); message && !this.done; message = this.plain.next()) this.onPlainMessage(message);
				return;
			case CONTENT_TYPE.applicationData: {
				if (this.state !== "tls13" || !this.protection) throw new WireError("encrypted record before a TLS 1.3 ServerHello");
				const inner = this.decrypt(record, this.protection);
				if (inner.type === CONTENT_TYPE.alert) return this.onAlert(inner.content);
				if (inner.type !== CONTENT_TYPE.handshake) throw new WireError(`unexpected content type ${inner.type} in the handshake`);
				this.decrypted.push(inner.content);
				for (let message = this.decrypted.next(); message && !this.done; message = this.decrypted.next()) this.onEncryptedMessage(message);
				return;
			}
		}
	}
	onAlert(fragment) {
		if (fragment.length < 2) throw new WireError("truncated alert");
		const [level, description] = [fragment[0], fragment[1]];
		this.observation.alert = {
			level,
			description,
			name: alertName(description)
		};
		this.finish(this.state === "hello" ? "alert" : "server-hello", this.state === "hello" ? void 0 : `server sent ${alertName(description)} after its ServerHello`);
	}
	onPlainMessage(message) {
		if (this.state === "hello") {
			if (message.type !== HANDSHAKE_TYPE.serverHello) throw new WireError(`expected a ServerHello, got handshake type ${message.type}`);
			return this.onServerHello(message);
		}
		const body = new Reader(message.body);
		switch (message.type) {
			case HANDSHAKE_TYPE.certificate: {
				const list = new Reader(body.vector(3));
				const certificates = [];
				while (list.remaining > 0) certificates.push(Buffer.from(list.vector(3)));
				this.observation.certificates = certificates;
				return;
			}
			case HANDSHAKE_TYPE.serverKeyExchange: return this.onServerKeyExchange(message.body);
			case HANDSHAKE_TYPE.certificateRequest:
				this.observation.clientCertificateRequested = true;
				return;
			case HANDSHAKE_TYPE.serverHelloDone: return this.finish("handshake");
			default: return;
		}
	}
	onServerHello(message) {
		const body = new Reader(message.body);
		const legacyVersion = body.u16();
		const random = body.bytes(32);
		body.vector(1);
		const cipherSuite = body.u16();
		body.u8();
		let selectedVersion;
		let share;
		if (body.remaining > 0) {
			const extensions = new Reader(body.vector(2));
			while (extensions.remaining > 0) {
				const type = extensions.u16();
				const data = new Reader(extensions.vector(2));
				if (type === EXTENSION.supportedVersions) selectedVersion = data.u16();
				else if (type === EXTENSION.keyShare) share = {
					group: data.u16(),
					keyExchange: data.remaining > 0 ? data.vector(2) : void 0
				};
				else if (type === EXTENSION.alpn) this.observation.alpn = readAlpn(data);
			}
		}
		const version = selectedVersion ?? legacyVersion;
		Object.assign(this.observation, {
			version,
			cipherSuite
		});
		this.serverRandom = Buffer.from(random);
		if (random.equals(HELLO_RETRY_RANDOM)) {
			if (!share) throw new WireError("HelloRetryRequest without a key_share extension");
			this.observation.group = share.group;
			return this.finish("hello-retry-request");
		}
		if (version !== 772) {
			this.state = "tls12";
			return;
		}
		if (!share?.keyExchange) throw new WireError("TLS 1.3 ServerHello without a key share");
		this.observation.group = share.group;
		this.transcript.push(message.raw);
		const suite = CIPHER_SUITES[cipherSuite];
		const aead = suite?.protocol === "1.3" ? AEAD[suite.cipher] : void 0;
		if (!suite || !aead || suite.hash === "sha1") return this.finish("server-hello", "the server chose a cipher suite this scanner cannot decrypt");
		const ours = this.keyShares.find((k) => k.group === share.group);
		if (!ours) throw new WireError("the server answered in a group no key share was sent for, without a HelloRetryRequest");
		const secrets = handshakeSecrets(suite.hash, ours.sharedSecret(share.keyExchange), transcriptHash(suite.hash, ...this.transcript));
		this.protection = {
			hash: suite.hash,
			algorithm: aead.algorithm,
			...trafficKeys(suite.hash, secrets.serverHandshakeTraffic, aead.keyLength),
			serverTrafficSecret: secrets.serverHandshakeTraffic,
			sequence: 0
		};
		this.state = "tls13";
	}
	onServerKeyExchange(raw) {
		const suite = CIPHER_SUITES[this.observation.cipherSuite ?? -1];
		const body = new Reader(raw);
		let paramsLength;
		if (suite?.keyExchange === "ECDHE") {
			if (body.u8() !== 3) return;
			this.observation.group = body.u16();
			body.vector(1);
			paramsLength = raw.length - body.remaining;
		} else if (suite?.keyExchange === "DHE") {
			const prime = body.vector(2);
			body.vector(2);
			body.vector(2);
			this.observation.dhPrimeBits = bitLength(prime);
			paramsLength = raw.length - body.remaining;
		} else return;
		if (body.remaining < 4) return;
		const scheme = body.u16();
		const signature = body.vector(2);
		this.observation.signatureScheme = scheme;
		const signed = Buffer.concat([
			this.clientHello.random,
			this.serverRandom,
			raw.subarray(0, paramsLength)
		]);
		this.observation.signatureValid = this.verifyLeafSignature(scheme, signed, signature, false);
	}
	decrypt(record, protection) {
		if (record.fragment.length < 17) throw new WireError("encrypted record too short");
		const tagAt = record.fragment.length - 16;
		const decipher = crypto.createDecipheriv(protection.algorithm, protection.key, recordNonce(protection.iv, protection.sequence++), { authTagLength: 16 });
		decipher.setAAD(record.header, { plaintextLength: tagAt });
		decipher.setAuthTag(record.fragment.subarray(tagAt));
		let plaintext;
		try {
			plaintext = Buffer.concat([decipher.update(record.fragment.subarray(0, tagAt)), decipher.final()]);
		} catch {
			throw new WireError("the server’s handshake records did not decrypt with the negotiated keys");
		}
		let end = plaintext.length;
		while (end > 0 && plaintext[end - 1] === 0) end--;
		if (end === 0) throw new WireError("encrypted record with no content type");
		return {
			type: plaintext[end - 1],
			content: plaintext.subarray(0, end - 1)
		};
	}
	onEncryptedMessage(message) {
		const { hash, serverTrafficSecret } = this.protection;
		const body = new Reader(message.body);
		switch (message.type) {
			case HANDSHAKE_TYPE.encryptedExtensions: {
				const extensions = new Reader(body.vector(2));
				while (extensions.remaining > 0) {
					const type = extensions.u16();
					const data = new Reader(extensions.vector(2));
					if (type === EXTENSION.alpn) this.observation.alpn = readAlpn(data);
					else if (type === EXTENSION.supportedGroups) {
						const list = new Reader(data.vector(2));
						const groups = [];
						while (list.remaining >= 2) groups.push(list.u16());
						this.observation.serverGroups = groups;
					}
				}
				break;
			}
			case HANDSHAKE_TYPE.certificateRequest:
				this.observation.clientCertificateRequested = true;
				break;
			case HANDSHAKE_TYPE.certificate: {
				body.vector(1);
				const list = new Reader(body.vector(3));
				const certificates = [];
				while (list.remaining > 0) {
					certificates.push(Buffer.from(list.vector(3)));
					list.vector(2);
				}
				this.observation.certificates = certificates;
				break;
			}
			case HANDSHAKE_TYPE.certificateVerify: {
				const scheme = body.u16();
				const signature = body.vector(2);
				this.observation.signatureScheme = scheme;
				const signed = Buffer.from(certificateVerifyInput(transcriptHash(hash, ...this.transcript)));
				this.observation.signatureValid = this.verifyLeafSignature(scheme, signed, signature, true);
				break;
			}
			case HANDSHAKE_TYPE.finished: {
				const expected = finishedVerifyData(hash, serverTrafficSecret, transcriptHash(hash, ...this.transcript));
				this.observation.finishedValid = message.body.length === expected.length && crypto.timingSafeEqual(message.body, expected);
				return this.finish("handshake");
			}
		}
		this.transcript.push(message.raw);
	}
	/** True or false when the check could be made; undefined when the key or scheme is one this scanner cannot use. */
	verifyLeafSignature(schemeId, data, signature, tls13) {
		const scheme = SIGNATURE_SCHEMES[schemeId];
		const leaf = this.observation.certificates?.[0];
		if (!scheme || !leaf) return void 0;
		let key;
		try {
			key = new crypto.X509Certificate(leaf).publicKey;
		} catch {
			return;
		}
		const type = key.asymmetricKeyType ?? "";
		try {
			switch (scheme.family) {
				case "RSA": {
					if (type !== "rsa" && type !== "rsa-pss") return false;
					const padding = scheme.padding === "pss" ? crypto.constants.RSA_PKCS1_PSS_PADDING : crypto.constants.RSA_PKCS1_PADDING;
					return crypto.verify(scheme.hash, data, {
						key,
						padding,
						saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
					}, signature);
				}
				case "ECDSA":
					if (type !== "ec") return false;
					if (tls13 && scheme.curve && key.asymmetricKeyDetails?.namedCurve !== scheme.curve) return false;
					return crypto.verify(scheme.hash, data, key, signature);
				case "EdDSA": return type === scheme.name && crypto.verify(null, data, key, signature);
				case "ML-DSA": return type === scheme.name.replace("mldsa", "ml-dsa-") && crypto.verify(null, data, key, signature);
			}
		} catch {
			return false;
		}
	}
};
function readAlpn(data) {
	const list = new Reader(data.vector(2));
	return list.remaining > 0 ? list.vector(1).toString("ascii") : void 0;
}
function bitLength(value) {
	let i = 0;
	while (i < value.length && value[i] === 0) i++;
	if (i === value.length) return 0;
	return (value.length - i) * 8 - Math.clz32(value[i]) + 24;
}
//#endregion
//#region packages/scan-core/src/tls/observe.ts
/**
* Sends one ClientHello to a pinned target and returns what the server showed.
* One call is one TCP connection. The connection is closed as soon as the
* server's flight has been read; nothing is sent after the ClientHello.
*/
/** A server's flight is a few kilobytes; ML-DSA chains reach tens. Past this the peer is not behaving like a TLS server. */
const MAX_BYTES = 524288;
async function observeHandshake(pinned, spec, options = {}) {
	const left = (options.deadline ?? Infinity) - Date.now();
	if (left <= 0) return {
		outcome: "timeout",
		detail: "the scan ran out of time before this handshake"
	};
	let socket;
	try {
		socket = await connectPinned(pinned, Math.min(options.connectTimeoutMs ?? 5e3, left));
	} catch (error) {
		if (error instanceof ConnectError) return {
			outcome: "unreachable",
			detail: error.message
		};
		throw error;
	}
	const hello = buildClientHello({
		...spec,
		serverName: pinned.hasHostname ? pinned.hostname : void 0
	});
	const observer = new HandshakeObserver(hello, spec.keyShares);
	return new Promise((resolve) => {
		let received = 0;
		const finish = () => {
			clearTimeout(timer);
			socket.destroy();
			resolve(observer.observation);
		};
		const timer = setTimeout(() => {
			observer.end("timeout");
			finish();
		}, Math.min(options.handshakeTimeoutMs ?? 6e3, left));
		socket.on("data", (chunk) => {
			received += chunk.length;
			if (received > MAX_BYTES) observer.end("closed", "the server sent more data than a TLS handshake needs");
			else observer.push(chunk);
			if (observer.done) finish();
		});
		socket.on("error", (error) => {
			observer.end("closed", error.code === "ECONNRESET" ? "the server reset the connection" : error.message);
			finish();
		});
		socket.on("close", () => {
			observer.end("closed");
			finish();
		});
		socket.write(record(CONTENT_TYPE.handshake, 769, hello.message));
	});
}
//#endregion
//#region packages/scan-core/src/tls/probes.ts
/**
* The set of handshakes one scan performs, and why each exists:
*
*   pq-capable-client   what a client that supports post-quantum key exchange gets: hybrid offered first
*   classical-client    what a client with no post-quantum support gets
*   classical-kex-client  only when the certificate is post-quantum and the classical client got no
*                       ServerHello: the same, but still offering ML-DSA signatures, so a refusal
*                       can only be about the key exchange
*   tls12-client        whether TLS 1.2 is still accepted, and its key exchange
*   group-N             one per post-quantum group: does the server accept it at all?
*
*   classical-sig-client  the mirror of that: post-quantum groups, classical signatures only, to see
*                       whether a classical certificate is still handed out
*
* Probes run one after another, each on its own connection to the pinned
* address: around eight short handshakes per scan. A handshake whose
* connection was cut is tried once more, since one cut connection shows nothing.
*/
const CLASSICAL_GROUPS = [
	GROUP.x25519,
	GROUP.secp256r1,
	GROUP.secp384r1
];
const PLANS = {
	"pq-capable-client": {
		id: "pq-capable-client",
		purpose: "A client that supports post-quantum key exchange and ML-DSA signatures",
		versions: ["1.3", "1.2"],
		groups: [
			GROUP.X25519MLKEM768,
			GROUP.x25519,
			GROUP.secp256r1,
			GROUP.SecP256r1MLKEM768,
			GROUP.SecP384r1MLKEM1024,
			GROUP.MLKEM768,
			GROUP.MLKEM1024,
			GROUP.secp384r1
		],
		shareGroups: [GROUP.X25519MLKEM768, GROUP.x25519],
		signatureSchemes: SIGNATURE_SCHEMES_WITH_PQ
	},
	"classical-client": {
		id: "classical-client",
		purpose: "A client with no post-quantum support",
		versions: ["1.3", "1.2"],
		groups: CLASSICAL_GROUPS,
		shareGroups: [GROUP.x25519, GROUP.secp256r1],
		signatureSchemes: SIGNATURE_SCHEMES_CLASSICAL
	},
	"tls12-client": {
		id: "tls12-client",
		purpose: "A client that only speaks TLS 1.2",
		versions: ["1.2"],
		groups: CLASSICAL_GROUPS,
		shareGroups: [],
		signatureSchemes: SIGNATURE_SCHEMES_CLASSICAL
	}
};
/**
* The classical client leaves out post-quantum groups and ML-DSA signature schemes together. A server with a
* post-quantum certificate refuses it for the signatures alone, whatever groups it accepts. This plan changes
* the key exchange only.
*/
const CLASSICAL_KEX_PLAN = {
	id: "classical-kex-client",
	purpose: "A client that accepts ML-DSA signatures but has no post-quantum key exchange",
	versions: ["1.3"],
	groups: CLASSICAL_GROUPS,
	shareGroups: [GROUP.x25519, GROUP.secp256r1],
	signatureSchemes: SIGNATURE_SCHEMES_WITH_PQ
};
/**
* And the other way round: the main handshake's groups, without ML-DSA. A server that holds a classical
* certificate next to a post-quantum one hands the classical one to this client, even when it refuses every
* handshake that lacks post-quantum key exchange.
*/
const CLASSICAL_SIG_PLAN = {
	id: "classical-sig-client",
	purpose: "A client with post-quantum key exchange that accepts only classical signatures",
	versions: ["1.3"],
	groups: PLANS["pq-capable-client"].groups,
	shareGroups: PLANS["pq-capable-client"].shareGroups,
	signatureSchemes: SIGNATURE_SCHEMES_CLASSICAL
};
const toSpec = (plan) => ({
	versions: plan.versions,
	groups: plan.groups,
	keyShares: plan.shareGroups.map(generateKeyShare),
	signatureSchemes: plan.signatureSchemes,
	alpn: ["h2", "http/1.1"]
});
/** The kind of key a leaf certificate carries, or undefined when the bytes are not a certificate. */
function leafKey(der) {
	try {
		const { algorithm, family, quantumSafe } = summarizeCertificate(der, 0).key;
		return {
			algorithm,
			family,
			quantumSafe
		};
	} catch {
		return;
	}
}
async function run(pinned, plan, options) {
	const started = Date.now();
	let seen = await observeHandshake(pinned, toSpec(plan), options);
	let retried = false;
	let confirmed;
	if (seen.outcome === "closed") {
		const again = await observeHandshake(pinned, toSpec(plan), options);
		if (again.outcome === "closed") confirmed = true;
		else if (again.outcome !== "timeout" && again.outcome !== "unreachable") seen = again;
	}
	if (seen.outcome === "hello-retry-request" && plan.shareGroups.length > 0 && seen.group !== void 0 && canGenerateKeyShare(seen.group)) {
		seen = await observeHandshake(pinned, toSpec({
			...plan,
			shareGroups: [seen.group]
		}), options);
		retried = true;
	}
	const { certificates, alert, ...rest } = seen;
	const leaf = certificates?.[0];
	return {
		seen,
		result: {
			id: plan.id,
			purpose: plan.purpose,
			offered: {
				versions: plan.versions,
				groups: plan.groups,
				keyShares: plan.shareGroups
			},
			...rest,
			alert: alert?.name,
			leafFingerprint: leaf ? crypto.createHash("sha256").update(leaf).digest("hex") : void 0,
			leafKey: leaf ? leafKey(leaf) : void 0,
			confirmed,
			retried: retried || void 0,
			durationMs: Date.now() - started
		}
	};
}
async function probeTls(pinned, options = {}) {
	const probes = [];
	const progress = options.onProgress ?? (() => {});
	progress("TLS handshake as a post-quantum-capable client");
	const main = await run(pinned, PLANS["pq-capable-client"], options);
	probes.push(main.result);
	if (main.seen.outcome === "unreachable") return {
		probes,
		groupSupport: [],
		certificates: [],
		reachable: false
	};
	progress("TLS handshake as a client without post-quantum support");
	const classical = await run(pinned, PLANS["classical-client"], options);
	probes.push(classical.result);
	const silent = (p) => [
		"timeout",
		"closed",
		"not-tls",
		"unreachable"
	].includes(p.seen.outcome);
	if (silent(main) && silent(classical)) return {
		probes,
		groupSupport: [],
		certificates: [],
		reachable: true
	};
	progress("TLS 1.2 handshake");
	const legacy = await run(pinned, PLANS["tls12-client"], options);
	probes.push(legacy.result);
	if (main.result.leafKey?.quantumSafe && !["handshake", "server-hello"].includes(classical.seen.outcome)) {
		progress("TLS handshake with classical key exchange and ML-DSA signatures");
		probes.push((await run(pinned, CLASSICAL_KEX_PLAN, options)).result);
	}
	if (main.result.leafKey?.quantumSafe && !classical.result.leafFingerprint && !legacy.result.leafFingerprint) {
		progress("TLS handshake with post-quantum key exchange and classical signatures");
		probes.push((await run(pinned, CLASSICAL_SIG_PLAN, options)).result);
	}
	const groupSupport = [];
	const speaks13 = [main, classical].some((p) => p.seen.version === 772);
	let unanswered = 0;
	for (const group of PQ_GROUPS_TO_ENUMERATE) {
		const info = GROUPS[group];
		const base = {
			group,
			name: info.name,
			kex: info.kex
		};
		if (main.seen.group === group && main.seen.version === 772) {
			groupSupport.push({
				...base,
				supported: true,
				evidence: "negotiated in the main handshake"
			});
			continue;
		}
		if (!speaks13) {
			groupSupport.push({
				...base,
				supported: false,
				evidence: "the server did not negotiate TLS 1.3"
			});
			continue;
		}
		if (unanswered >= 2) {
			groupSupport.push({
				...base,
				supported: void 0,
				evidence: "not asked: the server stopped answering these questions"
			});
			continue;
		}
		progress(`Asking whether ${info.name} is supported`);
		const asked = await run(pinned, {
			id: `group-${group}`,
			purpose: `Offers only ${info.name}, with no key share, to see whether the server asks for one`,
			versions: ["1.3"],
			groups: [group],
			shareGroups: [],
			signatureSchemes: SIGNATURE_SCHEMES_WITH_PQ
		}, options);
		probes.push(asked.result);
		const { outcome } = asked.seen;
		if (outcome === "hello-retry-request" && asked.seen.group === group) groupSupport.push({
			...base,
			supported: true,
			evidence: `HelloRetryRequest selecting ${groupName(group)}`
		});
		else if (outcome === "alert") groupSupport.push({
			...base,
			supported: false,
			evidence: `refused with alert ${asked.seen.alert?.name}`
		});
		else if (outcome === "closed" && asked.result.confirmed) groupSupport.push({
			...base,
			supported: false,
			evidence: `refused: the connection was ${asked.seen.detail ? "reset" : "closed"} without a TLS alert, twice`
		});
		else {
			unanswered++;
			groupSupport.push({
				...base,
				supported: void 0,
				evidence: `no usable answer (${outcome}${asked.seen.detail ? `: ${asked.seen.detail}` : ""})`
			});
		}
	}
	return {
		probes,
		groupSupport,
		certificates: [
			main,
			classical,
			legacy
		].map((p) => p.seen.certificates).find((c) => c && c.length > 0) ?? [],
		reachable: true
	};
}
//#endregion
//#region packages/scan-core/src/scan.ts
/**
* One scan, start to finish:
*
*   parse and check the address  →  resolve once, pin an address
*   →  HTTPS GET with hand-followed redirects; if that page is not a
*      sign-in, look for one: the site's own "Sign in" link, then the usual
*      paths. The origin that serves the sign-in is what the rest of the
*      scan is about. (Where its form posts to is not followed.)
*   →  TLS handshakes (probes.ts)  →  certificate summary  →  plain-HTTP check
*   →  OpenID Connect metadata and keys
*   →  findings (assess.ts)
*
* Every address the scanner goes on to, found or redirected to, is put
* through the same policy, resolution and pinning as the one it was given.
* The whole thing works against a deadline. A step that would start too late
* is skipped and the report says so, rather than the scan hanging.
*/
const TRUST_STORE = `the CA certificates shipped with Node.js ${process.version} (Mozilla’s list)`;
/** How many places the scanner will fetch looking for a sign-in it was not given. */
const MAX_SIGN_IN_FETCHES = 3;
const NO_OIDC = {
	found: false,
	tried: []
};
/** Fetches an address through the policy and classifies the page. Pins are shared, so an origin is resolved once. */
async function land(target, pins, policy, lookup, deadline) {
	let pinned = pins.get(target.origin);
	if (!pinned) pins.set(target.origin, pinned = await resolveTarget(target, { lookup }));
	const follow = await fetchFollowingRedirects(target, pinned, policy, {
		lookup,
		deadline,
		maxBytes: 262144
	});
	for (const hop of follow.responses) pins.set(hop.target.origin, hop.pinned);
	return {
		target,
		follow,
		page: summarizePage(follow, target.origin, NO_OIDC)
	};
}
/**
* Scans one address. Throws TargetRejected if the address is refused before or
* during resolution; everything after that is reported inside the report.
*/
async function runScan(input, options = {}) {
	const policy = options.policy ?? DEFAULT_POLICY;
	const progress = options.onProgress ?? (() => {});
	const started = /* @__PURE__ */ new Date();
	const deadline = started.getTime() + (options.budgetMs ?? 6e4);
	const entered = parseTarget(input, policy);
	progress(`Resolving ${entered.hostname}`);
	const pins = /* @__PURE__ */ new Map([[entered.origin, await resolveTarget(entered, { lookup: options.lookup })]]);
	progress("Fetching the page over HTTPS");
	let landing = await land(entered, pins, policy, options.lookup, deadline);
	let found;
	const searched = [];
	const endOf = (l) => l.follow.responses.at(-1);
	const typedPage = endOf(landing);
	const html = typedPage && typedPage.response.status === 200 && /html/i.test(String(typedPage.response.headers["content-type"] ?? "")) ? typedPage.response.body.toString("utf8") : "";
	if (landing.page.kind === "leads-to-sign-in") found = {
		by: "redirect",
		url: typedPage.response.url
	};
	else if (landing.page.kind === "other" && html && !landing.follow.blockedRedirect && Date.now() < deadline) {
		const base = new URL(typedPage.response.url);
		const candidates = [...findSignInLinks(html, base, 2).map((url) => ({
			url,
			by: "link"
		})), ...SIGN_IN_PATHS.map((path) => ({
			url: new URL(path, base.origin).href,
			by: "convention"
		}))];
		const seen = /* @__PURE__ */ new Set([entered.url.href, ...landing.follow.responses.map((r) => r.response.url)]);
		const refused = (url, error) => {
			if (!(error instanceof TargetRejected)) throw error;
			searched.push({
				label: "Looked for a sign-in",
				value: `${url}: refused (${error.code})`
			});
		};
		progress("Searching for the login page");
		let fetches = 0;
		for (const candidate of candidates) {
			if (fetches >= MAX_SIGN_IN_FETCHES || Date.now() >= deadline) break;
			if (seen.has(candidate.url)) continue;
			seen.add(candidate.url);
			let target;
			try {
				target = parseTarget(candidate.url, policy);
			} catch (error) {
				refused(candidate.url, error);
				continue;
			}
			fetches++;
			let attempt;
			try {
				attempt = await land(target, pins, policy, options.lookup, deadline);
			} catch (error) {
				refused(candidate.url, error);
				continue;
			}
			const end = endOf(attempt);
			if (end && (attempt.page.kind === "sign-in-page" || attempt.page.kind === "leads-to-sign-in")) {
				found = {
					by: candidate.by,
					url: end.response.url
				};
				landing = attempt;
				searched.push({
					label: "Looked for a sign-in",
					value: `${candidate.url}: found, ${candidate.by === "link" ? "by the site’s own link" : "at a usual address"}`
				});
				progress(`Found the login at ${end.target.hostname}${end.target.url.pathname}`);
				break;
			}
			searched.push({
				label: "Looked for a sign-in",
				value: `${candidate.url}: ${end ? `HTTP ${end.response.status}, ` : ""}not a sign-in`
			});
		}
	}
	const target = endOf(landing)?.target ?? landing.target;
	const pinned = pins.get(target.origin);
	const follow = landing.follow;
	const switched = target.origin !== entered.origin;
	const tls = await probeTls(pinned, {
		onProgress: progress,
		deadline
	});
	const certificates = summarizeChain(tls.certificates);
	const related = [];
	const relate = (origin, role) => {
		if (origin !== target.origin && !related.some((r) => r.origin === origin)) related.push({
			origin,
			role
		});
	};
	if (switched) relate(entered.origin, found ? "the address you entered; its sign-in is here" : "the address you entered; it sends visitors here");
	for (const hop of follow.responses) relate(hop.target.origin, "the page redirects through here");
	let plainHttp;
	let oidc = NO_OIDC;
	if (tls.reachable) {
		if (target.port === 443 && !target.isLab && Date.now() < deadline) {
			progress("Checking what plain HTTP does");
			plainHttp = await checkPlainHttp(pinned, Math.min(4e3, deadline - Date.now()));
		}
		progress("Looking for OpenID Connect metadata");
		const typed = target.url.href === entered.url.href;
		const discovery = await discoverOidc(target.url, pinned, policy, {
			lookup: options.lookup,
			deadline,
			includeFullPath: typed
		});
		oidc = discovery.summary;
		discovery.related.forEach((r) => relate(r.origin, r.role));
	}
	const page = summarizePage(follow, target.origin, oidc);
	if (found) page.found = found;
	page.evidence.push(...searched);
	const first = follow.responses.find((r) => r.target.origin === target.origin)?.response.tls;
	const trust = first ? {
		checked: true,
		trusted: first.authorized,
		error: first.authorized ? void 0 : describeTrustError(first.authorizationError),
		store: TRUST_STORE
	} : {
		checked: false,
		store: TRUST_STORE
	};
	const transport = summarizeTransport(follow, target.origin, plainHttp);
	const { layers, findings } = assess({
		hostname: target.hostname,
		lab: target.isLab,
		reachable: tls.reachable,
		probes: tls.probes,
		groupSupport: tls.groupSupport,
		certificates,
		trust,
		transport,
		oidc,
		related
	});
	const finished = /* @__PURE__ */ new Date();
	return {
		schema: 1,
		engine: ENGINE_VERSION,
		target: {
			input,
			url: target.url.href,
			origin: target.origin,
			hostname: target.hostname,
			port: target.port,
			lab: target.isLab
		},
		entered: switched ? {
			url: entered.url.href,
			origin: entered.origin
		} : void 0,
		startedAt: started.toISOString(),
		finishedAt: finished.toISOString(),
		durationMs: finished.getTime() - started.getTime(),
		network: {
			address: pinned.address,
			family: pinned.family,
			resolved: pinned.resolved.map((r) => r.address)
		},
		reachable: tls.reachable,
		tls: {
			probes: tls.probes,
			groupSupport: tls.groupSupport
		},
		certificates,
		trust,
		transport,
		oidc,
		page,
		related,
		layers,
		findings
	};
}
/** OpenSSL's verification codes, in words. */
function describeTrustError(code) {
	return {
		DEPTH_ZERO_SELF_SIGNED_CERT: "the certificate is self-signed",
		SELF_SIGNED_CERT_IN_CHAIN: "the chain ends in a certificate authority that is not in the trust store",
		UNABLE_TO_GET_ISSUER_CERT_LOCALLY: "the issuing certificate authority is not in the trust store",
		UNABLE_TO_VERIFY_LEAF_SIGNATURE: "the chain is incomplete: the issuer of the certificate was not sent and is not in the trust store",
		CERT_HAS_EXPIRED: "the certificate has expired",
		CERT_NOT_YET_VALID: "the certificate is not valid yet",
		ERR_TLS_CERT_ALTNAME_INVALID: "the certificate is for a different host name",
		CERT_REVOKED: "the certificate was revoked"
	}[code ?? ""] ?? code ?? "validation failed";
}
//#endregion
//#region packages/scan-core/src/oidc/issuer-keys.ts
/**
* Fetches an issuer's OpenID Connect metadata and public keys, for a browser
* that was not allowed to fetch them itself (the issuer sends no CORS
* headers). Only the issuer URL reaches the service; the token being checked
* stays in the browser (ADR 0010). The issuer URL comes from a token, so it
* goes through the same policy, resolution and pinning as any scan target.
*/
async function fetchIssuerKeys(issuer, options) {
	const target = parseTarget(issuer, options.policy);
	const pinned = await resolveTarget(target, { lookup: options.lookup });
	const deadline = Date.now() + (options.budgetMs ?? 2e4);
	const { summary, jwks } = await discoverOidc(target.url, pinned, options.policy, {
		lookup: options.lookup,
		deadline,
		includeFullPath: true,
		exactIssuer: true
	});
	return {
		kind: "issuer-keys",
		issuer: target.url.href.replace(/\/$/, ""),
		found: summary.found,
		discoveryUrl: summary.discoveryUrl,
		declaredIssuer: summary.issuer,
		issuerMatches: summary.issuerMatches,
		jwksUri: summary.jwksUri,
		jwks,
		error: summary.found ? summary.jwksError : `No OpenID Connect metadata at ${summary.tried[0]?.url} (${summary.tried[0]?.result}).`
	};
}
//#endregion
//#region services/vercel/src/scan.ts
/**
* The scanner as one Vercel Function (ADR 0016). A scan runs inside the
* request and its progress is streamed back as newline-delimited JSON:
*
*   {"progress":"Resolving example.com"}     as each step starts
*   {"scan":{...}}                            once, at the end
*
* Refusals (a bad address, a limit) are plain JSON with the HTTP status that
* says why, sent before anything is streamed. There is no database: a result
* exists only in the response. The limits are kept in the memory of the
* function instance, which Vercel shares between concurrent requests and
* keeps warm, so they hold for the common case and are not a hard guarantee.
*
* This file is bundled to api/v1/scan.js (npm run vercel:bundle) so that the
* deployed function is a single plain-JavaScript file with no workspace
* imports for Vercel's build to resolve.
*/
const config = { maxDuration: 60 };
/** Limits, per visitor and per scanned service. The same numbers as the self-hosted API's defaults. */
const LIMITS = {
	scansPerWindow: 20,
	windowMs: 6e5,
	activePerClient: 3,
	perHostPerMinute: 3,
	/** Scans running at once in this instance. */
	maxActive: 12,
	/** A repeat of the same address within this window is answered with the earlier result. */
	reuseMs: 3e5,
	/** The whole scan, including finding the login; well inside the function's maxDuration. */
	budgetMs: 45e3
};
/** What one instance remembers. Exported so tests can reset it. */
const memory = {
	byClient: /* @__PURE__ */ new Map(),
	activeByClient: /* @__PURE__ */ new Map(),
	byService: /* @__PURE__ */ new Map(),
	recent: /* @__PURE__ */ new Map(),
	active: 0,
	reset() {
		this.byClient.clear();
		this.activeByClient.clear();
		this.byService.clear();
		this.recent.clear();
		this.active = 0;
	}
};
var Refusal = class extends Error {
	status;
	code;
	retryAfter;
	constructor(status, code, message, retryAfter) {
		super(message);
		this.status = status;
		this.code = code;
		this.retryAfter = retryAfter;
	}
};
const json = (status, body, headers = {}) => new Response(JSON.stringify(body), {
	status,
	headers: {
		"content-type": "application/json",
		"cache-control": "no-store",
		...headers
	}
});
/** Vercel puts the visitor's address first in x-forwarded-for; there is no proxy of ours in front. */
function clientOf(request) {
	return (request.headers.get("x-forwarded-for") ?? "").split(",")[0].trim() || request.headers.get("x-real-ip") || "unknown";
}
/** Scans can only be started from the site itself: a page elsewhere must not spend a visitor's allowance or use them as a relay. */
function requireSameOrigin(request) {
	const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host") ?? "";
	const origin = request.headers.get("origin");
	const site = request.headers.get("sec-fetch-site");
	if (!(origin === null || origin === `https://${host}` || origin === `http://${host}`) || site !== null && site !== "same-origin" && site !== "none") throw new Refusal(403, "cross-site", "Scans can only be started from this site.");
}
/** Drops timestamps older than `windowMs` and returns how many remain. */
function recent(map, key, now, windowMs) {
	const kept = (map.get(key) ?? []).filter((t) => now - t < windowMs);
	map.set(key, kept);
	return kept;
}
/** Trims the memory maps so a long-lived instance does not grow without bound. */
function sweep(now) {
	for (const [key, times] of memory.byClient) if (times.every((t) => now - t >= LIMITS.windowMs)) memory.byClient.delete(key);
	for (const [key, times] of memory.byService) if (times.every((t) => now - t >= 6e4)) memory.byService.delete(key);
	for (const [key, entry] of memory.recent) if (now - entry.at >= LIMITS.reuseMs) memory.recent.delete(key);
}
var scan_default = { async fetch(request) {
	if (request.method !== "POST") return json(405, { error: {
		code: "method-not-allowed",
		message: "POST a JSON body with \"target\"."
	} }, { allow: "POST" });
	try {
		requireSameOrigin(request);
		if (!/^application\/json\b/.test(request.headers.get("content-type") ?? "")) throw new Refusal(415, "invalid-request", "Send JSON.");
		const text = await request.text();
		if (text.length > 4096) throw new Refusal(413, "invalid-request", "The request is too large.");
		let body;
		try {
			body = JSON.parse(text);
		} catch {
			throw new Refusal(400, "invalid-request", "The body is not JSON.");
		}
		if (typeof body.target !== "string") throw new Refusal(400, "invalid-request", "Give the address to scan as \"target\".");
		const kind = body.kind === "issuer-keys" ? "issuer-keys" : "scan";
		const input = body.target.trim().slice(0, 2048);
		let target;
		try {
			target = parseTarget(input, DEFAULT_POLICY);
		} catch (error) {
			if (!(error instanceof TargetRejected)) throw error;
			throw new Refusal(422, error.code, error.message);
		}
		const now = Date.now();
		sweep(now);
		const reuseKey = `${kind} ${target.url.href}`;
		const earlier = memory.recent.get(reuseKey);
		if (earlier && now - earlier.at < LIMITS.reuseMs) return json(200, {
			scan: earlier.scan,
			reused: true
		});
		const client = clientOf(request);
		const service = `${target.hostname}:${target.port}`;
		if (recent(memory.byClient, client, now, LIMITS.windowMs).length >= LIMITS.scansPerWindow) throw new Refusal(429, "rate-limited", `That is ${LIMITS.scansPerWindow} scans in ${LIMITS.windowMs / 6e4} minutes, which is the limit. Try again later.`, 60);
		if ((memory.activeByClient.get(client) ?? 0) >= LIMITS.activePerClient) throw new Refusal(429, "too-many-active", `You already have ${LIMITS.activePerClient} scans in progress. Wait for one to finish.`, 10);
		if (recent(memory.byService, service, now, 6e4).length >= LIMITS.perHostPerMinute) throw new Refusal(429, "host-busy", `${service} has been scanned several times in the last minute. Try again in a minute.`, 60);
		if (memory.active >= LIMITS.maxActive) throw new Refusal(503, "queue-full", "The scanner is busy. Try again shortly.", 30);
		memory.byClient.get(client).push(now);
		memory.byService.get(service).push(now);
		memory.activeByClient.set(client, (memory.activeByClient.get(client) ?? 0) + 1);
		memory.active++;
		const encoder = new TextEncoder();
		const stream = new ReadableStream({ async start(controller) {
			const line = (value) => controller.enqueue(encoder.encode(`${JSON.stringify(value)}\n`));
			const createdAt = new Date(now).toISOString();
			let finished;
			try {
				const report = kind === "issuer-keys" ? await fetchIssuerKeys(input, {
					policy: DEFAULT_POLICY,
					budgetMs: LIMITS.budgetMs
				}) : await runScan(input, {
					policy: DEFAULT_POLICY,
					budgetMs: LIMITS.budgetMs,
					onProgress: (step) => line({ progress: step })
				});
				finished = {
					kind,
					target: input,
					targetUrl: target.url.href,
					status: "succeeded",
					createdAt,
					finishedAt: (/* @__PURE__ */ new Date()).toISOString(),
					report
				};
				memory.recent.set(reuseKey, {
					at: Date.now(),
					scan: finished
				});
			} catch (error) {
				const refused = error instanceof TargetRejected;
				finished = {
					kind,
					target: input,
					targetUrl: target.url.href,
					status: "failed",
					createdAt,
					finishedAt: (/* @__PURE__ */ new Date()).toISOString(),
					error: refused ? {
						code: error.code,
						message: error.message
					} : {
						code: "scanner-error",
						message: "The scan failed. Try again, or try the login page’s own address."
					}
				};
				if (!refused) console.error("scan failed", {
					target: target.hostname,
					error: error instanceof Error ? error.message : String(error)
				});
			} finally {
				memory.active--;
				memory.activeByClient.set(client, Math.max(0, (memory.activeByClient.get(client) ?? 1) - 1));
			}
			line({ scan: finished });
			controller.close();
		} });
		return new Response(stream, {
			status: 200,
			headers: {
				"content-type": "application/x-ndjson",
				"cache-control": "no-store",
				"x-engine": ENGINE_VERSION
			}
		});
	} catch (error) {
		if (error instanceof Refusal) return json(error.status, { error: {
			code: error.code,
			message: error.message
		} }, error.retryAfter ? { "retry-after": String(error.retryAfter) } : {});
		console.error("request failed", error);
		return json(500, { error: {
			code: "internal",
			message: "Something went wrong."
		} });
	}
} };
//#endregion
export { ENGINE_VERSION, LIMITS, config, scan_default as default, memory };
