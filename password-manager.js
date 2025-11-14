"use strict";

const { subtle } = require("crypto").webcrypto;
const { 
    stringToBuffer, bufferToString,
    encodeBuffer, decodeBuffer,
    getRandomBytes 
} = require("./lib.js");

const PBKDF2_ITERATIONS = 100000;
const MAX_PASSWORD_LENGTH = 64;

class Keychain {

    constructor(salt, macKey, encKey, kvs = {}) {
        this.salt = salt;
        this.macKey = macKey;
        this.encKey = encKey;
        this.kvs = kvs;
    }

    // ---------- INIT ----------
    static async init(password) {
        const salt = getRandomBytes(16);

        const rawKey = await subtle.importKey(
            "raw",
            stringToBuffer(password),
            "PBKDF2",
            false,
            ["deriveBits"]
        );

        const masterKeyBits = await subtle.deriveBits(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: PBKDF2_ITERATIONS,
                hash: "SHA-256"
            },
            rawKey,
            256
        );

        const masterKey = new Uint8Array(masterKeyBits);

        // Derive MAC key
        const macKeyMaterial = await subtle.sign(
            { name: "HMAC", hash: "SHA-256" },
            await subtle.importKey(
                "raw", masterKey,
                { name: "HMAC", hash: "SHA-256" },
                false, ["sign"]
            ),
            stringToBuffer("mac")
        );

        // Derive ENC key
        const encKeyMaterial = await subtle.sign(
            { name: "HMAC", hash: "SHA-256" },
            await subtle.importKey(
                "raw", masterKey,
                { name: "HMAC", hash: "SHA-256" },
                false, ["sign"]
            ),
            stringToBuffer("enc")
        );

        const macKeyFinal = await subtle.importKey(
            "raw", macKeyMaterial,
            { name: "HMAC", hash: "SHA-256" },
            false, ["sign", "verify"]
        );

        const encKeyFinal = await subtle.importKey(
            "raw", encKeyMaterial,
            "AES-GCM",
            false,
            ["encrypt", "decrypt"]
        );

        return new Keychain(salt, macKeyFinal, encKeyFinal);
    }

// ---------- dump() ----------
async dump() {
    // deterministic kvs serialization for checksum
    const saltStr = String(encodeBuffer(this.salt));
    const kvsForCheck = JSON.stringify(this.kvs, Object.keys(this.kvs).sort());
    const checkData = stringToBuffer(kvsForCheck + saltStr);

    // compute checksum using instance macKey
    const checksum = String(
        encodeBuffer(await subtle.sign({ name: "HMAC" }, this.macKey, checkData))
    );

    // Serialized contents (include checksum inside too, it's harmless)
    const serializedObj = {
        salt: saltStr,
        kvs: this.kvs,
        checksum: checksum
    };

    const contents = JSON.stringify(serializedObj);

    // Return an array [contents, checksum] as the tests expect
    return [contents, checksum];
}

// ---------- load(password, contents, expectedChecksum) ----------
static async load(password, contents, expectedChecksum) {
    // Note: this function should reject (throw) on checksum mismatch / parse error
    try {
        // Ensure contents is a string
        if (typeof contents !== "string") {
            throw new Error("Invalid contents argument");
        }

        // Parse the JSON contents
        const data = JSON.parse(contents);

        if (!data || !data.salt || !data.kvs) {
            throw new Error("Serialized data missing required fields");
        }

        // Decode salt
        const salt = decodeBuffer(data.salt);

        // Derive master key bits
        const rawKey = await subtle.importKey(
            "raw",
            stringToBuffer(password),
            "PBKDF2",
            false,
            ["deriveBits"]
        );

        const masterKeyBits = await subtle.deriveBits(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: PBKDF2_ITERATIONS,
                hash: "SHA-256"
            },
            rawKey,
            256
        );

        const masterKey = new Uint8Array(masterKeyBits);

        // Helper to derive labels
        const deriveLabel = async (label) => {
            return await subtle.sign(
                { name: "HMAC", hash: "SHA-256" },
                await subtle.importKey(
                    "raw",
                    masterKey,
                    { name: "HMAC", hash: "SHA-256" },
                    false,
                    ["sign"]
                ),
                stringToBuffer(label)
            );
        };

        const macKeyMaterial = await deriveLabel("mac");
        const encKeyMaterial = await deriveLabel("enc");

        const macKeyFinal = await subtle.importKey(
            "raw", macKeyMaterial,
            { name: "HMAC", hash: "SHA-256" },
            false, ["sign", "verify"]
        );

        const encKeyFinal = await subtle.importKey(
            "raw", encKeyMaterial,
            "AES-GCM",
            false,
            ["encrypt", "decrypt"]
        );

        // Compute checksum (deterministic order)
        const kvsForCheck = JSON.stringify(data.kvs, Object.keys(data.kvs).sort());
        const checkData = stringToBuffer(kvsForCheck + data.salt);

        const computedChecksum = String(
            encodeBuffer(await subtle.sign({ name: "HMAC" }, macKeyFinal, checkData))
        );

        // Decide which checksum to verify:
        // - if expectedChecksum (third arg) is provided (string), use that,
        // - otherwise if data.checksum exists in contents, use that,
        // - otherwise treat as no-checksum case and allow restore.
        const provided = (typeof expectedChecksum === "string" && expectedChecksum.length > 0)
            ? expectedChecksum
            : (typeof data.checksum === "string" ? data.checksum : null);

        if (provided !== null) {
            if (computedChecksum !== provided) {
                // Tests expect promise rejection on checksum mismatch / wrong password
                throw new Error("Checksum mismatch or wrong password");
            }
        }

        // All good -> return Keychain instance
        return new Keychain(salt, macKeyFinal, encKeyFinal, data.kvs);

    } catch (err) {
        // Throw so the promise rejects (tests use expectReject)
        throw err;
    }
}

    async get(name) {
        const domainMacBuffer = await subtle.sign(
            { name: "HMAC" },
            this.macKey,
            stringToBuffer(name)
        );
        const domainKey = encodeBuffer(domainMacBuffer);

        const entry = this.kvs[domainKey];
        if (!entry) {
            return null;
        }

        // Verify MAC to prevent swap attacks
        const storedMac = decodeBuffer(entry.mac);
        const computedMac = await subtle.sign(
            { name: "HMAC" },
            this.macKey,
            stringToBuffer(name)
        );

        if (!this.constantTimeCompare(storedMac, computedMac)) {
            throw "Swap attack detected";
        }

        // Decrypt
        const iv = decodeBuffer(entry.iv);
        const ciphertext = decodeBuffer(entry.ciphertext);

        let decrypted;
        try {
            decrypted = await subtle.decrypt(
                { name: "AES-GCM", iv: iv },
                this.encKey,
                ciphertext
            );
        } catch (e) {
            throw "Decryption failed";
        }

        // Remove padding
        const bytes = new Uint8Array(decrypted);
        let end = MAX_PASSWORD_LENGTH;
        while (end > 0 && bytes[end - 1] === 0) {
            end--;
        }

        return bufferToString(bytes.slice(0, end).buffer);
    }

    async set(name, value) {
        const domainMacBuffer = await subtle.sign(
            { name: "HMAC" },
            this.macKey,
            stringToBuffer(name)
        );
        const domainKey = encodeBuffer(domainMacBuffer);

        const pwdBuffer = stringToBuffer(value);
        if (pwdBuffer.byteLength > MAX_PASSWORD_LENGTH) {
            throw new Error("Password too long");
        }
        
        const padded = new Uint8Array(MAX_PASSWORD_LENGTH);
        padded.set(new Uint8Array(pwdBuffer));

        const iv = getRandomBytes(12);
        const ciphertextBuffer = await subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            this.encKey,
            padded
        );

        const nameMacBuffer = await subtle.sign(
            { name: "HMAC" },
            this.macKey,
            stringToBuffer(name)
        );

        this.kvs[domainKey] = {
            iv: encodeBuffer(iv),
            ciphertext: encodeBuffer(ciphertextBuffer),
            mac: encodeBuffer(nameMacBuffer)
        };
    }

    async remove(name) {
        const domainMacBuffer = await subtle.sign(
            { name: "HMAC" },
            this.macKey,
            stringToBuffer(name)
        );
        const domainKey = encodeBuffer(domainMacBuffer);

        if (!this.kvs[domainKey]) {
            return false;
        }

        delete this.kvs[domainKey];
        return true;
    }

    // Helper method for constant-time comparison
    constantTimeCompare(a, b) {
        const aBuf = new Uint8Array(a);
        const bBuf = new Uint8Array(b);
        
        if (aBuf.length !== bBuf.length) {
            return false;
        }
        
        let result = 0;
        for (let i = 0; i < aBuf.length; i++) {
            result |= aBuf[i] ^ bBuf[i];
        }
        return result === 0;
    }
}

module.exports = { Keychain };
