"use strict";

const { randomBytes } = require("crypto");

// Convert JS string → ArrayBuffer
function stringToBuffer(str) {
    return Uint8Array.from(Buffer.from(str, "utf8")).buffer;
}

// Convert ArrayBuffer → JS string
function bufferToString(buf) {
    return Buffer.from(new Uint8Array(buf)).toString("utf8");
}

// Encode Uint8Array / ArrayBuffer → Base64 string
function encodeBuffer(buf) {
    const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    return Buffer.from(u8).toString("base64");
}

// Decode Base64 → Uint8Array
function decodeBuffer(b64) {
    return new Uint8Array(Buffer.from(b64, "base64"));
}

// Secure random bytes
function getRandomBytes(len) {
    return new Uint8Array(randomBytes(len));
}

module.exports = {
    stringToBuffer,
    bufferToString,
    encodeBuffer,
    decodeBuffer,
    getRandomBytes
};
