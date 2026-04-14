import crypto from "node:crypto";

const prefix = "ar_live_DEMO1";
const secret = crypto.randomBytes(24).toString("base64url");
const fullKey = `${prefix}.${secret}`;
const keyHash = crypto.createHash("sha256").update(fullKey).digest("hex");

console.log("FULL_KEY=" + fullKey);
console.log("KEY_PREFIX=" + prefix);
console.log("KEY_HASH=" + keyHash);