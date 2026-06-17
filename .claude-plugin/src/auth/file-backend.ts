// v1.37 BLOCKER 1 -- FileBackend: encrypted-at-rest token store for Linux/headless.
//
// The OSS unblock (design 4.2): @napi-rs/keyring needs a desktop Secret Service
// (D-Bus / gnome-keyring) that a headless Linux server does not have. FileBackend
// stores tokens in one AES-256-GCM file under configDir().
//
// KEY SOURCE -- HYBRID (B1 LOCKED), defaulting to key-file mode:
//   * passphrase mode (2): if $SAFESPACE_SECRET_PASSPHRASE is set, the AES key is
//     derived per-file via scrypt(N=2^17,r=8,p=1) -> NO key at rest.
//   * key-file mode (1): otherwise a random 32-byte key lives in secret.key
//     (0o600) beside secret.enc -> zero-friction, perms-bound protection (same
//     honest boundary as the macOS Keychain for the logged-in user; NOT against
//     whole-directory capture). A loud one-time stderr warning is emitted.
//
// CRYPTO (design 4.2.3):
//   * WHOLE-FILE: decrypt the blob to an in-memory { storageKey: tokenJson } map,
//     mutate, re-encrypt with a FRESH random 12-byte nonce, atomic tmp+rename.
//     Re-encrypting the whole file every write gives a fresh (key,nonce) per file
//     version BY CONSTRUCTION -> GCM nonce reuse is impossible.
//   * The whole header (magic|version|mode|kdf_n|salt|nonce) is GCM AAD, so a
//     downgrade/tamper of those fields trips the auth tag.
//
// ERRORS (design 4.5): missing passphrase / unreadable key file -> keychain_locked
// (RETRYABLE). GCM auth fail (wrong passphrase OR tamper -- deliberately
// CONFLATED, never an oracle), bad magic, truncated/unknown header, or
// decrypted-not-JSON -> secret_store_corrupt (-32031). NEVER forward String(e)
// from crypto/fs (Node errors carry paths / byte offsets) -- both throws carry
// only the static recovery string.

import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { MCPError } from "../errors";
import { configDir } from "./keychain";
import { type SecretBackend, storageKey } from "./secret-backend";
import { ENV_SECRET_PASSPHRASE } from "../config";

// 16-byte fixed magic (all printable ASCII; no literal control byte in source).
const MAGIC = Buffer.from("SAFESPACE-SECRET", "ascii");
const VERSION = 1;
const MODE_KEYFILE = 1;
const MODE_PASSPHRASE = 2;

// scrypt cost (B2 LOCKED). N=2^17 needs ~128 MiB (128*N*r); maxmem set above it.
const SCRYPT_N = 1 << 17;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_MAXMEM = 256 * 1024 * 1024;

const KEY_LEN = 32;
const SALT_LEN = 16;
const NONCE_LEN = 12;
const TAG_LEN = 16;

// Header field offsets. AAD = [0, OFF_TAG) = magic..nonce (the tag is the GCM
// OUTPUT, so it cannot be part of its own AAD).
const OFF_VERSION = MAGIC.length; // 16
const OFF_MODE = OFF_VERSION + 1; // 17
const OFF_KDFN = OFF_MODE + 1; // 18
const OFF_SALT = OFF_KDFN + 4; // 22
const OFF_NONCE = OFF_SALT + SALT_LEN; // 38
const OFF_TAG = OFF_NONCE + NONCE_LEN; // 50  (= AAD length)
const OFF_CIPHERTEXT = OFF_TAG + TAG_LEN; // 66

type TokenMap = Record<string, string>;

function encPath(): string {
  return path.join(configDir(), "secret.enc");
}
function keyFilePath(): string {
  return path.join(configDir(), "secret.key");
}

async function ensureConfigDir(): Promise<void> {
  await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
}

// One-time key-file-mode warning (honest threat-model signposting, B1). Module
// flag so it fires at most once per process.
//
// v1.110 PR 1c (S7): the message's "file-permission-bound to your OS user" claim
// rests on the secret.key 0o600 perms actually restricting other users. On
// Windows that is FALSE — NTFS uses ACLs, not POSIX permission bits, and node's
// fs honors only the read-only bit, so `fs.open(..., 0o600)` does NOT restrict
// other users. Key-file mode is therefore WEAKER on win32 (effectively no
// user-binding), so the warning appends a win32-specific caveat steering the
// operator to passphrase mode. (F6 already refuses key-file mode under autonomous
// on win32 — see select-backend.autonomousKeyfileRefusal; this warns the
// non-autonomous case the proxy still serves.)
let keyFileWarned = false;
function warnKeyFileModeOnce(): void {
  if (keyFileWarned) return;
  keyFileWarned = true;
  const win32Caveat =
    process.platform === "win32"
      ? " On Windows the secret.key 0o600 permission is a NO-OP (NTFS uses ACLs, " +
        "not POSIX permission bits), so the file-permission binding does NOT hold — " +
        "passphrase mode is effectively required for at-rest protection here."
      : "";
  console.error(
    "[safespace] FileBackend KEY-FILE mode: OAuth tokens are encrypted at rest, " +
      "but the key sits beside the ciphertext (protection is file-permission-bound " +
      "to your OS user -- NOT against whole-directory/backup capture). Set " +
      "SAFESPACE_SECRET_PASSPHRASE for no-key-at-rest encryption. See SECURITY.md." +
      win32Caveat,
  );
}

/** True iff FileBackend will use PASSPHRASE mode (key derived per-file via
 *  scrypt → NO key at rest), i.e. $SAFESPACE_SECRET_PASSPHRASE is set to a
 *  non-empty value. False = KEY-FILE mode (random key in secret.key beside the
 *  ciphertext). This mirrors the exact `if (passphrase)` decision in
 *  saveMap/loadMap; exported so the v1.55 F6 autonomous-deploy guard
 *  (select-backend.autonomousKeyfileRefusal) agrees with the ACTUAL mode and the
 *  two cannot drift. (Same `Boolean(env)` truthiness — empty string = key-file.) */
export function isPassphraseMode(): boolean {
  return Boolean(process.env[ENV_SECRET_PASSPHRASE]);
}

/** Test-only: reset the module-level one-time-warning flag + scrypt key memo +
 *  invocation counter so each case starts from a cold, deterministic state. */
export function __resetFileBackendStateForTests(): void {
  keyFileWarned = false;
  scryptMemo = null;
  scryptInvocations = 0;
}

/** Read the existing key file. Missing/unreadable -> keychain_locked (retryable;
 *  no native message). Wrong length -> secret_store_corrupt. */
async function readKeyFile(): Promise<Buffer> {
  let key: Buffer;
  try {
    key = await fs.readFile(keyFilePath());
  } catch {
    throw new MCPError("keychain_locked");
  }
  if (key.length !== KEY_LEN) throw new MCPError("secret_store_corrupt");
  return key;
}

/** Create the key file atomically (O_EXCL) with 32 random bytes, or read the
 *  winner's bytes on EEXIST (mirrors audit.ts getOrCreateAuditSalt). */
async function loadOrCreateKeyFile(): Promise<Buffer> {
  await ensureConfigDir();
  let fh: fs.FileHandle;
  try {
    fh = await fs.open(keyFilePath(), "wx", 0o600);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") return readKeyFile();
    throw new MCPError("keychain_locked");
  }
  try {
    const key = crypto.randomBytes(KEY_LEN);
    await fh.write(key);
    return key;
  } finally {
    await fh.close();
  }
}

// Single-entry memo for the scrypt-derived AES key. scrypt(N=2^17) costs
// ~128 MiB + tens-to-hundreds of ms; deriving it on every token read/write made
// it the dominant per-call cost on the passphrase path. The (passphrase, salt)
// pair is stable for the life of an encrypted file, so the derived key is too.
// The memo is keyed on sha256(passphrase) (plaintext passphrase never retained
// in a second place) + saltHex, so an env-passphrase change OR a fresh-salt
// write correctly recomputes. The derived key itself is the sensitive output —
// it already lives in process memory transiently during every crypto op, so
// holding it for the process lifetime does not weaken the at-rest guarantee.
let scryptMemo: { ph: string; saltHex: string; key: Buffer } | null = null;

// Test-only counter: how many times scryptSync actually ran (memo misses).
let scryptInvocations = 0;
export function __scryptInvocationsForTests(): number {
  return scryptInvocations;
}

function scryptKey(passphrase: string, salt: Buffer): Buffer {
  const ph = crypto.createHash("sha256").update(passphrase, "utf8").digest("hex");
  const saltHex = salt.toString("hex");
  if (scryptMemo && scryptMemo.ph === ph && scryptMemo.saltHex === saltHex) {
    return scryptMemo.key;
  }
  scryptInvocations++;
  const key = crypto.scryptSync(passphrase, salt, KEY_LEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAXMEM,
  });
  scryptMemo = { ph, saltHex, key };
  return key;
}

async function atomicWrite(p: string, data: Buffer): Promise<void> {
  const suffix = crypto.randomBytes(6).toString("hex");
  const tmp = `${p}.tmp.${process.pid}.${suffix}`;
  await fs.writeFile(tmp, data, { mode: 0o600 });
  await fs.rename(tmp, p);
}

export class FileBackend implements SecretBackend {
  async getToken(operatorId: string | null, googleAccount: string): Promise<string | null> {
    const map = await this.loadMap();
    const key = storageKey(operatorId, googleAccount);
    if (Object.prototype.hasOwnProperty.call(map, key)) return map[key]!;

    // Lazy re-key (design 4.3.3): only when an operatorId is set and the
    // namespaced key missed, fall back to the legacy null-key.
    if (operatorId !== null) {
      const legacyKey = storageKey(null, googleAccount);
      if (Object.prototype.hasOwnProperty.call(map, legacyKey)) {
        const value = map[legacyKey]!;
        try {
          map[key] = value;
          delete map[legacyKey];
          await this.saveMap(map);
        } catch {
          // Persist failed -> still return the token (never lose access). The
          // legacy entry stays; the next read retries the migration (idempotent).
        }
        return value;
      }
    }
    return null;
  }

  async setToken(operatorId: string | null, googleAccount: string, tokenJson: string): Promise<void> {
    const map = await this.loadMap();
    map[storageKey(operatorId, googleAccount)] = tokenJson;
    await this.saveMap(map);
  }

  async deleteToken(operatorId: string | null, googleAccount: string): Promise<void> {
    try {
      const map = await this.loadMap();
      const key = storageKey(operatorId, googleAccount);
      if (!Object.prototype.hasOwnProperty.call(map, key)) return; // idempotent no-op
      delete map[key];
      await this.saveMap(map);
    } catch {
      // Best-effort / idempotent: a corrupt/locked store must not make delete
      // throw (recovery > policy, mirrors keychain deleteToken).
    }
  }

  /** Read + decrypt the whole file into a token map. Missing file -> {}. */
  private async loadMap(): Promise<TokenMap> {
    let buf: Buffer;
    try {
      buf = await fs.readFile(encPath());
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return Object.create(null) as TokenMap;
      // Unreadable (perms etc.) -> locked/retryable, NOT corrupt. No String(e).
      throw new MCPError("keychain_locked");
    }

    if (buf.length < OFF_CIPHERTEXT || !buf.subarray(0, MAGIC.length).equals(MAGIC)) {
      throw new MCPError("secret_store_corrupt");
    }
    const version = buf.readUInt8(OFF_VERSION);
    const mode = buf.readUInt8(OFF_MODE);
    if (version !== VERSION || (mode !== MODE_KEYFILE && mode !== MODE_PASSPHRASE)) {
      throw new MCPError("secret_store_corrupt");
    }

    const salt = buf.subarray(OFF_SALT, OFF_SALT + SALT_LEN);
    const nonce = buf.subarray(OFF_NONCE, OFF_NONCE + NONCE_LEN);
    const tag = buf.subarray(OFF_TAG, OFF_TAG + TAG_LEN);
    const aad = buf.subarray(0, OFF_TAG);
    const ciphertext = buf.subarray(OFF_CIPHERTEXT);

    const key = await this.keyForRead(mode, salt); // may throw keychain_locked

    let plaintext: Buffer;
    try {
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
      decipher.setAAD(aad);
      decipher.setAuthTag(tag);
      plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch {
      // GCM auth failure (wrong passphrase / tamper -- conflated). No String(e).
      throw new MCPError("secret_store_corrupt");
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(plaintext.toString("utf8"));
    } catch {
      throw new MCPError("secret_store_corrupt");
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new MCPError("secret_store_corrupt");
    }
    // Copy into a null-prototype map (defuses any "__proto__"/"constructor" key
    // from the decrypted JSON) and verify every value is a string.
    const map = Object.create(null) as TokenMap;
    for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof v !== "string") throw new MCPError("secret_store_corrupt");
      map[k] = v;
    }
    return map;
  }

  /** Encrypt + atomically write the whole token map. Mode is chosen by env:
   *  passphrase if set, else key-file (with the one-time warning). */
  private async saveMap(map: TokenMap): Promise<void> {
    await ensureConfigDir();
    const passphrase = process.env[ENV_SECRET_PASSPHRASE];

    let mode: number;
    let salt: Buffer;
    let key: Buffer;
    let kdfN: number;
    if (passphrase) {
      mode = MODE_PASSPHRASE;
      salt = await this.saltForWrite();
      key = scryptKey(passphrase, salt);
      kdfN = SCRYPT_N;
    } else {
      mode = MODE_KEYFILE;
      salt = Buffer.alloc(SALT_LEN); // zeroed (no KDF)
      key = await loadOrCreateKeyFile();
      kdfN = 0;
      warnKeyFileModeOnce();
    }

    const nonce = crypto.randomBytes(NONCE_LEN); // FRESH per write
    const aad = Buffer.alloc(OFF_TAG);
    MAGIC.copy(aad, 0);
    aad.writeUInt8(VERSION, OFF_VERSION);
    aad.writeUInt8(mode, OFF_MODE);
    aad.writeUInt32LE(kdfN, OFF_KDFN);
    salt.copy(aad, OFF_SALT);
    nonce.copy(aad, OFF_NONCE);

    const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(aad);
    const plaintext = Buffer.from(JSON.stringify(map), "utf8");
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    await atomicWrite(encPath(), Buffer.concat([aad, tag, ciphertext]));
  }

  /** Derive/load the AES key for DECRYPTION, given the file's mode + salt. */
  private async keyForRead(mode: number, salt: Buffer): Promise<Buffer> {
    if (mode === MODE_KEYFILE) {
      warnKeyFileModeOnce();
      return readKeyFile();
    }
    const passphrase = process.env[ENV_SECRET_PASSPHRASE];
    if (!passphrase) throw new MCPError("keychain_locked"); // expected but unset
    return scryptKey(passphrase, salt);
  }

  /** For a passphrase-mode write, reuse the existing file's salt when it is
   *  already passphrase-mode (so the derived key is stable); otherwise mint a
   *  fresh random salt (fresh install, or upgrading from key-file mode). */
  private async saltForWrite(): Promise<Buffer> {
    try {
      const buf = await fs.readFile(encPath());
      if (
        buf.length >= OFF_CIPHERTEXT &&
        buf.subarray(0, MAGIC.length).equals(MAGIC) &&
        buf.readUInt8(OFF_VERSION) === VERSION && // sec-rev M-1: don't reuse a salt from an unknown-version file
        buf.readUInt8(OFF_MODE) === MODE_PASSPHRASE
      ) {
        return Buffer.from(buf.subarray(OFF_SALT, OFF_SALT + SALT_LEN));
      }
    } catch {
      // missing / unreadable -> fall through to a fresh salt
    }
    return crypto.randomBytes(SALT_LEN);
  }
}
