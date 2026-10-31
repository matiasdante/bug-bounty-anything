import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { canonical, SafeError } from './contracts.ts';
import { fields } from './scope.ts';
import { readJson } from './session.ts';

export type SignedEntry = { path: string; sha256: string };

export type SignatureEnvelope = {
  schemaVersion: 1;
  algorithm: 'ed25519';
  targetKind: 'file' | 'directory';
  publicKeyFingerprint: string;
  signedAt: string;
  entries: SignedEntry[];
  payloadSha256: string;
  signature: string;
};

const MAX_SIGNABLE_FILE_BYTES = 128 * 1024 * 1024;
const transientLockPrefix = 'execution-lock.sqlite';

function sha256Hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

function publicFingerprintFromKey(pubKey: ReturnType<typeof createPublicKey>): string {
  const der = pubKey.export({ type: 'spki', format: 'der' });
  return sha256Hex(der);
}

function collectSignableEntries(target: string, excludedAbsPath: string): { targetKind: 'file' | 'directory'; entries: SignedEntry[] } {
  const st = lstatSync(target);
  if (st.isSymbolicLink()) throw new SafeError('Refusing to sign or verify a symbolic link');
  if (st.isFile()) {
    if (st.size > MAX_SIGNABLE_FILE_BYTES) throw new SafeError('Signable file exceeds size limit');
    return {
      targetKind: 'file',
      entries: [{ path: '.', sha256: sha256Hex(readFileSync(target)) }],
    };
  }
  if (!st.isDirectory()) throw new SafeError('Signable target must be a regular file or directory');

  const entries: SignedEntry[] = [];
  const walk = (dir: string, relPrefix: string) => {
    const names = readdirSync(dir).sort();
    for (const name of names) {
      if (name.startsWith(transientLockPrefix) || name === '.initializing') continue;
      const full = join(dir, name);
      if (resolve(full) === excludedAbsPath) continue;
      const itemStat = lstatSync(full);
      if (itemStat.isSymbolicLink()) throw new SafeError('Refusing to sign or verify directory containing symbolic links');
      const rel = relPrefix ? `${relPrefix}/${name}` : name;
      if (itemStat.isDirectory()) {
        walk(full, rel);
      } else if (itemStat.isFile()) {
        if (rel === 'signature.json') continue;
        if (itemStat.size > MAX_SIGNABLE_FILE_BYTES) throw new SafeError('Signable file exceeds size limit');
        entries.push({ path: rel, sha256: sha256Hex(readFileSync(full)) });
        if (entries.length > 2000) throw new SafeError('Signable directory exceeds 2000 files');
      }
    }
  };
  walk(target, '');
  if (!entries.length) throw new SafeError('Signable directory contains no regular files');
  return { targetKind: 'directory', entries };
}

export function generateSigningKeypair(outDir: string): {
  privateKeyPath: string;
  publicKeyPath: string;
  publicKeyFingerprint: string;
} {
  const targetDir = resolve(outDir);
  mkdirSync(dirname(targetDir), { recursive: true });
  mkdirSync(targetDir);
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const pubPem = publicKey.export({ type: 'spki', format: 'pem' });
  const privateKeyPath = join(targetDir, 'bba-ed25519.key.pem');
  const publicKeyPath = join(targetDir, 'bba-ed25519.pub.pem');
  writeFileSync(privateKeyPath, privPem, { flag: 'wx', mode: 0o600 });
  writeFileSync(publicKeyPath, pubPem, { flag: 'wx', mode: 0o644 });
  return {
    privateKeyPath,
    publicKeyPath,
    publicKeyFingerprint: publicFingerprintFromKey(publicKey),
  };
}

export function defaultSignaturePath(targetPath: string): string {
  const full = resolve(targetPath);
  return lstatSync(full).isDirectory() ? join(full, 'signature.json') : `${full}.sig.json`;
}

export function signEvidence(
  targetPath: string,
  privateKeyPath: string,
  sigOutPath?: string,
): { signaturePath: string; publicKeyFingerprint: string; payloadSha256: string; filesSigned: number } {
  const fullTarget = resolve(targetPath);
  const fullSig = resolve(sigOutPath ?? defaultSignaturePath(fullTarget));
  const keyPem = readFileSync(resolve(privateKeyPath), 'utf8');
  const privKey = createPrivateKey(keyPem);
  if (privKey.asymmetricKeyType !== 'ed25519') {
    throw new SafeError('Expected an Ed25519 private key');
  }
  const pubKey = createPublicKey(privKey);
  const publicKeyFingerprint = publicFingerprintFromKey(pubKey);
  const { targetKind, entries } = collectSignableEntries(fullTarget, fullSig);
  const signedAt = new Date().toISOString();
  const payloadObj = {
    schemaVersion: 1 as const,
    algorithm: 'ed25519' as const,
    targetKind,
    publicKeyFingerprint,
    signedAt,
    entries,
  };
  const payloadBytes = Buffer.from(canonical(payloadObj), 'utf8');
  const payloadSha256 = sha256Hex(payloadBytes);
  const sigBase64 = sign(null, payloadBytes, privKey).toString('base64');
  const envelope: SignatureEnvelope = {
    ...payloadObj,
    payloadSha256,
    signature: sigBase64,
  };
  mkdirSync(dirname(fullSig), { recursive: true });
  writeFileSync(fullSig, JSON.stringify(envelope, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return { signaturePath: fullSig, publicKeyFingerprint, payloadSha256, filesSigned: entries.length };
}

export function verifyEvidenceSignature(
  targetPath: string,
  publicKeyPath: string,
  sigPath?: string,
): { verified: true; publicKeyFingerprint: string; signedAt: string; filesVerified: number; payloadSha256: string } {
  const fullTarget = resolve(targetPath);
  const fullSig = resolve(sigPath ?? defaultSignaturePath(fullTarget));
  const rawEnvelope = readJson(fullSig);
  fields(rawEnvelope, ['schemaVersion', 'algorithm', 'targetKind', 'publicKeyFingerprint', 'signedAt', 'entries', 'payloadSha256', 'signature']);
  if (rawEnvelope.schemaVersion !== 1 || rawEnvelope.algorithm !== 'ed25519'
    || (rawEnvelope.targetKind !== 'file' && rawEnvelope.targetKind !== 'directory')
    || typeof rawEnvelope.publicKeyFingerprint !== 'string' || !/^[a-f0-9]{64}$/.test(rawEnvelope.publicKeyFingerprint)
    || typeof rawEnvelope.signedAt !== 'string'
    || typeof rawEnvelope.payloadSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(rawEnvelope.payloadSha256)
    || typeof rawEnvelope.signature !== 'string' || !rawEnvelope.signature
    || !Array.isArray(rawEnvelope.entries) || !rawEnvelope.entries.length) {
    throw new SafeError('Invalid signature envelope');
  }
  const pubPem = readFileSync(resolve(publicKeyPath), 'utf8');
  const pubKey = createPublicKey(pubPem);
  if (pubKey.asymmetricKeyType !== 'ed25519') {
    throw new SafeError('Expected an Ed25519 public key');
  }
  const actualFingerprint = publicFingerprintFromKey(pubKey);
  if (actualFingerprint !== rawEnvelope.publicKeyFingerprint) {
    throw new SafeError('Public key fingerprint does not match signature envelope');
  }

  const { targetKind, entries } = collectSignableEntries(fullTarget, fullSig);
  if (targetKind !== rawEnvelope.targetKind || canonical(entries) !== canonical(rawEnvelope.entries)) {
    throw new SafeError('Evidence files were modified, added or removed since signing');
  }

  const payloadObj = {
    schemaVersion: 1 as const,
    algorithm: 'ed25519' as const,
    targetKind: rawEnvelope.targetKind,
    publicKeyFingerprint: rawEnvelope.publicKeyFingerprint,
    signedAt: rawEnvelope.signedAt,
    entries: rawEnvelope.entries,
  };
  const payloadBytes = Buffer.from(canonical(payloadObj), 'utf8');
  if (sha256Hex(payloadBytes) !== rawEnvelope.payloadSha256) {
    throw new SafeError('Signature payload digest mismatch');
  }
  const sigBytes = Buffer.from(rawEnvelope.signature, 'base64');
  if (!verify(null, payloadBytes, pubKey, sigBytes)) {
    throw new SafeError('Ed25519 cryptographic signature verification failed');
  }
  return {
    verified: true,
    publicKeyFingerprint: actualFingerprint,
    signedAt: rawEnvelope.signedAt,
    filesVerified: entries.length,
    payloadSha256: rawEnvelope.payloadSha256,
  };
}
