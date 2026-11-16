export declare const VERSION: number

export declare class EnvelopeError extends Error {
  code: 'malformed' | 'version' | 'unknown_key' | 'auth_failed' | 'no_key'
  constructor(code: EnvelopeError['code'], message: string)
}

export declare function keyId(secret: string): Buffer

export declare function encrypt(args: {
  secret: string
  purpose: string
  context: string
  plaintext: string
  nonce?: Buffer
}): string

export declare function decrypt(args: {
  secrets: Array<string | undefined>
  purpose: string
  context: string
  envelope: string
}): { plaintext: string; keyIndex: number }
