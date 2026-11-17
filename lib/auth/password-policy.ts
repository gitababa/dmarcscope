// Password rules for local accounts: at least 12 characters, at most 256,
// not one of the most common passwords of that length, and not built from
// the account's own address.
//
// The list holds the most frequent 12+ character entries of public password
// breach corpora; a longer list would add little against an attacker who is
// also rate-limited and stopped by TOTP.

const COMMON = new Set(
  [
    '123456789012', '1234567890123', '12345678901234', '123456789012345', '1234567890123456',
    '111111111111', '000000000000', '123123123123', '121212121212', '987654321098',
    '098765432109', '112233445566', '123321123321', '147258369147', '012345678901',
    'qwertyuiopas', 'qwertyuiop12', 'qwertyuiop123', 'qwerty123456', '123456qwerty',
    'qwertyqwerty', 'asdfghjkl123', 'asdfasdfasdf', 'zxcvbnm12345', '1q2w3e4r5t6y',
    '1qaz2wsx3edc', 'qazwsxedcrfv', '1qazxsw23edc', 'zaq12wsxcde3', 'q1w2e3r4t5y6',
    'password1234', 'password12345', 'password123456', 'passwordpassword', 'password1234!',
    'password123!', 'password@123', 'password!123', 'mypassword123', 'mypassword12',
    'passw0rd1234', 'p@ssw0rd1234', 'p@ssword1234', 'p@ssw0rd123!', 'changeme1234',
    'changemenow1', 'welcome12345', 'welcome123456', 'welcome@1234', 'welcome2024!',
    'welcome2025!', 'welcome2026!', 'letmein12345', 'letmein123456', 'iloveyou1234',
    'iloveyou12345', 'administrator', 'administrator1', 'administrator123', 'admin1234567',
    'admin12345678', 'adminadmin123', 'superman1234', 'batman123456', 'football1234',
    'baseball1234', 'basketball12', 'basketball123', 'sunshine1234', 'princess1234',
    'monkey123456', 'dragon123456', 'master123456', 'shadow123456', 'michael12345',
    'jennifer1234', 'trustno11234', 'starwars1234', 'whatever1234', 'abcdefghijkl',
    'abcdefgh1234', 'abc123456789', 'abcd12345678', 'aaaaaaaaaaaa', 'abcabcabcabc',
    'dmarcscope123', 'dmarcscope1234', 'correcthorsebatterystaple', 'thequickbrownfox',
    'spring2026!!', 'summer2026!!', 'autumn2026!!', 'winter2026!!', 'january2026!',
    'company12345', 'company123456', 'secret123456', 'mysecret1234', 'access123456',
    'default12345', 'computer1234', 'internet1234', 'security1234', 'liverpool123',
  ].map((p) => p.toLowerCase())
)

export const PASSWORD_MIN = 12
export const PASSWORD_MAX = 256

export function passwordProblem(password: string, email: string): string | null {
  if (password.length < PASSWORD_MIN) return `Use at least ${PASSWORD_MIN} characters.`
  if (password.length > PASSWORD_MAX) return `Use at most ${PASSWORD_MAX} characters.`
  const lower = password.toLowerCase()
  if (COMMON.has(lower)) return 'That password is one of the most common ones. Choose another.'
  if (new Set(lower).size <= 2) return 'That password repeats the same characters. Choose another.'
  const local = email.toLowerCase().split('@')[0] ?? ''
  if (lower === email.toLowerCase() || (local.length >= 4 && lower.replace(/[^a-z0-9]/g, '') === local.replace(/[^a-z0-9]/g, ''))) {
    return 'The password must not be your email address.'
  }
  return null
}
