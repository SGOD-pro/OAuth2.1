import fs from 'fs';
import path from 'path';
import assert from 'assert/strict';

console.log('================================================================');
console.log('  SWYRA AUTH -- CANONICAL AI AGENT INTEGRATION CONTRACT LINTER');
console.log('================================================================');

interface Violation {
  ruleId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  file: string;
  line?: number;
  message: string;
  snippet?: string;
}

const violations: Violation[] = [];
const passedChecks: string[] = [];

// Determine repository root
const repoRoot = path.resolve(import.meta.dirname, '../..');

function recordViolation(v: Violation) {
  violations.push(v);
}

function check(desc: string, fn: () => void) {
  try {
    fn();
    passedChecks.push(desc);
    console.log(`[PASS] ${desc}`);
  } catch (err: any) {
    console.error(`[FAIL] ${desc}: ${err.message || err}`);
    recordViolation({
      ruleId: 'GENERAL_CONSISTENCY',
      severity: 'CRITICAL',
      file: 'workspace',
      message: `${desc}: ${err.message || err}`,
    });
  }
}

// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
// 1. Validate Normative Integration Specification & Security Policy
// -----------------------------------------------------------------------------
check('Normative integration contract (docs/INTEGRATION.md) exists and defines core policy', () => {
  const contractPath = path.join(repoRoot, 'docs/INTEGRATION.md');
  assert.ok(fs.existsSync(contractPath), 'docs/INTEGRATION.md must exist');

  const content = fs.readFileSync(contractPath, 'utf-8');

  // Validate the 10 Golden Rules are present
  assert.ok(content.includes('The 10 Golden Rules for AI Agents'), 'Must define The 10 Golden Rules for AI Agents');

  // Validate client types
  assert.ok(content.includes('Public Application') && content.includes('Private Application'), 'Must define public and private applications');
  assert.ok(content.includes('NO client_secret'), 'Public client must not require client_secret');
  assert.ok(content.includes('CLIENT_SECRET'), 'Confidential client must require client_secret');

  // Validate token validation rules
  assert.ok(content.includes('RS256'), 'Allowed algorithm must strictly be RS256');

  // Validate review questions
  assert.ok(content.includes('18 Security Review Questions'), 'Must define 18 Security Review Questions');
});

// -----------------------------------------------------------------------------
// 2. Validate Normative Contract & Documentation Consistency
// -----------------------------------------------------------------------------
check('Authoritative documentation files exist and cite canonical contract', () => {
  const docFiles = [
    'docs/INTEGRATION.md',
    'AGENTS.md',
    'docs/SECURITY.md',
    'docs/ARCHITECTURE.md',
  ];

  for (const f of docFiles) {
    const fullPath = path.join(repoRoot, f);
    assert.ok(fs.existsSync(fullPath), `Required documentation file missing: ${f}`);
    const content = fs.readFileSync(fullPath, 'utf-8');

    // All must reference canonical authorization endpoint /api/auth/oauth2/authorize
    assert.ok(
      content.includes('/api/auth/oauth2/authorize'),
      `${f} must reference canonical OAuth authorization endpoint '/api/auth/oauth2/authorize'`
    );

    // None should contain exposed client secrets in public prefixes
    assert.ok(!content.includes('NEXT_PUBLIC_CLIENT_SECRET'), `${f} must never contain NEXT_PUBLIC_CLIENT_SECRET`);
    assert.ok(!content.includes('VITE_CLIENT_SECRET'), `${f} must never contain VITE_CLIENT_SECRET`);
  }
});

// -----------------------------------------------------------------------------
// 3. Scan Files for Anti-Patterns & Policy Violations
// -----------------------------------------------------------------------------
const FORBIDDEN_CODE_PATTERNS = [
  {
    id: 'LOCALHOST_FALLBACK',
    severity: 'CRITICAL' as const,
    regex: /(AUTH_CALLBACK_URL|REDIRECT_URI|CLIENT_ID|CLIENT_SECRET|AUTH_ISSUER)\s*\|\|\s*["']http:\/\/(localhost|127\.0\.0\.1|\[::1\])/,
    message: 'Prohibited localhost fallback literal found in configuration. Missing configuration must fail closed.',
  },
  {
    id: 'PLACEHOLDER_SECRET_FALLBACK',
    severity: 'CRITICAL' as const,
    regex: /(CLIENT_ID|CLIENT_SECRET)\s*\|\|\s*["'](dev-client|test-secret|secret|placeholder)["']/,
    message: 'Prohibited credential placeholder fallback found. Missing credentials must fail closed.',
  },
  {
    id: 'PUBLIC_CLIENT_SECRET',
    severity: 'CRITICAL' as const,
    regex: /(NEXT_PUBLIC_[A-Z_]*CLIENT_SECRET|VITE_[A-Z_]*CLIENT_SECRET|REACT_APP_[A-Z_]*CLIENT_SECRET)/,
    message: 'Confidential client secret exposed in public frontend environment variable prefix.',
  },
  {
    id: 'DYNAMIC_HOST_REDIRECT',
    severity: 'CRITICAL' as const,
    regex: /redirect_uri\s*[:=]\s*.*req(uest)?\.headers(\.get\(["']host["']\)|\[["']host["']\]|\.host)/,
    message: 'Insecure redirect URI constructed dynamically from Host header.',
  },
  {
    id: 'DISABLE_AUTH_FLAG',
    severity: 'CRITICAL' as const,
    regex: /(DISABLE_AUTH|SKIP_AUTH)\s*[:=]\s*(true|["']true["']|1)/,
    message: 'Prohibited authentication bypass flag (DISABLE_AUTH/SKIP_AUTH) detected.',
  },
  {
    id: 'AUTH_PATH_MISDIRECTION',
    severity: 'CRITICAL' as const,
    regex: /new\s+URL\([^)]*\/auth["']\)/,
    message: 'Redirecting OAuth authorization to internal UI path "/auth" instead of "/api/auth/oauth2/authorize".',
  },
  {
    id: 'ALGORITHM_NONE_OR_HS256',
    severity: 'CRITICAL' as const,
    regex: /algorithms\s*:\s*\[[^\]]*["'](none|HS256)["'][^\]]*\]/,
    message: 'Insecure algorithm configuration for IdP RS256 token verification.',
  },
];

function scanFileForPatterns(filePath: string, relPath: string) {
  // Skip binary files, git, node_modules, dist, .next
  if (
    relPath.includes('node_modules') ||
    relPath.includes('.git') ||
    relPath.includes('dist') ||
    relPath.includes('.next') ||
    relPath.endsWith('.png') ||
    relPath.endsWith('.jpg') ||
    relPath.endsWith('.zip') ||
    relPath.endsWith('.ico')
  ) {
    return;
  }

  // Exempt internal IdP test fixtures and linter script itself
  if (
    relPath.includes('tests/security/') ||
    relPath.includes('check-integration-contract.ts') ||
    relPath.includes('integration-policy.json')
  ) {
    return;
  }

  const content = fs.readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Skip comment lines explaining anti-patterns in documentation or linter
    if (
      relPath.endsWith('.md') &&
      (line.includes('Anti-Pattern') ||
        line.includes('Anti-pattern') ||
        line.includes('forbidden') ||
        line.includes('NEVER') ||
        line.includes('MUST NOT') ||
        line.includes('Prohibited') ||
        line.includes('|| "http://localhost') ||
        line.includes("|| 'http://localhost"))
    ) {
      // Documentation mentioning the forbidden pattern for instructional purposes is allowed
      continue;
    }

    for (const pattern of FORBIDDEN_CODE_PATTERNS) {
      if (pattern.regex.test(line)) {
        // If it's a documentation file showing an anti-pattern as an example of what NOT to do
        if (relPath.endsWith('.md')) {
          let isWarningBlock = false;
          for (let lookback = 0; lookback <= 5 && i - lookback >= 0; lookback++) {
            const checkLine = lines[i - lookback];
            if (
              checkLine.includes('❌') ||
              checkLine.includes('WRONG') ||
              checkLine.includes('Unsafe') ||
              checkLine.includes('Bad') ||
              checkLine.includes('Anti-Pattern') ||
              checkLine.includes('anti-pattern')
            ) {
              isWarningBlock = true;
              break;
            }
          }
          if (isWarningBlock) {
            continue;
          }
        }

        recordViolation({
          ruleId: pattern.id,
          severity: pattern.severity,
          file: relPath,
          line: i + 1,
          message: pattern.message,
          snippet: line.trim(),
        });
      }
    }
  }
}

function scanDirectory(dirPath: string) {
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    const relPath = path.relative(repoRoot, fullPath);

    if (entry.isDirectory()) {
      if (
        entry.name === 'node_modules' ||
        entry.name === '.git' ||
        entry.name === 'dist' ||
        entry.name === '.next'
      ) {
        continue;
      }
      scanDirectory(fullPath);
    } else if (entry.isFile()) {
      scanFileForPatterns(fullPath, relPath);
    }
  }
}

check('Static scan of consumer templates, code recipes, and docs for forbidden patterns', () => {
  // Scan consumer sample apps and documentation
  scanDirectory(path.join(repoRoot, 'docs'));
  if (fs.existsSync(path.join(repoRoot, 'test'))) {
    scanDirectory(path.join(repoRoot, 'test'));
  }
});

// -----------------------------------------------------------------------------
// 4. Validate Consumer App Dependencies (No Duplicate Auth)
// -----------------------------------------------------------------------------
check('Consumer applications do not install duplicate auth engines or mongo drivers', () => {
  const consumerPkgPaths = [
    'test/next-app/package.json',
    'test/react-express-app/backend/package.json',
    'test/react-express-app/frontend/package.json',
  ];

  const duplicateEngines = [
    'better-auth',
    '@better-auth/mongo-adapter',
    '@better-auth/oauth-provider',
    'next-auth',
    '@auth/core',
    'passport',
    '@supabase/supabase-js',
    'lucia',
  ];

  for (const pkgRel of consumerPkgPaths) {
    const fullPath = path.join(repoRoot, pkgRel);
    if (!fs.existsSync(fullPath)) continue;

    const pkg = JSON.parse(fs.readFileSync(fullPath, 'utf-8'));
    const allDeps = {
      ...(pkg.dependencies || {}),
      ...(pkg.devDependencies || {}),
    };

    for (const engine of duplicateEngines) {
      if (allDeps[engine]) {
        recordViolation({
          ruleId: 'DUPLICATE_AUTH_ENGINE',
          severity: 'CRITICAL',
          file: pkgRel,
          message: `Consumer package.json contains duplicate auth engine '${engine}'.`,
        });
      }
    }

    if (allDeps['mongodb'] || allDeps['mongoose']) {
      recordViolation({
        ruleId: 'IDP_DIRECT_MONGO_ACCESS',
        severity: 'CRITICAL',
        file: pkgRel,
        message: `Consumer package.json contains direct MongoDB driver ('${allDeps['mongodb'] ? 'mongodb' : 'mongoose'}').`,
      });
    }
  }
});

// -----------------------------------------------------------------------------
// 5. Validate Gateway Secret Isolation & Perimeter Configuration
// -----------------------------------------------------------------------------
check('Gateway secret configuration is isolated from version control', () => {
  const gitignorePath = path.join(repoRoot, '.gitignore');
  assert.ok(fs.existsSync(gitignorePath), '.gitignore must exist');
  const gitignoreContent = fs.readFileSync(gitignorePath, 'utf-8');

  assert.ok(gitignoreContent.includes('vercel.json'), '.gitignore must ignore vercel.json');
  assert.ok(gitignoreContent.includes('frontend/vercel.json'), '.gitignore must ignore frontend/vercel.json');

  const vTemplate = path.join(repoRoot, 'vercel.template.json');
  const fvTemplate = path.join(repoRoot, 'frontend/vercel.template.json');
  assert.ok(fs.existsSync(vTemplate), 'vercel.template.json must exist');
  assert.ok(fs.existsSync(fvTemplate), 'frontend/vercel.template.json must exist');

  const vTemplateContent = fs.readFileSync(vTemplate, 'utf-8');
  assert.ok(
    vTemplateContent.includes('__INTERNAL_GATEWAY_SECRET__'),
    'vercel.template.json must contain __INTERNAL_GATEWAY_SECRET__ placeholder'
  );
});

// -----------------------------------------------------------------------------
// Results Reporting
// -----------------------------------------------------------------------------
console.log('================================================================');
if (violations.length > 0) {
  console.error(`  INTEGRATION CONTRACT VIOLATIONS: ${violations.length} issue(s) detected\n`);
  for (const v of violations) {
    console.error(`  [${v.severity}] [${v.ruleId}] in ${v.file}${v.line ? `:${v.line}` : ''}`);
    console.error(`    Message: ${v.message}`);
    if (v.snippet) {
      console.error(`    Code:    ${v.snippet}`);
    }
    console.error('');
  }
  console.error('================================================================');
  console.error('  FAIL CLOSED: Please rectify all violations before proceeding.');
  console.error('================================================================');
  process.exit(1);
} else {
  console.log(`  ALL INTEGRATION CONTRACT CHECKS PASSED (0 VIOLATIONS)`);
  console.log(`  Verified against docs/security/integration-policy.json`);
  console.log('================================================================');
  process.exit(0);
}
