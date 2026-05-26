// src/app/core/data.service.ts
import { Injectable } from '@angular/core';
import { SonarIssue, PipelineRun, RuleKbEntry } from './models';

@Injectable({ providedIn: 'root' })
export class DataService {

  readonly issues: SonarIssue[] = [
    // { key: 'AY-001', ruleKey: 'java:S2259', severity: 'BLOCKER',   component: 'com.example.service:UserService.java',      line: 87,  message: 'A "NullPointerException" could be thrown; "user" is nullable here.',                       effort: '30min', status: 'RESOLVED', outcome: 'pr_opened', confidence: 'HIGH',   prUrl: 'https://github.com/org/repo/pull/142' },
    // { key: 'AY-002', ruleKey: 'java:S2095', severity: 'CRITICAL',  component: 'com.example.io:FileProcessor.java',          line: 45,  message: '"stream" is never closed. Move the invocation into a try-with-resource.',                  effort: '15min', status: 'RESOLVED', outcome: 'pr_opened', confidence: 'HIGH',   prUrl: 'https://github.com/org/repo/pull/141' },
    // { key: 'AY-003', ruleKey: 'java:S5547', severity: 'CRITICAL',  component: 'com.example.security:CryptoUtil.java',       line: 34,  message: 'Use a stronger cipher algorithm; "DES" is considered obsolete and insecure.',               effort: '1h',    status: 'CONFIRMED', outcome: 'draft_pr',  confidence: 'MEDIUM', prUrl: 'https://github.com/org/repo/pull/143' },
    // { key: 'AY-004', ruleKey: 'java:S106',  severity: 'MAJOR',     component: 'com.example.api:OrderController.java',       line: 55,  message: 'Replace this usage of System.out by a logger.',                                            effort: '5min',  status: 'RESOLVED', outcome: 'pr_opened', confidence: 'HIGH',   prUrl: 'https://github.com/org/repo/pull/144' },
    // { key: 'AY-005', ruleKey: 'java:S2068', severity: 'BLOCKER',   component: 'com.example.config:DatabaseConfig.java',     line: 22,  message: '"password" detected in this expression — review this potentially hard-coded credential.',   effort: '30min', status: 'CONFIRMED', outcome: 'escalated', confidence: 'LOW' },
    // { key: 'AY-006', ruleKey: 'java:S2259', severity: 'CRITICAL',  component: 'com.example.service:ProductService.java',    line: 112, message: 'A "NullPointerException" could be thrown; "product" is nullable here.',                     effort: '30min', status: 'OPEN',      outcome: 'pending' },
    // { key: 'AY-007', ruleKey: 'java:S3776', severity: 'MAJOR',     component: 'com.example.reports:ReportGenerator.java',  line: 78,  message: 'Refactor this method to reduce its Cognitive Complexity from 23 to the 15 allowed.',        effort: '2h',    status: 'OPEN',      outcome: 'pending' },
    // { key: 'AY-008', ruleKey: 'java:S1192', severity: 'MINOR',     component: 'com.example.util:Constants.java',            line: 34,  message: 'Define a constant instead of duplicating the literal "ERROR" 4 times.',                    effort: '5min',  status: 'OPEN',      outcome: 'pending' },
    // { key: 'AY-009', ruleKey: 'java:S2259', severity: 'MAJOR',     component: 'com.example.service:InventoryService.java',  line: 56,  message: 'A "NullPointerException" could be thrown; "item" is nullable here.',                       effort: '30min', status: 'OPEN',      outcome: 'pending' },
    // { key: 'AY-010', ruleKey: 'java:S2095', severity: 'MAJOR',     component: 'com.example.logging:LogService.java',        line: 89,  message: '"reader" is never closed.',                                                                 effort: '15min', status: 'OPEN',      outcome: 'pending' },
    // { key: 'AY-011', ruleKey: 'java:S106',  severity: 'MINOR',     component: 'com.example.debug:DebugHelper.java',         line: 12,  message: 'Replace this usage of System.out.println by a logger.',                                    effort: '5min',  status: 'OPEN',      outcome: 'pending' },
    // { key: 'AY-012', ruleKey: 'java:S1172', severity: 'INFO',       component: 'com.example.util:Utils.java',                line: 203, message: 'Remove this unused method parameter "ctx".',                                               effort: '5min',  status: 'OPEN',      outcome: 'pending' },
  ];

  readonly runs: PipelineRun[] = [
    // {
    //   id: 'run-1', ruleKey: 'java:S2259', severity: 'BLOCKER',
    //   component: 'com.example.service:UserService.java',
    //   ragHits: 3, retries: 0, confidence: 'HIGH', outcome: 'pr_opened',
    //   prUrl: 'https://github.com/org/repo/pull/142',
    //   steps: [
    //     { label: 'Ingest',        status: 'done', detail: 'Parsed S2259 issue — BLOCKER severity',              ms: 120   },
    //     { label: 'Load Repo',     status: 'done', detail: 'Cloned @ abc1234, resolved UserService.java:87',     ms: 2400  },
    //     { label: 'RAG Fetch',     status: 'done', detail: '3 similar fixes retrieved from vector store',         ms: 340   },
    //     { label: 'Planner',       status: 'done', detail: 'Strategy: add null check before dereference (0.91)', ms: 1800  },
    //     { label: 'Generator',     status: 'done', detail: 'Generated diff — 1 hunk, 4 lines changed',           ms: 2200  },
    //     { label: 'Critic',        status: 'done', detail: 'Approved — correct null-guard pattern',               ms: 1600  },
    //     { label: 'Validate',      status: 'done', detail: 'git apply ✓  mvn compile ✓  mvn test ✓',             ms: 14200 },
    //     { label: 'Deliver',       status: 'done', detail: 'PR #142 opened, fix stored in vector DB',             ms: 890   },
    //   ],
    // },
    // {
    //   id: 'run-2', ruleKey: 'java:S5547', severity: 'CRITICAL',
    //   component: 'com.example.security:CryptoUtil.java',
    //   ragHits: 1, retries: 1, confidence: 'MEDIUM', outcome: 'draft_pr',
    //   prUrl: 'https://github.com/org/repo/pull/143',
    //   steps: [
    //     { label: 'Ingest',        status: 'done', detail: 'Parsed S5547 weak cipher issue',                     ms: 110   },
    //     { label: 'Load Repo',     status: 'done', detail: 'Resolved CryptoUtil.java:34',                        ms: 2100  },
    //     { label: 'RAG Fetch',     status: 'done', detail: '1 similar fix retrieved',                             ms: 290   },
    //     { label: 'Planner',       status: 'done', detail: 'Strategy: replace DES with AES-256-GCM',             ms: 2100  },
    //     { label: 'Generator',     status: 'done', detail: 'Generated diff (attempt 1)',                          ms: 2500  },
    //     { label: 'Critic',        status: 'done', detail: 'Rejected — IV reuse risk in CBC mode → retry',       ms: 1700  },
    //     { label: 'Generator ×2',  status: 'done', detail: 'Regenerated using GCM + secure IV',                  ms: 2200  },
    //     { label: 'Validate',      status: 'done', detail: 'git apply ✓  mvn compile ✓  mvn test ✓',             ms: 12800 },
    //     { label: 'Deliver',       status: 'done', detail: 'Draft PR #143 — review required (MEDIUM confidence)', ms: 760  },
    //   ],
    // },
    // {
    //   id: 'run-3', ruleKey: 'java:S2068', severity: 'BLOCKER',
    //   component: 'com.example.config:DatabaseConfig.java',
    //   ragHits: 0, retries: 1, confidence: 'LOW', outcome: 'escalated',
    //   steps: [
    //     { label: 'Ingest',    status: 'done',  detail: 'Parsed S2068 hardcoded credential issue',              ms: 105  },
    //     { label: 'Load Repo', status: 'done',  detail: 'Resolved DatabaseConfig.java:22',                     ms: 1900 },
    //     { label: 'RAG Fetch', status: 'done',  detail: 'No prior fixes found in vector store',                 ms: 200  },
    //     { label: 'Planner',   status: 'done',  detail: 'Strategy: move credential to environment variable',    ms: 2000 },
    //     { label: 'Generator', status: 'done',  detail: 'Generated diff',                                       ms: 2400 },
    //     { label: 'Critic',    status: 'done',  detail: 'Approved with low confidence',                         ms: 1500 },
    //     { label: 'Validate',  status: 'error', detail: 'mvn compile FAILED — @Value wiring missing',           ms: 9200 },
    //     { label: 'Deliver',   status: 'done',  detail: 'Escalation written: escalations/AY-005.md',            ms: 210  },
    //   ],
    // },
  ];

  readonly ruleKb: Record<string, RuleKbEntry> = {
    'java:S2259': {
      title: 'Null Pointer Dereference',
      description: 'A reference to null is dereferenced. This will throw a NullPointerException at runtime.',
      fix: `if (obj != null) { obj.method(); }\n// or: Optional.ofNullable(obj).ifPresent(...)`,
    },
    'java:S2095': {
      title: 'Resource Leak',
      description: 'Resources (streams, connections) opened in this method are never closed.',
      fix: `try (InputStream is = new FileInputStream(path)) {\n  // use stream — auto-closed\n}`,
    },
    'java:S106': {
      title: 'System.out / System.err Usage',
      description: 'Standard outputs should not be used directly to log. Use a logging framework instead.',
      fix: `private static final Logger log =\n    LoggerFactory.getLogger(Foo.class);\nlog.info("value: {}", value);`,
    },
    'java:S5547': {
      title: 'Weak Cipher Algorithm',
      description: 'DES, 3DES and RC4 are cryptographically broken. Use AES-256-GCM.',
      fix: `Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\nbyte[] iv = new byte[12];\nnew SecureRandom().nextBytes(iv);`,
    },
    'java:S2068': {
      title: 'Hardcoded Credentials',
      description: 'Hard-coded passwords or API keys are a high-severity security risk.',
      fix: `// Use environment variable:\nString pw = System.getenv("DB_PASSWORD");\n// or Spring: @Value("\${db.password}")`,
    },
    'java:S3776': {
      title: 'Cognitive Complexity Too High',
      description: 'Method complexity exceeds the allowed threshold. Refactor into smaller methods.',
      fix: `// Extract sub-operations into private methods.\n// Each method should do exactly one thing.`,
    },
  };

  getIssue(key: string): SonarIssue | undefined {
    return this.issues.find(i => i.key === key);
  }

  getRuleKb(ruleKey: string): RuleKbEntry | undefined {
    return this.ruleKb[ruleKey];
  }

  get stats() {
    const total      = this.issues.length;
    const prOpened   = this.issues.filter(i => i.outcome === 'pr_opened').length;
    const draftPr    = this.issues.filter(i => i.outcome === 'draft_pr').length;
    const escalated  = this.issues.filter(i => i.outcome === 'escalated').length;
    const pending    = this.issues.filter(i => i.outcome === 'pending').length;
    return { total, prOpened, draftPr, escalated, pending };
  }
}
