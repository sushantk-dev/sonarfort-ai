// src/app/core/models.ts

export type Severity = 'BLOCKER' | 'CRITICAL' | 'MAJOR' | 'MINOR' | 'INFO';
export type Outcome  = 'pr_opened' | 'draft_pr' | 'escalated' | 'error' | 'pending';
export type StepStatus = 'pending' | 'running' | 'done' | 'error';

export interface SonarIssue {
  key:       string;
  ruleKey:   string;
  severity:  Severity;
  component: string;       // e.g. "com.example:UserService.java"
  line:      number;
  message:   string;
  effort:    string;
  status:    'OPEN' | 'CONFIRMED' | 'RESOLVED';
  outcome?:  Outcome;
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
  prUrl?:    string;
}

export interface PipelineStep {
  label:   string;
  status:  StepStatus;
  detail?: string;
  ms?:     number;
}

export interface PipelineRun {
  id:        string;
  ruleKey:   string;
  severity:  Severity;
  component: string;
  steps:     PipelineStep[];
  outcome?:  Outcome;
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
  prUrl?:    string;
  ragHits?:  number;
  retries?:  number;
}

export interface RuleKbEntry {
  title:       string;
  description: string;
  fix:         string;
}
