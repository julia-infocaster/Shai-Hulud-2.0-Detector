export interface PackageEntry {
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  affectedVersions: string[];
}

export interface FileHash {
  sha1?: string;
  sha256: string | string[];
}

export interface MasterPackages {
  version: string;
  lastUpdated: string;
  attackInfo: {
    name: string;
    alias: string;
    firstDetected: string;
    description: string;
  };
  indicators: {
    maliciousFiles: string[];
    maliciousWorkflows: string[];
    fileHashes: Record<string, FileHash>;
    gitHubIndicators: {
      runnerName: string;
      repoDescription: string;
      repoNamePattern?: string;
      workflowTrigger?: string;
    };
    runnerPaths?: string[];
    credentialPaths?: string[];
    primaryInfectionVectors?: string[];
    mavenPackages?: string[];
  };
  // Optional: Used in legacy format
  stats?: {
    totalUniquePackages: number;
    byOrganization: Record<string, number>;
  };
  packages: PackageEntry[];
  // Optional: Used in legacy format
  sources?: string[];
  // New: Data source information for automated updates
  dataSource?: {
    url: string;
    description: string;
    sources: string[];
    fetchedAt: string;
  };
  acknowledgements?: {
    securityResearchers: Array<{
      org: string;
      github: string;
    }>;
  };
}

export interface ScanResult {
  package: string;
  version: string;
  affected: boolean;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'none';
  isDirect: boolean;
  location: string;
}

// Types for advanced security checks
export type SecurityFindingType =
  | 'compromised-package'
  | 'suspicious-script'
  | 'trufflehog-activity'
  | 'shai-hulud-repo'
  | 'secrets-exfiltration'
  | 'malicious-runner'
  | 'malware-hash-match'
  | 'runner-installation'
  | 'malicious-workflow-trigger';

export interface SecurityFinding {
  type: SecurityFindingType;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  location: string;
  line?: number;
  evidence?: string;
}

export interface ScriptCheckResult {
  hasSuspiciousScripts: boolean;
  findings: SecurityFinding[];
}

export interface FileCheckResult {
  found: boolean;
  findings: SecurityFinding[];
}

export interface ScanSummary {
  totalDependencies: number;
  affectedCount: number;
  cleanCount: number;
  results: ScanResult[];
  securityFindings: SecurityFinding[];
  scannedFilesCount: number;
  scannedFiles: string[];
  scanTime: number;
}

export interface PackageJson {
  name?: string;
  version?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

export interface PackageLock {
  name?: string;
  version?: string;
  lockfileVersion?: number;
  packages?: Record<string, PackageLockEntry>;
  dependencies?: Record<string, PackageLockDependency>;
}

export interface PackageLockEntry {
  version?: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  optional?: boolean;
  dependencies?: Record<string, string>;
}

export interface PackageLockDependency {
  version: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  optional?: boolean;
  requires?: Record<string, string>;
  dependencies?: Record<string, PackageLockDependency>;
}

export interface YarnLockEntry {
  version: string;
  resolved?: string;
  integrity?: string;
  dependencies?: Record<string, string>;
}

export interface Inputs {
  failOnCritical: boolean;
  failOnHigh: boolean;
  failOnAny: boolean;
  scanLockfiles: boolean;
  scanNodeModules: boolean;
  outputFormat: 'text' | 'json' | 'sarif';
  workingDirectory: string;
}

export interface SarifResult {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResultEntry[];
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri: string;
  defaultConfiguration: {
    level: 'error' | 'warning' | 'note';
  };
}

export interface SarifResultEntry {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: SarifLocation[];
}

export interface SarifLocation {
  physicalLocation: {
    artifactLocation: {
      uri: string;
    };
    region?: {
      startLine: number;
      startColumn: number;
    };
  };
}
