export type ReportIssue = {
  rule: string
  message: string
  line: number
  column: number
  filename: string
  severity: 'error' | 'warning' | 'note'
}

export interface SarifReport {
  version: string
  $schema: string
  runs: SarifRun[]
}

export interface SarifRun {
  tool: SarifTool
  results: SarifResult[]
}

export interface SarifTool {
  driver: SarifDriver
}

export interface SarifDriver {
  name: string
  version: string
  informationUri: string
  rules: SarifRule[]
}

export interface SarifRule {
  id: string
  name: string
  shortDescription: {
    text: string
  }
  fullDescription: {
    text: string
  }
  helpUri?: string
  defaultConfiguration: {
    level: string
  }
}

export interface SarifResult {
  ruleId: string
  level: string
  message: {
    text: string
  }
  locations: SarifLocation[]
}

export interface SarifLocation {
  physicalLocation: {
    artifactLocation: {
      uri: string
    }
    region: {
      startLine: number
      startColumn: number
      endLine: number
      endColumn: number
    }
  }
}
