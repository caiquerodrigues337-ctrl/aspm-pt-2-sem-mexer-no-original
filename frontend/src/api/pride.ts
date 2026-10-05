import axios from 'axios'

const API = 'http://127.0.0.1:8000/api'

export interface BackendFinding {
  id: string
  repo_url: string
  fonte: string
  rule_id: string
  severity: string
  file_path: string
  line: number
  message: string
  ai_fix: string | null
  fix_validado: boolean | null
  pride_score: number
  created_at: string
}

export interface ScanResponse {
  scan_id: string
  repo: string
  total: number
  semgrep: number
  trivy: number
  gitleaks: number
  ia: string
}

export interface ResumoResponse {
  scan_id: string | null
  total: number
  por_severidade: Record<string, number>
  por_fonte: Record<string, number>
  criticos: number
  altos: number
}

export interface LimparResponse {
  mensagem: string
  removidos: number
}

export const iniciarScan = async (repoUrl: string): Promise<ScanResponse> => {
  const response = await axios.post<ScanResponse>(
    `${API}/scan`,
    null,
    {
      params: {
        repo_url: repoUrl,
      },
    },
  )

  return response.data
}

export const buscarFindings = async (
  severity?: string,
  repoUrl?: string,
): Promise<BackendFinding[]> => {
  const response = await axios.get<BackendFinding[]>(
    `${API}/findings`,
    {
      params: {
        severity: severity || undefined,
        repo_url: repoUrl || undefined,
      },
    },
  )

  return response.data
}

export const buscarResumo = async (): Promise<ResumoResponse> => {
  const response = await axios.get<ResumoResponse>(`${API}/resumo`)
  return response.data
}

export const limparFindings = async (): Promise<LimparResponse> => {
  const response = await axios.delete<LimparResponse>(`${API}/findings`)
  return response.data
}

export interface ChatFindingContext {
  severity?: string
  severidade?: string
  pride_score?: number
  prideScore?: number
  file_path?: string
  arquivo?: string
  message?: string
  problema?: string
  fonte?: string
  rule_id?: string
  ruleId?: string
  ai_fix?: string | null
  fixIa?: string | null
}

export interface ChatResponse {
  resposta: string
}

export const enviarPerguntaClaude = async (
  pergunta: string,
  findings: ChatFindingContext[],
): Promise<ChatResponse> => {
  const response = await axios.post<ChatResponse>(
    `${API}/chat`,
    {
      pergunta,
      findings,
    },
    {
      timeout: 120000,
    },
  )

  return response.data
}

