import axios from 'axios'

const API = 'http://127.0.0.1:8000/api'


// ============================================================
// TIPOS DA API
// ============================================================

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
  repo: string
  total: number
  semgrep: number
  trivy: number
  ia: string
}


export interface ResumoResponse {
  total: number

  por_severidade: {
    [key: string]: number
  }

  por_fonte: {
    [key: string]: number
  }

  criticos: number
  altos: number
}


export interface LimparResponse {
  mensagem: string
  removidos: number
}


// ============================================================
// POST /api/scan
// ============================================================

export const iniciarScan = async (
  repoUrl: string
): Promise<ScanResponse> => {

  const response = await axios.post<ScanResponse>(
    `${API}/scan`,
    null,
    {
      params: {
        repo_url: repoUrl
      }
    }
  )

  return response.data
}


// ============================================================
// GET /api/findings
// ============================================================

export const buscarFindings = async (
  severity?: string,
  repoUrl?: string
): Promise<BackendFinding[]> => {

  const response = await axios.get<BackendFinding[]>(
    `${API}/findings`,
    {
      params: {
        severity: severity || undefined,
        repo_url: repoUrl || undefined
      }
    }
  )

  return response.data
}


// ============================================================
// GET /api/resumo
// ============================================================

export const buscarResumo = async (): Promise<ResumoResponse> => {

  const response = await axios.get<ResumoResponse>(
    `${API}/resumo`
  )

  return response.data
}


// ============================================================
// DELETE /api/findings
// ============================================================

export const limparFindings = async (): Promise<LimparResponse> => {

  const response = await axios.delete<LimparResponse>(
    `${API}/findings`
  )

  return response.data
}