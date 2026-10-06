import React, { useState, useEffect } from 'react';
import { 
  Play, 
  AlertTriangle, 
  ShieldCheck, 
  Sparkles, 
  Send, 
  X, 
  Search,
  Code2,
  Globe,
  User,
  Info,
  SlidersHorizontal,
  RefreshCw,
  Camera,
  Upload,
  Lock,
  Mail,
  CheckCircle2,
  CreditCard,
  Zap,
  Shield,
  LogOut,
  UserPlus,
  LogIn,
  ArrowLeft,
  ChevronRight,
  Home,
  LayoutDashboard,
  Check,
  Bot,
  MessageSquare
} from 'lucide-react';

import logoHeader from './logo_comprida.jpeg';
import bgHero from './tela_inicial.jpeg';

import {
  iniciarScan,
  buscarFindings,
  type BackendFinding,
  type ScanResponse,
} from './api/pride';

interface Finding {
  id: string;
  repoUrl: string;
  fonte: string;
  ruleId: string;
  arquivo: string;
  linha: number;
  severidade: string;
  prideScore: number;
  problema: string;
  fixIa: string;
  fixValidado: boolean | null;
}

interface UserProfile {
  email: string;
  password?: string;
  username: string;
  defaultRepo: string;
  profilePic: string;
  currentPlan: 'Starter' | 'Pro' | 'Enterprise';
  scansUsed: number;
  maxScans: number;
}

const BRAND_GREEN = "#00FF41";

// HELPER PARA CORES DAS SEVERIDADES
const getSeverityColorClass = (sev: string) => {
  const s = sev.toLowerCase();
  if (s.includes('crític') || s === 'critical') return 'text-rose-500 font-bold';
  if (s === 'alto' || s === 'high') return 'text-amber-500 font-bold';
  if (s.includes('méd') || s === 'medium') return 'text-yellow-400 font-bold';
  if (s === 'baixo' || s === 'low') return 'text-sky-400 font-bold';
  return 'text-slate-300';
};

const getSourceLabel = (fonte: string) => {
  const source = (fonte || '').toLowerCase();
  if (source === 'semgrep') return 'SAST · Semgrep';
  if (source === 'trivy') return 'SCA · Trivy';
  return fonte || 'Desconhecida';
};

const getSourceColorClass = (fonte: string) => {
  const source = (fonte || '').toLowerCase();
  if (source === 'semgrep') return 'text-emerald-400 border-emerald-900/60 bg-emerald-950/30';
  if (source === 'trivy') return 'text-cyan-400 border-cyan-900/60 bg-cyan-950/30';
  return 'text-zinc-300 border-zinc-800 bg-zinc-900';
};

const mapBackendFinding = (finding: BackendFinding): Finding => ({
  id: finding.id,
  repoUrl: finding.repo_url,
  fonte: (finding.fonte || 'desconhecida').toLowerCase(),
  ruleId: finding.rule_id || 'N/A',
  arquivo: finding.file_path || 'N/A',
  linha: Number(finding.line || 0),
  severidade: (finding.severity || 'UNKNOWN').toUpperCase(),
  prideScore: Number(finding.pride_score || 0),
  problema: finding.message || 'Sem descrição disponível.',
  fixIa: finding.ai_fix || '',
  fixValidado: finding.fix_validado,
});

const translations: Record<string, any> = {
  pt: {
    badgeTag: "PLATAFORMA ASPM & SEGURANÇA EM TEMPO REAL",
    heroTitleLanding: "Análise de Código Ilimitada,",
    heroTitleGreen: "Proteção Instantânea.",
    heroDescLanding: "Monitore repositórios, corrija vulnerabilidades com inteligência artificial e mantenha sua aplicação blindada antes da publicação.",
    inputEmailPlaceholder: "Digite seu e-mail para começar",
    btnCreateAccount: "Criar Conta",
    btnAlreadyHaveAccount: "Já possui conta?",
    footerRights: "© 2026 CodeShield Security Inc. Todos os direitos reservados.",
    loginTitle: "Acessar Plataforma",
    registerTitle: "Criar Nova Conta",
    labelUsername: "Nome de Usuário",
    labelEmail: "E-mail",
    labelPassword: "Senha",
    btnLoginSubmit: "Entrar na Conta",
    btnRegisterSubmit: "Criar Conta",
    linkSwitchToRegister: "Não tem conta? Cadastre-se aqui",
    linkSwitchToLogin: "Já possui conta? Faça login",
    errEmailExists: "E-mail já cadastrado! Faça login ou escolha outro.",
    errAuthFailed: "E-mail ou senha incorretos!",

    navDashboard: "Dashboard",
    navPricing: "Planos & Assinaturas",
    navAccount: "Minha Conta",
    btnBackHome: "Voltar à Tela Inicial",
    logoutBtn: "Sair da Conta",

    heroTitle: "Proteja seu código antes que o ataque aconteça.",
    heroDesc: "Analise repositórios em busca de falhas de segurança, identifique vulnerabilidades em tempo real e utilize nossa IA nativa para correções.",
    repoPlaceholder: "https://github.com/usuario/repositorio.git",
    scanBtn: "Iniciar Scan",
    scanningBtn: "Analisando...",
    scanLimitReached: "Limite de scans atingido para seu plano atual.",

    metricTotal: "TOTAL",
    metricCritical: "CRÍTICOS",
    metricHigh: "ALTOS",
    metricMedium: "MÉDIOS",
    metricLow: "BAIXOS",
    metricSast: "SAST",
    metricSca: "SCA",

    findingsTitle: "Security Findings",
    searchPlaceholder: "Buscar arquivo ou problema...",
    filterAllSeverities: "Todas Severidades",
    filterAllSources: "Todas Fontes",
    thSource: "FONTE",
    thRule: "REGRA / CVE",
    thFile: "ARQUIVO",
    thLine: "LINHA",
    thSeverity: "SEVERIDADE",
    thPride: "PRIDE SCORE",
    thIssue: "PROBLEMA",
    thFix: "FIX IA",
    aiDisabled: "IA desativada",
    emptyFindings: "Nenhum finding encontrado até o momento.",
    emptyFindingsDesc: "Insira a URL de um repositório acima e clique em 'Iniciar Scan' para analisar.",

    aiTitle: "Assistente CodeShield IA",
    aiInputPlaceholder: "Pergunte como aplicar a correção...",
    aiInitialGreeting: (prob: string, arq: string, lin: number | string, fix: string) => 
      `Olá! Identifiquei a vulnerabilidade "${prob}" no arquivo ${arq} (Linha ${lin}).\n\nSugestão de Correção: ${fix}. Como posso te ajudar a implementar?`,
    aiResponsePrefix: (usrText: string) => `Analisando "${usrText}"...\nPara este cenário, recomendo aplicar a correção diretamente utilizando parâmetros isolados e sanitização antes do commit.`,

    claudeTitle: "Chatbot Claude (Anthropic)",
    claudeDesc: "Tire dúvidas complexas sobre arquitetura de segurança, DevSecOps e Pentest com o Claude.",
    claudePlaceholder: "Pergunte algo para o Claude sobre segurança de código...",
    claudeGreeting: "Olá! Sou o Claude. Como posso ajudar com a segurança do seu código hoje?",

    welcomeTitle: "Bem-vindo ao CodeShield!",
    welcomeMessage: "Sua plataforma ASPM de segurança em tempo real está pronta para proteger seus repositórios contra vulnerabilidades.",
    welcomeBtn: "Acessar Painel",

    accountTitle: "Configurações da Conta",
    labelDefaultRepo: "Repositório Padrão",
    labelProfilePic: "Foto de Perfil (URL ou Arquivo)",
    uploadPicBtn: "Carregar Imagem Local",
    saveSettings: "Salvar Preferências",
    prefSaved: "Preferências salvas com sucesso!",

    pricingTitle: "Planos & Assinaturas",
    pricingDesc: "Escolha o plano ideal para blindar suas aplicações do desenvolvimento à produção.",
    currentPlanTag: "PLANO ATUAL",
    btnSelectPlan: "Assinar Plano",
    btnActivePlan: "Plano Ativo"
  },
  en: {
    badgeTag: "ASPM PLATFORM & REAL-TIME SECURITY",
    heroTitleLanding: "Unlimited Code Analysis,",
    heroTitleGreen: "Instant Protection.",
    heroDescLanding: "Monitor repositories, fix vulnerabilities with artificial intelligence, and keep your app secure before deployment.",
    inputEmailPlaceholder: "Enter your email to get started",
    btnCreateAccount: "Get Started",
    btnAlreadyHaveAccount: "Already have an account?",
    footerRights: "© 2026 CodeShield Security Inc. All rights reserved.",
    loginTitle: "Login to Platform",
    registerTitle: "Create New Account",
    labelUsername: "Username",
    labelEmail: "Email",
    labelPassword: "Password",
    btnLoginSubmit: "Sign In",
    btnRegisterSubmit: "Create Account",
    linkSwitchToRegister: "Don't have an account? Sign up here",
    linkSwitchToLogin: "Already have an account? Sign in",
    errEmailExists: "Email already registered! Please sign in or use another.",
    errAuthFailed: "Invalid email or password!",

    navDashboard: "Dashboard",
    navPricing: "Plans & Subscriptions",
    navAccount: "My Account",
    btnBackHome: "Back to Main Screen",
    logoutBtn: "Sign Out",

    heroTitle: "Protect your code before the attack happens.",
    heroDesc: "Scan repositories for security flaws, identify vulnerabilities in real time, and use native AI for automatic fixes.",
    repoPlaceholder: "https://github.com/user/repository.git",
    scanBtn: "Start Scan",
    scanningBtn: "Scanning...",
    scanLimitReached: "Scan limit reached for your current plan.",

    metricTotal: "TOTAL",
    metricCritical: "CRITICAL",
    metricHigh: "HIGH",
    metricMedium: "MEDIUM",
    metricLow: "LOW",
    metricSast: "SAST",
    metricSca: "SCA",

    findingsTitle: "Security Findings",
    searchPlaceholder: "Search file or vulnerability...",
    filterAllSeverities: "All Severities",
    filterAllSources: "All Sources",
    thSource: "SOURCE",
    thRule: "RULE / CVE",
    thFile: "FILE",
    thLine: "LINE",
    thSeverity: "SEVERITY",
    thPride: "PRIDE SCORE",
    thIssue: "ISSUE",
    thFix: "AI FIX",
    aiDisabled: "AI disabled",
    emptyFindings: "No findings discovered yet.",
    emptyFindingsDesc: "Enter a repository URL above and click 'Start Scan' to analyze.",

    aiTitle: "CodeShield AI Assistant",
    aiInputPlaceholder: "Ask how to apply the fix...",
    aiInitialGreeting: (prob: string, arq: string, lin: number | string, fix: string) => 
      `Hello! I identified the vulnerability "${prob}" in file ${arq} (Line ${lin}).\n\nFix Suggestion: ${fix}. How can I assist you in implementing this?`,
    aiResponsePrefix: (usrText: string) => `Analyzing "${usrText}"...\nFor this scenario, I recommend applying the fix directly using isolated parameters and input sanitization before committing.`,

    claudeTitle: "Claude Chatbot (Anthropic)",
    claudeDesc: "Ask complex security architecture, DevSecOps, and Pentesting questions to Claude.",
    claudePlaceholder: "Ask Claude anything about code security...",
    claudeGreeting: "Hello! I'm Claude. How can I assist you with your code security today?",

    welcomeTitle: "Welcome to CodeShield!",
    welcomeMessage: "Your real-time ASPM security platform is ready to shield your code repositories against vulnerabilities.",
    welcomeBtn: "Access Dashboard",

    accountTitle: "Account Settings",
    labelDefaultRepo: "Default Repository",
    labelProfilePic: "Profile Picture (URL or File)",
    uploadPicBtn: "Upload Local Image",
    saveSettings: "Save Preferences",
    prefSaved: "Preferences saved successfully!",

    pricingTitle: "Plans & Subscriptions",
    pricingDesc: "Choose the best plan to shield your applications from development to production.",
    currentPlanTag: "CURRENT PLAN",
    btnSelectPlan: "Subscribe Plan",
    btnActivePlan: "Active Plan"
  },
  es: {
    badgeTag: "PLATAFORMA ASPM Y SEGURIDAD EN TIEMPO REAL",
    heroTitleLanding: "Análisis de Código Ilimitado,",
    heroTitleGreen: "Protección Instantánea.",
    heroDescLanding: "Monitorea repositorios, corrige vulnerabilidades con inteligencia artificial y mantén tu aplicación blindada antes de la publicación.",
    inputEmailPlaceholder: "Ingresa tu e-mail para comenzar",
    btnCreateAccount: "Crear Cuenta",
    btnAlreadyHaveAccount: "¿Ya tienes cuenta?",
    footerRights: "© 2026 CodeShield Security Inc. Todos los derechos reservados.",
    loginTitle: "Acceder a la Plataforma",
    registerTitle: "Crear Nueva Cuenta",
    labelUsername: "Nombre de Usuario",
    labelEmail: "Correo electrónico",
    labelPassword: "Contraseña",
    btnLoginSubmit: "Iniciar Sesión",
    btnRegisterSubmit: "Crear Cuenta",
    linkSwitchToRegister: "¿No tienes cuenta? Regístrate aquí",
    linkSwitchToLogin: "¿Ya tienes cuenta? Inicia sesión",
    errEmailExists: "¡E-mail ya registrado! Inicia sesión o usa otro.",
    errAuthFailed: "¡E-mail o contraseña incorrectos!",

    navDashboard: "Panel",
    navPricing: "Planes y Suscripciones",
    navAccount: "Mi Cuenta",
    btnBackHome: "Volver a la Pantalla Principal",
    logoutBtn: "Cerrar Sesión",

    heroTitle: "Protege tu código antes de que ocurra el ataque.",
    heroDesc: "Escanea repositorios en busca de fallos de seguridad, identifica vulnerabilidades en tiempo real y usa nuestra IA nativa para correcciones.",
    repoPlaceholder: "https://github.com/usuario/repositorio.git",
    scanBtn: "Iniciar Escaneo",
    scanningBtn: "Analizando...",
    scanLimitReached: "Límite de escaneos alcanzado para tu plan actual.",

    metricTotal: "TOTAL",
    metricCritical: "CRÍTICOS",
    metricHigh: "ALTOS",
    metricMedium: "MÉDIOS",
    metricLow: "BAJOS",
    metricSast: "SAST",
    metricSca: "SCA",

    findingsTitle: "Hallazgos de Seguridad",
    searchPlaceholder: "Buscar archivo o problema...",
    filterAllSeverities: "Todas Severidades",
    filterAllSources: "Todas las Fuentes",
    thSource: "FUENTE",
    thRule: "REGLA / CVE",
    thFile: "ARCHIVO",
    thLine: "LÍNEA",
    thSeverity: "SEVERIDAD",
    thPride: "PUNTAJE PRIDE",
    thIssue: "PROBLEMA",
    thFix: "SOLUCIÓN IA",
    aiDisabled: "IA desactivada",
    emptyFindings: "No se encontraron hallazgos hasta el momento.",
    emptyFindingsDesc: "Ingrese una URL de repositorio arriba y haga clic en 'Iniciar Escaneo'.",

    aiTitle: "Asistente CodeShield IA",
    aiInputPlaceholder: "Pregunta cómo aplicar la corrección...",
    aiInitialGreeting: (prob: string, arq: string, lin: number | string, fix: string) => 
      `¡Hola! Identifiqué la vulnerabilidad "${prob}" en el archivo ${arq} (Línea ${lin}).\n\nSugerencia de corrección: ${fix}. ¿Cómo puedo ayudarte a implementarla?`,
    aiResponsePrefix: (usrText: string) => `Analizando "${usrText}"...\nPara este escenario, recomiendo aplicar la corrección directamente utilizando parámetros aislados y desinfección antes del commit.`,

    claudeTitle: "Chatbot Claude (Anthropic)",
    claudeDesc: "Resuelve preguntas complejas sobre arquitectura de seguridad, DevSecOps y Pentesting con Claude.",
    claudePlaceholder: "Pregunta a Claude sobre seguridad de código...",
    claudeGreeting: "¡Hola! Soy Claude. ¿Cómo puedo ayudarte hoy con la seguridad de tu código?",

    welcomeTitle: "¡Bienvenido a CodeShield!",
    welcomeMessage: "Tu plataforma ASPM de seguridad en tiempo real está lista para proteger tus repositorios.",
    welcomeBtn: "Acceder al Panel",

    accountTitle: "Configuración de la Cuenta",
    labelDefaultRepo: "Repositorio Predeterminado",
    labelProfilePic: "Foto de Perfil (URL o Archivo)",
    uploadPicBtn: "Cargar Imagen Local",
    saveSettings: "Guardar Preferencias",
    prefSaved: "¡Preferencias guardadas con éxito!",

    pricingTitle: "Planes y Suscripciones",
    pricingDesc: "Elige el plan ideal para blindar tus aplicaciones desde el desarrollo hasta la producción.",
    currentPlanTag: "PLAN ACTUAL",
    btnSelectPlan: "Suscribir Plan",
    btnActivePlan: "Plan Activo"
  }
};

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'pricing' | 'account'>('dashboard');
  const [showLandingScreen, setShowLandingScreen] = useState(true);
  const [showWelcomePopup, setShowWelcomePopup] = useState(false);

  const [lang, setLang] = useState<'pt' | 'en' | 'es'>(() => {
    return (localStorage.getItem('shield_lang') as any) || 'pt';
  });

  const [registeredUsers, setRegisteredUsers] = useState<UserProfile[]>(() => {
    const saved = localStorage.getItem('shield_registered_users');
    return saved ? JSON.parse(saved) : [
      {
        email: "analista@codeshield.io",
        password: "123",
        username: "Analista SOC",
        defaultRepo: "https://github.com/maickryamassaki/CodeShield-ASPM",
        profilePic: "",
        currentPlan: "Pro",
        scansUsed: 12,
        maxScans: 100
      }
    ];
  });

  const [currentUser, setCurrentUser] = useState<UserProfile | null>(() => {
    const saved = localStorage.getItem('shield_current_user');
    return saved ? JSON.parse(saved) : null;
  });

  const [authMode, setAuthMode] = useState<'login' | 'register'>('login');
  const [authEmail, setAuthEmail] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [authUsername, setAuthUsername] = useState('');
  const [authError, setAuthError] = useState('');

  const [findings, setFindings] = useState<Finding[]>([]);
  const [scanSummary, setScanSummary] = useState<ScanResponse | null>(null);
  const t = translations[lang] || translations.pt;

  const [repoUrl, setRepoUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState('');
  const [scanProgress, setScanProgress] = useState(0);
  const [scanError, setScanError] = useState('');
  const [saveAlert, setSaveAlert] = useState(false);

  // Modal de IA (Ação do Finding)
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [chatMessages, setChatMessages] = useState<{ sender: 'ai' | 'user'; text: string }[]>([]);
  const [inputAi, setInputAi] = useState('');

  // CHATBOT CLAUDE (NOVO)
  const [showClaudeModal, setShowClaudeModal] = useState(false);
  const [claudeMessages, setClaudeMessages] = useState<{ sender: 'claude' | 'user'; text: string }[]>([]);
  const [inputClaude, setInputClaude] = useState('');

  // Filtros
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('todos');
  const [filterSource, setFilterSource] = useState('todos');

  useEffect(() => {
    localStorage.setItem('shield_registered_users', JSON.stringify(registeredUsers));
  }, [registeredUsers]);

  // Mantém a sessão local e carrega findings reais do repositório padrão.
  useEffect(() => {
    if (currentUser) {
      localStorage.setItem('shield_current_user', JSON.stringify(currentUser));

      const defaultRepo = currentUser.defaultRepo || 'https://github.com/maickryamassaki/CodeShield-ASPM';
      setRepoUrl(defaultRepo);
      setShowLandingScreen(false);

      buscarFindings(undefined, defaultRepo)
        .then((dados) => setFindings(dados.map(mapBackendFinding)))
        .catch((erro) => {
          console.error('[CodeShield] Falha ao carregar findings:', erro);
        });
    } else {
      localStorage.removeItem('shield_current_user');
      setFindings([]);
      setScanSummary(null);
    }
  }, [currentUser?.email, currentUser?.defaultRepo]);

  useEffect(() => {
    setClaudeMessages([
      {
        sender: 'claude',
        text: `${t.claudeGreeting}

${t.aiDisabled}: configure ANTHROPIC_API_KEY no backend para habilitar este recurso.`
      }
    ]);
  }, [lang, t.claudeGreeting, t.aiDisabled]);

  const handleLangChange = (newLang: 'pt' | 'en' | 'es') => {
    setLang(newLang);
    localStorage.setItem('shield_lang', newLang);
  };

  const handleStartAuth = (mode: 'login' | 'register') => {
    setAuthMode(mode);
    setShowLandingScreen(false);
    setAuthError('');
  };

  const handleLogout = () => {
    setCurrentUser(null);
    setFindings([]);
    setScanSummary(null);
    setScanError('');
    setShowLandingScreen(true);
    setShowWelcomePopup(false);
  };

  const handleAuthSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError('');

    if (authMode === 'register') {
      const existing = registeredUsers.find(u => u.email.toLowerCase() === authEmail.toLowerCase());
      if (existing) {
        setAuthError(t.errEmailExists);
        return;
      }

      const newUser: UserProfile = {
        email: authEmail,
        password: authPassword,
        username: authUsername || authEmail.split('@')[0],
        defaultRepo: "https://github.com/maickryamassaki/CodeShield-ASPM",
        profilePic: "",
        currentPlan: "Starter",
        scansUsed: 0,
        maxScans: 20
      };

      setRegisteredUsers(prev => [...prev, newUser]);
      setCurrentUser(newUser);
      setShowWelcomePopup(true); // Exibe o popup somente ao realizar a autenticação
      return;
    }

    if (authMode === 'login') {
      const user = registeredUsers.find(
        u => u.email.toLowerCase() === authEmail.toLowerCase() && u.password === authPassword
      );

      if (!user) {
        setAuthError(t.errAuthFailed);
        return;
      }

      setCurrentUser(user);
      setShowWelcomePopup(true); // Exibe o popup somente ao realizar a autenticação
    }
  };

  const handleStartScan = async () => {
    if (!currentUser) return;

    if (currentUser.scansUsed >= currentUser.maxScans) {
      alert(t.scanLimitReached);
      return;
    }

    const repo = repoUrl.trim();
    if (!repo) {
      alert(lang === 'pt' ? 'Por favor, insira a URL de um repositório Git.' : lang === 'es' ? 'Ingrese la URL de un repositorio Git.' : 'Please enter a Git repository URL.');
      return;
    }

    setIsScanning(true);
    setScanProgress(10);
    setScanError('');
    setScanSummary(null);
    setScanMessage(lang === 'pt' ? 'Enviando repositório para análise...' : lang === 'es' ? 'Enviando repositorio para análisis...' : 'Sending repository for analysis...');

    try {
      setScanProgress(25);
      setScanMessage(lang === 'pt' ? 'Executando Semgrep (SAST) e Trivy (SCA)...' : lang === 'es' ? 'Ejecutando Semgrep (SAST) y Trivy (SCA)...' : 'Running Semgrep (SAST) and Trivy (SCA)...');

      const resultado = await iniciarScan(repo);
      setScanSummary(resultado);

      setScanProgress(80);
      setScanMessage(lang === 'pt' ? 'Carregando findings do banco...' : lang === 'es' ? 'Cargando hallazgos de la base...' : 'Loading findings from database...');

      const dados = await buscarFindings(undefined, repo);
      setFindings(dados.map(mapBackendFinding));

      setScanProgress(100);
      setScanMessage(
        lang === 'pt'
          ? `Scan concluído: ${resultado.semgrep} SAST + ${resultado.trivy} SCA.`
          : lang === 'es'
            ? `Escaneo finalizado: ${resultado.semgrep} SAST + ${resultado.trivy} SCA.`
            : `Scan complete: ${resultado.semgrep} SAST + ${resultado.trivy} SCA.`
      );

      const updated = { ...currentUser, scansUsed: currentUser.scansUsed + 1 };
      setCurrentUser(updated);
      setRegisteredUsers(prev => prev.map(u => u.email === updated.email ? updated : u));
    } catch (erro: any) {
      console.error('[CodeShield] Erro ao executar scan:', erro);

      const detalhe = erro?.response?.data?.erro || erro?.response?.data?.detail || erro?.message;
      setScanError(
        lang === 'pt'
          ? `Falha ao executar o scan${detalhe ? `: ${detalhe}` : '.'}`
          : lang === 'es'
            ? `Error al ejecutar el escaneo${detalhe ? `: ${detalhe}` : '.'}`
            : `Scan failed${detalhe ? `: ${detalhe}` : '.'}`
      );
      setScanProgress(0);
    } finally {
      setIsScanning(false);
    }
  };

  const handleOpenAiModal = (finding: Finding) => {
    setSelectedFinding(finding);
    setChatMessages([
      {
        sender: 'ai',
        text: finding.fixIa
          ? t.aiInitialGreeting(finding.problema, finding.arquivo, finding.linha || '—', finding.fixIa)
          : `${t.aiDisabled}. O finding continua disponível para análise manual.`
      }
    ]);
  };

  const handleSendAiMessage = () => {
    if (!inputAi.trim()) return;

    const userText = inputAi;
    setChatMessages(prev => [...prev, { sender: 'user', text: userText }]);
    setInputAi('');
    setChatMessages(prev => [
      ...prev,
      {
        sender: 'ai',
        text: `${t.aiDisabled}. Configure a API da Anthropic no backend para habilitar respostas interativas.`
      }
    ]);
  };

  // O chat visual é mantido, mas não simula respostas enquanto a IA estiver desativada.
  const handleSendClaudeMessage = () => {
    if (!inputClaude.trim()) return;

    const text = inputClaude;
    setClaudeMessages(prev => [
      ...prev,
      { sender: 'user', text },
      {
        sender: 'claude',
        text: `${t.aiDisabled}. Configure ANTHROPIC_API_KEY no backend para habilitar o chatbot.`
      }
    ]);
    setInputClaude('');
  };

  // UPLOAD DE FOTO DE PERFIL
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file && currentUser) {
      const reader = new FileReader();
      reader.onloadend = () => {
        const base64 = reader.result as string;
        setCurrentUser({ ...currentUser, profilePic: base64 });
      };
      reader.readAsDataURL(file);
    }
  };

  const handleSelectPlan = (planName: 'Starter' | 'Pro' | 'Enterprise', maxScans: number) => {
    if (currentUser) {
      const updated = { ...currentUser, currentPlan: planName, maxScans };
      setCurrentUser(updated);
      setRegisteredUsers(prev => prev.map(u => u.email === updated.email ? updated : u));
      alert(`Plano ${planName} assinado com sucesso!`);
    }
  };

  const handleSaveAccount = (e: React.FormEvent) => {
    e.preventDefault();
    if (currentUser) {
      setRegisteredUsers(prev => prev.map(u => u.email === currentUser.email ? currentUser : u));
      setSaveAlert(true);
      setTimeout(() => setSaveAlert(false), 3000);
    }
  };

  const filteredFindings = findings.filter(f => {
    const termo = searchTerm.toLowerCase();
    const matchSearch =
      f.arquivo.toLowerCase().includes(termo) ||
      f.problema.toLowerCase().includes(termo) ||
      f.ruleId.toLowerCase().includes(termo) ||
      f.fonte.toLowerCase().includes(termo);

    const matchSev = filterSeverity === 'todos' || f.severidade.toLowerCase() === filterSeverity.toLowerCase();
    const matchSource = filterSource === 'todos' || f.fonte.toLowerCase() === filterSource.toLowerCase();

    return matchSearch && matchSev && matchSource;
  });

  const countCritical = findings.filter(f => f.severidade === 'CRITICAL').length;
  const countHigh = findings.filter(f => f.severidade === 'HIGH').length;
  const countMedium = findings.filter(f => f.severidade === 'MEDIUM').length;
  const countLow = findings.filter(f => f.severidade === 'LOW').length;
  const countSast = findings.filter(f => f.fonte === 'semgrep').length;
  const countSca = findings.filter(f => f.fonte === 'trivy').length;

  // LANDING PAGE ESTILO NETFLIX
  if (showLandingScreen && !currentUser) {
    return (
      <div className="relative min-h-screen bg-black text-white flex flex-col justify-between overflow-hidden animate-fadeIn">
        <div 
          className="absolute inset-0 bg-cover bg-center bg-no-repeat opacity-40 transform scale-105 transition-transform duration-1000 ease-out"
          style={{ backgroundImage: `url(${bgHero})` }}
        />
        <div className="absolute inset-0 bg-gradient-to-t from-black via-black/60 to-black/80" />

        <header className="relative z-10 max-w-7xl mx-auto w-full px-6 py-6 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            {logoHeader ? (
              <img src={logoHeader} alt="CodeShield" className="h-10 w-auto object-contain rounded hover:scale-105 transition-transform" />
            ) : (
              <span className="font-extrabold text-xl tracking-wider" style={{ color: BRAND_GREEN }}>CODESHIELD</span>
            )}
          </div>

          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-1.5 bg-black/60 border border-zinc-800 px-3 py-1.5 rounded-xl text-xs backdrop-blur-md">
              <Globe className="w-3.5 h-3.5" style={{ color: BRAND_GREEN }} />
              <select 
                value={lang} 
                onChange={(e) => handleLangChange(e.target.value as any)}
                className="bg-transparent text-slate-200 focus:outline-none cursor-pointer text-xs"
              >
                <option value="pt" className="bg-zinc-900 text-white">Português (PT)</option>
                <option value="en" className="bg-zinc-900 text-white">English (EN)</option>
                <option value="es" className="bg-zinc-900 text-white">Español (ES)</option>
              </select>
            </div>

            <button 
              onClick={() => handleStartAuth('login')}
              style={{ backgroundColor: BRAND_GREEN }}
              className="text-black font-bold text-xs px-5 py-2 rounded-xl hover:opacity-90 hover:scale-105 transition-all shadow-lg"
            >
              {t.btnAlreadyHaveAccount}
            </button>
          </div>
        </header>

        <main className="relative z-10 max-w-4xl mx-auto px-6 text-center my-auto space-y-6 py-12">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full border border-zinc-700 bg-zinc-900/40 backdrop-blur-md text-xs font-mono mb-2 animate-pulse" style={{ color: BRAND_GREEN }}>
            <Shield className="w-3.5 h-3.5" />
            <span>{t.badgeTag}</span>
          </div>

          <h1 className="text-4xl sm:text-6xl font-black tracking-tight text-white leading-tight">
            {t.heroTitleLanding} <br />
            <span style={{ color: BRAND_GREEN }}>{t.heroTitleGreen}</span>
          </h1>

          <p className="text-slate-300 text-base sm:text-lg max-w-2xl mx-auto font-normal leading-relaxed">
            {t.heroDescLanding}
          </p>

          <div className="pt-4 max-w-xl mx-auto flex flex-col sm:flex-row items-center gap-3">
            <input 
              type="email" 
              placeholder={t.inputEmailPlaceholder} 
              value={authEmail}
              onChange={(e) => setAuthEmail(e.target.value)}
              className="w-full bg-black/70 border border-zinc-700/80 rounded-xl px-4 py-3.5 text-sm text-white focus:outline-none backdrop-blur-md transition-all"
            />
            <button 
              onClick={() => handleStartAuth('register')}
              style={{ backgroundColor: BRAND_GREEN }}
              className="w-full sm:w-auto px-8 py-3.5 text-black font-bold text-sm rounded-xl flex items-center justify-center space-x-2 whitespace-nowrap hover:opacity-90 hover:scale-105 transition-all shadow-lg"
            >
              <span>{t.btnCreateAccount}</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </main>

        <footer className="relative z-10 text-center py-6 text-xs text-zinc-500 border-t border-zinc-900 bg-black/80">
          <p>{t.footerRights}</p>
        </footer>
      </div>
    );
  }

  // APLICAÇÃO PRINCIPAL
  return (
    <div className="min-h-screen bg-[#050505] text-slate-100 font-sans">
      
      {/* POPUP DE BOAS-VINDAS */}
      {showWelcomePopup && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 animate-fadeIn">
          <div className="bg-[#0a0a0a] border rounded-3xl p-8 max-w-md w-full text-center space-y-6 shadow-2xl relative" style={{ borderColor: BRAND_GREEN }}>
            <button 
              onClick={() => setShowWelcomePopup(false)} 
              className="absolute top-4 right-4 text-zinc-500 hover:text-white transition-colors"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex justify-center">
              {logoHeader ? (
                <img src={logoHeader} alt="CodeShield Logo" className="h-16 w-auto object-contain rounded-xl" />
              ) : (
                <Shield className="w-16 h-16" style={{ color: BRAND_GREEN }} />
              )}
            </div>

            <div className="space-y-2">
              <h3 className="text-2xl font-bold text-white">{t.welcomeTitle}</h3>
              <p className="text-xs text-slate-300 leading-relaxed">{t.welcomeMessage}</p>
            </div>

            <button 
              onClick={() => setShowWelcomePopup(false)}
              style={{ backgroundColor: BRAND_GREEN, color: '#000000' }}
              className="w-full py-3 rounded-xl font-bold text-xs uppercase tracking-wider hover:opacity-90 transition-all shadow-lg"
            >
              {t.welcomeBtn}
            </button>
          </div>
        </div>
      )}

      {/* HEADER */}
      <header className="sticky top-0 z-40 bg-[#000000] border-b border-zinc-900 px-6 sm:px-8 py-4 backdrop-blur-md bg-black/90">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          
          {/* LADO ESQUERDO: LOGO + NAVEGAÇÃO NA MESMA LINHA */}
          <div className="flex items-center space-x-6">
            <div className="flex items-center space-x-3 cursor-pointer group" onClick={() => setShowLandingScreen(true)}>
              {logoHeader ? (
                <img src={logoHeader} alt="CodeShield" className="h-9 w-auto object-contain transition-transform group-hover:scale-105" />
              ) : (
                <span className="font-extrabold text-xl tracking-wider" style={{ color: BRAND_GREEN }}>CODESHIELD</span>
              )}
            </div>
            <span className="hidden sm:inline bg-zinc-900 border border-zinc-800 text-[10px] font-mono px-2 py-0.5 rounded-full" style={{ color: BRAND_GREEN }}>v1.0</span>

            {/* ABAS MOVIDAS PARA O HEADER AO LADO DA LOGO */}
            {currentUser && (
              <nav className="flex space-x-1 sm:space-x-2 text-xs font-semibold">
                <button 
                  onClick={() => setActiveTab('dashboard')} 
                  className={`px-3 py-1.5 rounded-xl flex items-center space-x-1.5 transition-all ${activeTab === 'dashboard' ? 'bg-zinc-800 text-white shadow-lg' : 'text-slate-400 hover:text-white'}`}
                >
                  <LayoutDashboard className="w-3.5 h-3.5" />
                  <span className="hidden md:inline">{t.navDashboard}</span>
                </button>

                <button 
                  onClick={() => setActiveTab('pricing')} 
                  className={`px-3 py-1.5 rounded-xl flex items-center space-x-1.5 transition-all ${activeTab === 'pricing' ? 'bg-zinc-800 text-white shadow-lg' : 'text-slate-400 hover:text-white'}`}
                >
                  <CreditCard className="w-3.5 h-3.5" />
                  <span className="hidden md:inline">{t.navPricing}</span>
                </button>

                <button 
                  onClick={() => setActiveTab('account')} 
                  className={`px-3 py-1.5 rounded-xl flex items-center space-x-1.5 transition-all ${activeTab === 'account' ? 'bg-zinc-800 text-white shadow-lg' : 'text-slate-400 hover:text-white'}`}
                >
                  <User className="w-3.5 h-3.5" />
                  <span className="hidden md:inline">{t.navAccount}</span>
                </button>
              </nav>
            )}
          </div>

          {/* LADO DIREITO: CHATBOT, IDIOMA E PERFIL */}
          <div className="flex items-center space-x-3 sm:space-x-4">
            {/* BOTÃO CLAUDE CHATBOT */}
            <button 
              onClick={() => setShowClaudeModal(true)}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-purple-950/40 border border-purple-800/60 text-purple-300 text-xs hover:bg-purple-900/50 transition-all"
            >
              <Bot className="w-3.5 h-3.5 text-purple-400" />
              <span className="hidden sm:inline font-semibold">Claude Chat</span>
            </button>

            <div className="flex items-center space-x-1.5 bg-[#0a0a0a] border border-zinc-800/80 px-3 py-1.5 rounded-xl text-xs">
              <Globe className="w-3.5 h-3.5" style={{ color: BRAND_GREEN }} />
              <select 
                value={lang} 
                onChange={(e) => handleLangChange(e.target.value as any)}
                className="bg-transparent text-slate-200 focus:outline-none cursor-pointer text-xs"
              >
                <option value="pt" className="bg-zinc-900 text-white">Português (PT)</option>
                <option value="en" className="bg-zinc-900 text-white">English (EN)</option>
                <option value="es" className="bg-zinc-900 text-white">Español (ES)</option>
              </select>
            </div>

            {currentUser && (
              <button onClick={() => setActiveTab('account')} className="p-1.5 rounded-xl bg-[#0a0a0a] border border-zinc-800/80 hover:border-zinc-700 transition-all flex items-center justify-center overflow-hidden">
                {currentUser.profilePic ? (
                  <img src={currentUser.profilePic} alt="Perfil" className="w-6 h-6 rounded-full object-cover" />
                ) : (
                  <User className="w-4 h-4 text-slate-300" />
                )}
              </button>
            )}
          </div>
        </div>
      </header>

      {/* LOGIN / CADASTRO */}
      {!currentUser ? (
        <main className="max-w-md mx-auto px-6 py-16 animate-fadeIn">
          <div className="bg-[#0a0a0a] border border-zinc-800/80 rounded-2xl p-6 space-y-6 shadow-2xl">
            <div className="flex justify-between items-center">
              <button 
                onClick={() => setShowLandingScreen(true)}
                className="text-xs text-slate-400 hover:text-white flex items-center space-x-1 transition-colors"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>{t.btnBackHome}</span>
              </button>
            </div>

            <div className="text-center space-y-2">
              <div className="inline-flex p-3 rounded-2xl bg-zinc-900 border border-zinc-800 mb-2" style={{ color: BRAND_GREEN }}>
                {authMode === 'login' ? <LogIn className="w-6 h-6" /> : <UserPlus className="w-6 h-6" />}
              </div>
              <h2 className="text-xl font-bold text-white">{authMode === 'login' ? t.loginTitle : t.registerTitle}</h2>
            </div>

            <form onSubmit={handleAuthSubmit} className="space-y-4 text-xs">
              {authMode === 'register' && (
                <div>
                  <label className="block text-slate-400 mb-1">{t.labelUsername}</label>
                  <div className="relative">
                    <User className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
                    <input 
                      type="text" 
                      required
                      value={authUsername}
                      onChange={(e) => setAuthUsername(e.target.value)}
                      placeholder="Analista SOC"
                      className="w-full bg-black border border-zinc-800 rounded-xl pl-9 pr-4 py-2.5 text-slate-200 focus:outline-none focus:border-zinc-700"
                    />
                  </div>
                </div>
              )}

              <div>
                <label className="block text-slate-400 mb-1">{t.labelEmail}</label>
                <div className="relative">
                  <Mail className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
                  <input 
                    type="email" 
                    required
                    value={authEmail}
                    onChange={(e) => setAuthEmail(e.target.value)}
                    placeholder="seu@email.com"
                    className="w-full bg-black border border-zinc-800 rounded-xl pl-9 pr-4 py-2.5 text-slate-200 focus:outline-none focus:border-zinc-700"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">{t.labelPassword}</label>
                <div className="relative">
                  <Lock className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
                  <input 
                    type="password" 
                    required
                    value={authPassword}
                    onChange={(e) => setAuthPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full bg-black border border-zinc-800 rounded-xl pl-9 pr-4 py-2.5 text-slate-200 focus:outline-none focus:border-zinc-700"
                  />
                </div>
              </div>

              {authError && (
                <div className="p-3 bg-rose-950/60 border border-rose-800/80 rounded-xl text-[11px] text-rose-300 font-medium">
                  {authError}
                </div>
              )}

              <button 
                type="submit" 
                style={{ backgroundColor: BRAND_GREEN, color: '#000000' }}
                className="w-full py-3 font-bold text-sm rounded-xl transition-all hover:opacity-90 hover:scale-[1.02] flex items-center justify-center space-x-2"
              >
                <span>{authMode === 'login' ? t.btnLoginSubmit : t.btnRegisterSubmit}</span>
              </button>
            </form>

            <div className="text-center pt-2 border-t border-zinc-800/80">
              <button 
                onClick={() => setAuthMode(authMode === 'login' ? 'register' : 'login')} 
                className="text-xs text-slate-400 hover:text-white transition-colors"
              >
                {authMode === 'login' ? t.linkSwitchToRegister : t.linkSwitchToLogin}
              </button>
            </div>
          </div>
        </main>
      ) : (

        /* DASHBOARD PRINCIPAL */
        <main className="max-w-7xl mx-auto px-6 sm:px-8 py-8 space-y-8 animate-fadeIn">

          {/* ABA 1: DASHBOARD */}
          {activeTab === 'dashboard' && (
            <>
              <section className="space-y-3">
                <h2 className="text-3xl md:text-4xl font-bold text-white tracking-tight">{t.heroTitle}</h2>
                <p className="text-slate-400 max-w-3xl text-sm leading-relaxed">{t.heroDesc}</p>
              </section>

              {/* BARRA DE SCANNER */}
              <section className="bg-[#080808] border border-zinc-900 rounded-2xl p-6 space-y-5 transition-all hover:border-zinc-800">
                <div className="flex items-center space-x-2 text-xs font-mono text-zinc-400">
                  <span style={{ color: BRAND_GREEN }}>&gt;_</span>
                  <span className="tracking-wider">REPOSITORY_SCANNER.SH</span>
                </div>

                <div className="flex flex-col md:flex-row items-center gap-4">
                  <div className="relative flex-1 w-full">
                    <span className="absolute left-4 top-1/2 -translate-y-1/2 font-mono text-sm" style={{ color: BRAND_GREEN }}>$</span>
                    <input
                      type="text"
                      value={repoUrl}
                      onChange={(e) => setRepoUrl(e.target.value)}
                      placeholder={t.repoPlaceholder}
                      className="w-full bg-black border border-zinc-800/80 rounded-xl pl-9 pr-4 py-3.5 text-sm font-mono focus:outline-none focus:border-zinc-700 transition-all"
                      style={{ color: BRAND_GREEN }}
                    />
                  </div>
                  <button 
                    onClick={handleStartScan}
                    disabled={isScanning}
                    style={{ backgroundColor: BRAND_GREEN, color: '#000000' }} 
                    className="w-full md:w-auto px-8 py-3.5 font-bold text-sm rounded-xl flex items-center justify-center space-x-2 disabled:opacity-50 hover:opacity-90 hover:scale-105 transition-all whitespace-nowrap shadow-lg"
                  >
                    {isScanning ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-current" />}
                    <span>{isScanning ? t.scanningBtn : t.scanBtn}</span>
                  </button>
                </div>

                {isScanning && (
                  <div className="space-y-2">
                    <div className="p-3 bg-zinc-950 border border-zinc-800/80 rounded-xl flex items-center space-x-3 text-xs font-mono" style={{ color: BRAND_GREEN }}>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>{scanMessage}</span>
                    </div>
                    <div className="w-full bg-zinc-900 rounded-full h-1.5 overflow-hidden">
                      <div 
                        className="h-1.5 rounded-full transition-all duration-500" 
                        style={{ width: `${scanProgress}%`, backgroundColor: BRAND_GREEN }} 
                      />
                    </div>
                  </div>
                )}

                {!isScanning && scanMessage && !scanError && scanSummary && (
                  <div className="p-3 bg-emerald-950/20 border border-emerald-900/50 rounded-xl text-xs font-mono text-emerald-300 flex flex-wrap items-center gap-x-4 gap-y-1">
                    <span>{scanMessage}</span>
                    <span>SAST: {scanSummary.semgrep}</span>
                    <span>SCA: {scanSummary.trivy}</span>
                    <span>IA: {scanSummary.ia}</span>
                  </div>
                )}

                {scanError && (
                  <div className="p-3 bg-rose-950/30 border border-rose-900/60 rounded-xl text-xs text-rose-300">
                    {scanError}
                  </div>
                )}
              </section>

              {/* CARDS MÉTRICOS */}
              <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-7 gap-4">
                <div className="bg-[#080808] border border-zinc-900 rounded-xl p-5 flex items-center justify-between hover:border-zinc-700 transition-all">
                  <div>
                    <span className="text-[11px] font-bold text-zinc-400 tracking-wider block mb-2">{t.metricTotal}</span>
                    <span className="text-3xl font-bold text-white font-mono">{findings.length}</span>
                  </div>
                  <ShieldCheck className="w-5 h-5 text-zinc-400" />
                </div>

                <div className="bg-[#080808] border border-emerald-900/40 rounded-xl p-5 flex items-center justify-between hover:border-emerald-800 transition-all">
                  <div>
                    <span className="text-[11px] font-bold text-emerald-400 tracking-wider block mb-2">{t.metricSast}</span>
                    <span className="text-3xl font-bold text-emerald-400 font-mono">{countSast}</span>
                  </div>
                  <Code2 className="w-5 h-5 text-emerald-400" />
                </div>

                <div className="bg-[#080808] border border-cyan-900/40 rounded-xl p-5 flex items-center justify-between hover:border-cyan-800 transition-all">
                  <div>
                    <span className="text-[11px] font-bold text-cyan-400 tracking-wider block mb-2">{t.metricSca}</span>
                    <span className="text-3xl font-bold text-cyan-400 font-mono">{countSca}</span>
                  </div>
                  <Shield className="w-5 h-5 text-cyan-400" />
                </div>

                {/* CRÍTICOS - VERMELHO */}
                <div className="bg-[#080808] border border-rose-900/40 rounded-xl p-5 flex items-center justify-between hover:border-rose-800 transition-all">
                  <div>
                    <span className="text-[11px] font-bold text-rose-500 tracking-wider block mb-2">{t.metricCritical}</span>
                    <span className="text-3xl font-bold text-rose-500 font-mono">{countCritical}</span>
                  </div>
                  <AlertTriangle className="w-5 h-5 text-rose-500" />
                </div>

                {/* ALTOS - LARANJA */}
                <div className="bg-[#080808] border border-amber-900/40 rounded-xl p-5 flex items-center justify-between hover:border-amber-800 transition-all">
                  <div>
                    <span className="text-[11px] font-bold text-amber-500 tracking-wider block mb-2">{t.metricHigh}</span>
                    <span className="text-3xl font-bold text-amber-500 font-mono">{countHigh}</span>
                  </div>
                  <AlertTriangle className="w-5 h-5 text-amber-500" />
                </div>

                {/* MÉDIOS - AMARELO */}
                <div className="bg-[#080808] border border-yellow-900/40 rounded-xl p-5 flex items-center justify-between hover:border-yellow-800 transition-all">
                  <div>
                    <span className="text-[11px] font-bold text-yellow-400 tracking-wider block mb-2">{t.metricMedium}</span>
                    <span className="text-3xl font-bold text-yellow-400 font-mono">{countMedium}</span>
                  </div>
                  <Info className="w-5 h-5 text-yellow-400" />
                </div>

                {/* BAIXOS - AZUL */}
                <div className="bg-[#080808] border border-sky-900/40 rounded-xl p-5 flex items-center justify-between hover:border-sky-800 transition-all">
                  <div>
                    <span className="text-[11px] font-bold text-sky-400 tracking-wider block mb-2">{t.metricLow}</span>
                    <span className="text-3xl font-bold text-sky-400 font-mono">{countLow}</span>
                  </div>
                  <SlidersHorizontal className="w-5 h-5 text-sky-400" />
                </div>
              </section>

              {/* FINDINGS TABLE */}
              <section className="bg-[#080808] border border-zinc-900 rounded-2xl overflow-hidden shadow-xl">
                <div className="p-5 border-b border-zinc-900 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="flex items-center space-x-2">
                    <Code2 className="w-5 h-5" style={{ color: BRAND_GREEN }} />
                    <h3 className="font-bold text-base text-white">{t.findingsTitle}</h3>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <div className="relative">
                      <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-zinc-500" />
                      <input 
                        type="text" 
                        placeholder={t.searchPlaceholder}
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="bg-black border border-zinc-800 text-xs rounded-xl pl-8 pr-3 py-1.5 text-slate-200 focus:outline-none focus:border-zinc-700"
                      />
                    </div>

                    <select 
                      value={filterSeverity} 
                      onChange={(e) => setFilterSeverity(e.target.value)}
                      className="bg-black border border-zinc-800 text-xs rounded-xl px-3 py-1.5 text-slate-200 focus:outline-none"
                    >
                      <option value="todos">{t.filterAllSeverities}</option>
                      <option value="CRITICAL">CRITICAL</option>
                      <option value="HIGH">HIGH</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="LOW">LOW</option>
                    </select>

                    <select
                      value={filterSource}
                      onChange={(e) => setFilterSource(e.target.value)}
                      className="bg-black border border-zinc-800 text-xs rounded-xl px-3 py-1.5 text-slate-200 focus:outline-none"
                    >
                      <option value="todos">{t.filterAllSources}</option>
                      <option value="semgrep">Semgrep / SAST</option>
                      <option value="trivy">Trivy / SCA</option>
                    </select>
                  </div>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-[#0a0a0a] border-b border-zinc-900 text-zinc-400">
                      <tr>
                        <th className="px-4 py-4 font-semibold tracking-wider">{t.thSource}</th>
                        <th className="px-4 py-4 font-semibold tracking-wider">{t.thRule}</th>
                        <th className="px-4 py-4 font-semibold tracking-wider">{t.thFile}</th>
                        <th className="px-4 py-4 font-semibold tracking-wider">{t.thLine}</th>
                        <th className="px-4 py-4 font-semibold tracking-wider">{t.thSeverity}</th>
                        <th className="px-4 py-4 font-semibold tracking-wider">{t.thPride}</th>
                        <th className="px-4 py-4 font-semibold tracking-wider">{t.thIssue}</th>
                        <th className="px-4 py-4 font-semibold tracking-wider">{t.thFix}</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-900">
                      {filteredFindings.length > 0 ? (
                        filteredFindings.map((finding) => (
                          <tr key={finding.id} className="hover:bg-zinc-900/40 transition-colors align-top">
                            <td className="px-4 py-4">
                              <span className={`inline-flex px-2 py-1 rounded-lg border text-[10px] font-bold whitespace-nowrap ${getSourceColorClass(finding.fonte)}`}>
                                {getSourceLabel(finding.fonte)}
                              </span>
                            </td>
                            <td className="px-4 py-4 text-zinc-300 max-w-[220px] break-all">{finding.ruleId}</td>
                            <td className="px-4 py-4 text-slate-200 max-w-[240px] break-all">{finding.arquivo}</td>
                            <td className="px-4 py-4 text-zinc-400">{finding.linha > 0 ? finding.linha : '—'}</td>
                            <td className={`px-4 py-4 uppercase ${getSeverityColorClass(finding.severidade)}`}>
                              {finding.severidade}
                            </td>
                            <td className="px-4 py-4 font-bold" style={{ color: BRAND_GREEN }}>{finding.prideScore.toFixed(1)}</td>
                            <td className="px-4 py-4 text-slate-300 min-w-[280px] max-w-[520px] whitespace-normal">{finding.problema}</td>
                            <td className="px-4 py-4">
                              <button 
                                onClick={() => handleOpenAiModal(finding)}
                                disabled={!finding.fixIa}
                                style={finding.fixIa ? { color: BRAND_GREEN, borderColor: BRAND_GREEN + "40" } : {}}
                                className={`px-3 py-1 border rounded-lg text-[11px] font-sans font-medium flex items-center space-x-1 transition-all whitespace-nowrap ${finding.fixIa ? 'bg-zinc-900 hover:scale-105' : 'bg-zinc-950 border-zinc-800 text-zinc-600 cursor-not-allowed'}`}
                              >
                                <Sparkles className="w-3 h-3" />
                                <span>{finding.fixIa ? (lang === 'pt' ? 'Ver correção' : lang === 'es' ? 'Ver corrección' : 'View fix') : t.aiDisabled}</span>
                              </button>
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan={8} className="px-6 py-16 text-center text-zinc-500">
                            <div className="flex flex-col items-center justify-center space-y-3">
                              <ShieldCheck className="w-8 h-8 text-zinc-700" />
                              <p className="font-sans text-sm text-zinc-400">{t.emptyFindings}</p>
                              <p className="font-sans text-xs text-zinc-600">{t.emptyFindingsDesc}</p>
                            </div>
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </section>
            </>
          )}

          {/* ABA 2: PLANOS E ASSINATURAS */}
          {activeTab === 'pricing' && (
            <section className="space-y-8 animate-fadeIn">
              <div className="text-center space-y-3 max-w-2xl mx-auto">
                <h2 className="text-3xl font-bold text-white">{t.pricingTitle}</h2>
                <p className="text-slate-400 text-sm">{t.pricingDesc}</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-6xl mx-auto">
                {/* PLANO STARTER */}
                <div 
                  className="bg-[#080808] border rounded-2xl p-6 flex flex-col justify-between transition-all relative border-zinc-900 hover:border-zinc-800"
                  style={currentUser.currentPlan === 'Starter' ? { borderColor: BRAND_GREEN } : {}}
                >
                  {currentUser.currentPlan === 'Starter' && (
                    <span 
                      style={{ backgroundColor: BRAND_GREEN }} 
                      className="absolute -top-3 right-6 text-black text-[10px] font-bold px-3 py-0.5 rounded-full uppercase"
                    >
                      {t.currentPlanTag}
                    </span>
                  )}
                  <div className="space-y-4">
                    <div className="flex items-center space-x-2" style={{ color: BRAND_GREEN }}>
                      <Zap className="w-5 h-5" />
                      <h3 className="font-bold text-lg text-white">Starter</h3>
                    </div>
                    <div className="font-mono">
                      <span className="text-3xl font-bold text-white">R$ 99</span>
                      <span className="text-zinc-500 text-xs"> / mês</span>
                    </div>
                    <ul className="space-y-2.5 text-xs text-slate-300 pt-4 border-t border-zinc-900">
                      <li className="flex items-center space-x-2">
                        <Check className="w-4 h-4" style={{ color: BRAND_GREEN }} />
                        <span>Até 20 Scans de código por mês</span>
                      </li>
                      <li className="flex items-center space-x-2">
                        <Check className="w-4 h-4" style={{ color: BRAND_GREEN }} />
                        <span>Análise de vulnerabilidades SAST</span>
                      </li>
                      <li className="flex items-center space-x-2">
                        <Check className="w-4 h-4" style={{ color: BRAND_GREEN }} />
                        <span>Assistente IA básico para correções</span>
                      </li>
                    </ul>
                  </div>

                  <button 
                    onClick={() => handleSelectPlan('Starter', 20)}
                    disabled={currentUser.currentPlan === 'Starter'}
                    style={currentUser.currentPlan !== 'Starter' ? { backgroundColor: BRAND_GREEN, color: '#000000' } : {}}
                    className={`w-full mt-6 py-2.5 rounded-xl font-bold text-xs transition-all ${currentUser.currentPlan === 'Starter' ? 'bg-zinc-800 text-zinc-500 cursor-default' : 'hover:opacity-90'}`}
                  >
                    {currentUser.currentPlan === 'Starter' ? t.btnActivePlan : t.btnSelectPlan}
                  </button>
                </div>

                {/* PLANO PRO */}
                <div 
                  className="bg-[#080808] border rounded-2xl p-6 flex flex-col justify-between transition-all relative border-zinc-800 hover:border-zinc-700"
                  style={currentUser.currentPlan === 'Pro' ? { borderColor: BRAND_GREEN } : {}}
                >
                  {currentUser.currentPlan === 'Pro' && (
                    <span 
                      style={{ backgroundColor: BRAND_GREEN }} 
                      className="absolute -top-3 right-6 text-black text-[10px] font-bold px-3 py-0.5 rounded-full uppercase"
                    >
                      {t.currentPlanTag}
                    </span>
                  )}
                  <div className="space-y-4">
                    <div className="flex items-center space-x-2" style={{ color: BRAND_GREEN }}>
                      <Sparkles className="w-5 h-5" />
                      <h3 className="font-bold text-lg text-white">Pro</h3>
                    </div>
                    <div className="font-mono">
                      <span className="text-3xl font-bold text-white">R$ 299</span>
                      <span className="text-zinc-500 text-xs"> / mês</span>
                    </div>
                    <ul className="space-y-2.5 text-xs text-slate-300 pt-4 border-t border-zinc-900">
                      <li className="flex items-center space-x-2">
                        <Check className="w-4 h-4" style={{ color: BRAND_GREEN }} />
                        <span>Até 100 Scans de código por mês</span>
                      </li>
                      <li className="flex items-center space-x-2">
                        <Check className="w-4 h-4" style={{ color: BRAND_GREEN }} />
                        <span>SAST + ASPM em tempo real</span>
                      </li>
                      <li className="flex items-center space-x-2">
                        <Check className="w-4 h-4" style={{ color: BRAND_GREEN }} />
                        <span>Assistente IA com refatoração automática</span>
                      </li>
                      <li className="flex items-center space-x-2">
                        <Check className="w-4 h-4" style={{ color: BRAND_GREEN }} />
                        <span>Suporte prioritário 24/7</span>
                      </li>
                    </ul>
                  </div>

                  <button 
                    onClick={() => handleSelectPlan('Pro', 100)}
                    disabled={currentUser.currentPlan === 'Pro'}
                    style={currentUser.currentPlan !== 'Pro' ? { backgroundColor: BRAND_GREEN, color: '#000000' } : {}}
                    className={`w-full mt-6 py-2.5 rounded-xl font-bold text-xs transition-all ${currentUser.currentPlan === 'Pro' ? 'bg-zinc-800 text-zinc-500 cursor-default' : 'hover:opacity-90'}`}
                  >
                    {currentUser.currentPlan === 'Pro' ? t.btnActivePlan : t.btnSelectPlan}
                  </button>
                </div>

                {/* PLANO ENTERPRISE */}
                <div 
                  className="bg-[#080808] border rounded-2xl p-6 flex flex-col justify-between transition-all relative border-zinc-900 hover:border-zinc-800"
                  style={currentUser.currentPlan === 'Enterprise' ? { borderColor: BRAND_GREEN } : {}}
                >
                  {currentUser.currentPlan === 'Enterprise' && (
                    <span 
                      style={{ backgroundColor: BRAND_GREEN }} 
                      className="absolute -top-3 right-6 text-black text-[10px] font-bold px-3 py-0.5 rounded-full uppercase"
                    >
                      {t.currentPlanTag}
                    </span>
                  )}
                  <div className="space-y-4">
                    <div className="flex items-center space-x-2" style={{ color: BRAND_GREEN }}>
                      <Shield className="w-5 h-5" />
                      <h3 className="font-bold text-lg text-white">Enterprise</h3>
                    </div>
                    <div className="font-mono">
                      <span className="text-3xl font-bold text-white">R$ 899</span>
                      <span className="text-zinc-500 text-xs"> / mês</span>
                    </div>
                    <ul className="space-y-2.5 text-xs text-slate-300 pt-4 border-t border-zinc-900">
                      <li className="flex items-center space-x-2">
                        <Check className="w-4 h-4" style={{ color: BRAND_GREEN }} />
                        <span>Scans Ilimitados para toda equipe</span>
                      </li>
                      <li className="flex items-center space-x-2">
                        <Check className="w-4 h-4" style={{ color: BRAND_GREEN }} />
                        <span>Integração CI/CD nativa & Webhooks</span>
                      </li>
                      <li className="flex items-center space-x-2">
                        <Check className="w-4 h-4" style={{ color: BRAND_GREEN }} />
                        <span>Relatórios Customizados de Conformidade</span>
                      </li>
                      <li className="flex items-center space-x-2">
                        <Check className="w-4 h-4" style={{ color: BRAND_GREEN }} />
                        <span>Gerente de Conta Dedicado</span>
                      </li>
                    </ul>
                  </div>

                  <button 
                    onClick={() => handleSelectPlan('Enterprise', 99999)}
                    disabled={currentUser.currentPlan === 'Enterprise'}
                    style={currentUser.currentPlan !== 'Enterprise' ? { backgroundColor: BRAND_GREEN, color: '#000000' } : {}}
                    className={`w-full mt-6 py-2.5 rounded-xl font-bold text-xs transition-all ${currentUser.currentPlan === 'Enterprise' ? 'bg-zinc-800 text-zinc-500 cursor-default' : 'hover:opacity-90'}`}
                  >
                    {currentUser.currentPlan === 'Enterprise' ? t.btnActivePlan : t.btnSelectPlan}
                  </button>
                </div>
              </div>
            </section>
          )}

          {/* ABA 3: CONFIGURAÇÕES DA CONTA COM OPÇÃO DE FOTO */}
          {activeTab === 'account' && (
            <section className="bg-[#080808] border border-zinc-900 rounded-2xl p-6 space-y-6 max-w-2xl mx-auto shadow-xl animate-fadeIn">
              <div className="flex items-center justify-between border-b border-zinc-900 pb-4">
                <h3 className="font-bold text-lg text-white">{t.accountTitle}</h3>
                <button onClick={handleLogout} className="px-3 py-1.5 bg-rose-950/60 border border-rose-800/60 text-rose-400 rounded-xl text-xs font-semibold hover:bg-rose-900/50 transition-all flex items-center space-x-1.5">
                  <LogOut className="w-3.5 h-3.5" />
                  <span>{t.logoutBtn}</span>
                </button>
              </div>

              {/* MUDANÇA DE FOTO DO USUÁRIO */}
              <div className="flex flex-col sm:flex-row items-center space-y-4 sm:space-y-0 sm:space-x-6 p-4 bg-zinc-950 border border-zinc-900 rounded-xl">
                <div className="relative group">
                  <div className="w-20 h-20 rounded-full overflow-hidden border-2 bg-black flex items-center justify-center" style={{ borderColor: BRAND_GREEN }}>
                    {currentUser.profilePic ? (
                      <img src={currentUser.profilePic} alt="Perfil" className="w-full h-full object-cover" />
                    ) : (
                      <User className="w-10 h-10 text-zinc-600" />
                    )}
                  </div>
                  <label htmlFor="file-upload" className="absolute inset-0 bg-black/60 rounded-full flex items-center justify-center opacity-0 group-hover:opacity-100 cursor-pointer transition-opacity">
                    <Camera className="w-6 h-6 text-white" />
                  </label>
                  <input id="file-upload" type="file" accept="image/*" onChange={handleFileUpload} className="hidden" />
                </div>

                <div className="flex-1 space-y-2 text-center sm:text-left">
                  <label className="block text-xs font-medium text-slate-300">{t.labelProfilePic}</label>
                  <div className="flex gap-2">
                    <input 
                      type="text" 
                      value={currentUser.profilePic} 
                      onChange={(e) => setCurrentUser({ ...currentUser, profilePic: e.target.value })}
                      placeholder="https://exemplo.com/foto.jpg"
                      className="flex-1 bg-black border border-zinc-800 rounded-xl px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-zinc-700"
                    />
                    <label htmlFor="file-upload" className="px-3 py-2 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-xs text-white font-medium rounded-xl cursor-pointer flex items-center space-x-1 transition-all">
                      <Upload className="w-3.5 h-3.5" />
                      <span className="hidden sm:inline">{t.uploadPicBtn}</span>
                    </label>
                  </div>
                </div>
              </div>

              <form onSubmit={handleSaveAccount} className="space-y-4 text-xs">
                <div>
                  <label className="block text-slate-400 mb-1">{t.labelUsername}</label>
                  <input 
                    type="text" 
                    value={currentUser.username} 
                    onChange={(e) => setCurrentUser({ ...currentUser, username: e.target.value })}
                    className="w-full bg-black border border-zinc-800 rounded-xl px-4 py-2.5 text-slate-200 focus:outline-none focus:border-zinc-700"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">{t.labelDefaultRepo}</label>
                  <input 
                    type="text" 
                    value={currentUser.defaultRepo} 
                    onChange={(e) => setCurrentUser({ ...currentUser, defaultRepo: e.target.value })}
                    className="w-full bg-black border border-zinc-800 rounded-xl px-4 py-2.5 font-mono text-slate-200 focus:outline-none focus:border-zinc-700"
                  />
                </div>

                {saveAlert && (
                  <div className="p-3 bg-zinc-900 border rounded-xl text-xs font-medium" style={{ color: BRAND_GREEN, borderColor: BRAND_GREEN + "40" }}>
                    {t.prefSaved}
                  </div>
                )}

                <button 
                  type="submit" 
                  style={{ backgroundColor: BRAND_GREEN, color: '#000000' }}
                  className="px-6 py-2.5 font-bold text-xs rounded-xl hover:opacity-90 hover:scale-105 transition-all"
                >
                  {t.saveSettings}
                </button>
              </form>
            </section>
          )}
        </main>
      )}

      {/* MODAL DE CHAT CLAUDE (ANTHROPIC) */}
      {showClaudeModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 animate-fadeIn">
          <div className="bg-[#0a0a0a] border border-purple-800/60 rounded-2xl w-full max-w-xl flex flex-col h-[520px] shadow-2xl">
            <div className="p-4 border-b border-zinc-800 flex items-center justify-between bg-purple-950/20">
              <div className="flex items-center space-x-2 text-purple-400 font-bold text-sm">
                <Bot className="w-5 h-5 text-purple-400" />
                <span>{t.claudeTitle}</span>
              </div>
              <button onClick={() => setShowClaudeModal(false)} className="text-zinc-500 hover:text-white transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="px-4 py-2 bg-zinc-900/50 border-b border-zinc-800 text-[11px] text-zinc-400">
              {t.claudeDesc}
            </div>

            <div className="flex-1 p-4 overflow-y-auto space-y-3 text-xs">
              {claudeMessages.map((msg, index) => (
                <div key={index} className={`flex ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div className={`max-w-[85%] p-3 rounded-xl ${msg.sender === 'user' ? 'bg-purple-600 text-white font-medium' : 'bg-zinc-900 border border-zinc-800 text-slate-200 whitespace-pre-line'}`}>
                    {msg.text}
                  </div>
                </div>
              ))}
            </div>

            <div className="p-3 border-t border-zinc-800 flex items-center space-x-2">
              <input 
                type="text" 
                value={inputClaude}
                onChange={(e) => setInputClaude(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSendClaudeMessage()}
                placeholder={t.aiDisabled}
                disabled
                className="flex-1 bg-black border border-zinc-800 rounded-xl px-3 py-2 text-xs text-zinc-600 cursor-not-allowed"
              />
              <button onClick={handleSendClaudeMessage} disabled className="p-2 bg-zinc-800 text-zinc-600 rounded-xl cursor-not-allowed">
                <Send className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL DE CHAT IA (FINDINGS) */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 animate-fadeIn">
          <div className="bg-[#0a0a0a] border border-zinc-800 rounded-2xl w-full max-w-xl flex flex-col h-[500px] shadow-2xl">
            <div className="p-4 border-b border-zinc-800 flex items-center justify-between">
              <div className="flex items-center space-x-2 font-bold text-sm" style={{ color: BRAND_GREEN }}>
                <Sparkles className="w-4 h-4 animate-pulse" />
                <span>{t.aiTitle}</span>
              </div>
              <button onClick={() => setSelectedFinding(null)} className="text-zinc-500 hover:text-white transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex-1 p-4 overflow-y-auto space-y-3 text-xs">
              {chatMessages.map((msg, index) => (
                <div key={index} className={`flex ${msg.sender === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div 
                    style={msg.sender === 'user' ? { backgroundColor: BRAND_GREEN, color: '#000000' } : {}}
                    className={`max-w-[80%] p-3 rounded-xl ${msg.sender === 'user' ? 'font-medium' : 'bg-zinc-900 border border-zinc-800 text-slate-200 whitespace-pre-line'}`}
                  >
                    {msg.text}
                  </div>
                </div>
              ))}
            </div>

            <div className="p-3 border-t border-zinc-800 flex items-center space-x-2">
              <input 
                type="text" 
                value={inputAi}
                onChange={(e) => setInputAi(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSendAiMessage()}
                placeholder={t.aiDisabled}
                disabled
                className="flex-1 bg-black border border-zinc-800 rounded-xl px-3 py-2 text-xs text-zinc-600 cursor-not-allowed"
              />
              <button 
                onClick={handleSendAiMessage}
                disabled
                className="p-2 rounded-xl bg-zinc-800 text-zinc-600 cursor-not-allowed"
              >
                <Send className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}