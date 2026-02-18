'use client';

import { useEffect, useRef, useState } from 'react';
import toast, { Toaster } from 'react-hot-toast';
import { motion } from 'framer-motion';

const fadeIn = {
  hidden: { opacity: 0, y: 30 },
  show: { opacity: 1, y: 0, transition: { duration: 0.6 } },
};

const LOGS = [
  { text: 'INFO:VulnSeeker:🚀 Iniciando escaneo: target_url=http://target.local', type: 'command' },
  { text: 'INFO:VulnSeeker:🕷️ Crawler: SÍ (Max Pages: 50)', type: 'command' },
  { text: 'DEBUG:core.engine:Módulo registrado: SQL Injection Module (Error-Based)', type: 'success' },
  { text: 'DEBUG:core.engine:Módulo registrado: Reflected XSS Module', type: 'success' },
  { text: 'DEBUG:core.engine:Módulo registrado: GroqAIAnalyst', type: 'ai' },
  { text: 'INFO:VulnSeeker:⚡ Motor de análisis iniciado (5 módulos activos)...', type: 'warning' },
  { text: 'INFO:modules.port_scanner:Scanning critical ports (21, 22, 80, 443, 3306)...', type: 'command' },
  { text: "WARN:modules.header_analyzer:Missing 'X-Frame-Options' header [LOW]", type: 'warning' },
  { text: "INFO:modules.path_fuzzer:🕵️‍♂️ Fuzzing 14 critical paths (.env, .git)...", type: 'command' },
  { text: "WARN:modules.sqli_module:  [!!!] Posible SQLi en parámetro 'id' con payload: ' OR '1'='1", type: 'error' },
  { text: "DEBUG:modules.sqli_module:Signature matched: 'You have an error in your SQL syntax'", type: 'error' },
  { text: 'INFO:modules.ai_analyst:🤖 Llama 3.3 70B: Generando Informe Ejecutivo...', type: 'ai' },
  { text: 'INFO:reports.pdf_generator:✅ PDF generado: vulnseeker_scan_492.pdf', type: 'success' },
  { text: 'INFO:DB:💾 Scan 42 guardado en SQLite (subdomains + vulns)', type: 'success' },
  { text: 'INFO:VulnSeeker:✅ ESCANEO COMPLETADO EXITOSAMENTE', type: 'success' },
  { text: 'INFO:modules.header_analyzer:HEAD 200 OK → auditando X-Frame-Options/CSP/HSTS', type: 'command' },
  { text: 'WARN:modules.header_analyzer:Falta Content-Security-Policy [MEDIUM]', type: 'warning' },
  { text: 'WARN:modules.port_scanner:Open Port 23 (Telnet) → HIGH', type: 'error' },
  { text: 'WARN:modules.path_fuzzer:EXPOSED .env → https://target.local/.env', type: 'error' },
  { text: "WARN:modules.xss_module:Reflected XSS detectado en parámetro 'q'", type: 'error' },
  { text: 'INFO:core.crawler:🕷️ WebCrawler (max_pages=5) descubriendo enlaces...', type: 'command' },
  { text: 'INFO:reports.report_generator:JSON listo -> results/scan_report_20250101_120102.json', type: 'success' },
  { text: 'INFO:reports.pdf_generator:📄 Portada + KPIs + Pie/Bar Charts generados (A4)', type: 'ai' },
  { text: 'INFO:ui.main_window:CTk UI refrescada con KPIs, pie/bar charts y subdominios', type: 'command' },
  { text: 'INFO:core.engine:Timeout=5s | Retries=2 | UA=VulnSeeker/2.4.0', type: 'command' },
  { text: 'INFO:core.engine:Persistencia activada → SQLite + JSON en ./results', type: 'success' },
];

const STATS = [
  { value: '10+', label: 'Hilos Máx' },
  { value: '70B', label: 'Modelo Llama 3.3' },
  { value: '100%', label: 'Python 3.14' },
];

const PIPELINE = [
  { title: 'Descubrir', desc: 'WebCrawler + SubdomainScanner + HeaderAnalyzer mapean superficie y cabeceras.' },
  { title: 'Fuzz', desc: 'PathFuzzer caza .env, .git y backups expuestos en paralelo.' },
  { title: 'Explotar', desc: 'SQL Injection + Reflected XSS con firmas y canarios controlados.' },
  { title: 'Reportar', desc: 'ReportGenerator JSON + PDFReportGenerator (pie/bar) + Groq Llama 3.3.' },
  { title: 'Entregar', desc: 'SQLite + JSON versionables para CI/CD y dashboards CTk.' },
];
const SETTINGS = [
  { label: '--threads', value: '10', desc: 'Workers de ThreadPoolExecutor (ajustable desde CLI/GUI).' },
  { label: '--timeout', value: '5s', desc: 'Timeout de requests para módulos HTTP (crawler, fuzzer, headers).' },
  { label: '--retries', value: '2', desc: 'Reintentos ante errores transitorios de red.' },
  { label: '--user-agent', value: 'VulnSeeker/2.4.0', desc: 'UA coherente para fingerprint y respeto de cabeceras.' },
  { label: '--output', value: './results', desc: 'Ruta para export JSON, PDF y base SQLite.' },
];
const INTEGRATIONS = [
  { name: 'GitHub Actions', tag: 'CI/CD', desc: 'Ejecuta el escaneo en cada pull request y bloquea merges inseguros.' },
  { name: 'Slack Webhooks', tag: 'Alerting', desc: 'Envía hallazgos críticos a #secops con contexto y severidad.' },
  { name: 'Burp Suite', tag: 'Proxy', desc: 'Comparte sesión y cookies para pruebas autenticadas.' },
  { name: 'SQLite / JSON', tag: 'Export', desc: 'Persistencia ligera para pipelines y dashboards.' },
  { name: 'Groq Cloud', tag: 'AI', desc: 'Inferencia ultrarrápida con Llama 3.3 para reportes ejecutivos.' },
];

export default function Page() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [renderLines, setRenderLines] = useState<{ id: number; text: string; type: string }[]>([]);
  const [showTop, setShowTop] = useState(false);
  const logRef = useRef<HTMLDivElement | null>(null);
  const shouldAnimateRef = useRef(true);
  const [showEaster, setShowEaster] = useState(false);
  const konamiRef = useRef(0);
  const hideEasterRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const mql = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (mql.matches) {
      shouldAnimateRef.current = false;
      return;
    }

    const handleVisibility = () => {
      shouldAnimateRef.current = document.visibilityState === 'visible';
    };
    const handleReduce = (e: MediaQueryListEvent) => {
      shouldAnimateRef.current = !e.matches;
    };
    document.addEventListener('visibilitychange', handleVisibility);
    mql.addEventListener('change', handleReduce);

    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener('resize', resize);

    let animId: number;
    const draw = () => {
      if (!shouldAnimateRef.current) {
        animId = requestAnimationFrame(draw);
        return;
      }
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.font = '14px "JetBrains Mono", monospace';
      ctx.textBaseline = 'top';

      ctx.strokeStyle = 'rgba(0, 255, 136, 0.03)';
      ctx.lineWidth = 1;
      const gridSize = 40;
      for (let x = 0; x < canvas.width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, canvas.height);
        ctx.stroke();
      }
      for (let y = 0; y < canvas.height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
      }

      const hexChars = '0123456789ABCDEF';
      const cols = Math.floor(canvas.width / 120);
      const rows = Math.floor(canvas.height / 20);

      for (let row = 0; row < rows; row++) {
        for (let col = 0; col < cols; col++) {
          const x = col * 120 + 20;
          const y = row * 20 + 10;

          ctx.fillStyle = 'rgba(0, 255, 136, 0.15)';
          const address = (row * 16 + col * 7).toString(16).toUpperCase().padStart(8, '0');
          ctx.fillText('0x' + address, x, y);

          ctx.fillStyle = 'rgba(160, 160, 160, 0.1)';
          for (let i = 0; i < 7; i++) {
            const byte = hexChars[Math.floor(Math.random() * 16)] + hexChars[Math.floor(Math.random() * 16)];
            ctx.fillText(byte, x + 100 + i * 22, y);
          }
        }
      }
      animId = requestAnimationFrame(draw);
    };

    animId = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', resize);
      document.removeEventListener('visibilitychange', handleVisibility);
      mql.removeEventListener('change', handleReduce);
    };
  }, []);

  useEffect(() => {
    let lineIdx = 0;
    let charIdx = 0;
    let timeout: NodeJS.Timeout;

    const type = () => {
      if (lineIdx >= LOGS.length) return;

      const line = LOGS[lineIdx];
      setRenderLines((prev) => {
        const next = [...prev];
        if (charIdx === 0) next.push({ id: next.length, text: '', type: line.type });
        const last = next.length - 1;
        next[last] = { ...next[last], text: line.text.substring(0, charIdx + 1) };
        return next;
      });

      charIdx++;
      if (charIdx < line.text.length) {
        timeout = setTimeout(type, 10 + Math.random() * 15);
      } else {
        charIdx = 0;
        lineIdx++;
        timeout = setTimeout(type, 400);
      }
    };

    timeout = setTimeout(type, 800);
    return () => clearTimeout(timeout);
  }, []);

  useEffect(() => {
    const el = logRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [renderLines]);

  const handleCopy = () => {
    const cmd = 'git clone https://github.com/palmar973/VulnSeeker.git && pip install -r requirements.txt';
    navigator.clipboard.writeText(cmd).then(() => {
      toast.success('Copiado');
    });
  };

  useEffect(() => {
    const onScroll = () => setShowTop(window.scrollY > 240);
    window.addEventListener('scroll', onScroll);
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  useEffect(() => {
    const sequence = [
      'arrowup',
      'arrowup',
      'arrowdown',
      'arrowdown',
      'arrowleft',
      'arrowright',
      'arrowleft',
      'arrowright',
      'b',
      'a',
    ];
    const handler = (e: KeyboardEvent) => {
      const key = e.key.toLowerCase();
      const expected = sequence[konamiRef.current];
      if (key === expected) {
        konamiRef.current += 1;
        if (konamiRef.current === sequence.length) {
          setShowEaster(true);
          if (hideEasterRef.current) clearTimeout(hideEasterRef.current);
          hideEasterRef.current = setTimeout(() => setShowEaster(false), 8000);
          konamiRef.current = 0;
        }
      } else {
        konamiRef.current = 0;
      }
    };
    window.addEventListener('keydown', handler);
    return () => {
      window.removeEventListener('keydown', handler);
      if (hideEasterRef.current) clearTimeout(hideEasterRef.current);
    };
  }, []);

  return (
    <div className="relative min-h-screen bg-[#0a0a0a] text-white font-sans overflow-x-hidden">
      {showEaster && (
        <motion.div
          initial={{ opacity: 0, y: -20, scale: 0.98 }}
          animate={{ opacity: 1, y: 0, scale: 1, transition: { duration: 0.25 } }}
          exit={{ opacity: 0, y: -20 }}
          className="fixed top-24 left-1/2 z-[70] -translate-x-1/2 rounded-xl border border-[#00ff88] bg-black/70 px-6 py-3 shadow-[0_18px_50px_rgba(0,0,0,0.55)] backdrop-blur-sm"
        >
          <div className="flex items-center gap-3 font-mono text-sm text-[#00ff88]">
            <span className="flex h-3 w-3">
              <span className="h-3 w-3 rounded-full bg-[#00ff88] opacity-80 animate-ping" />
            </span>
            <span className="font-semibold tracking-[0.08em]">MODO DIOS ACTIVADO</span>
            <span className="text-gray-300">+20% threads · IA extendida · HUD reactivo</span>
          </div>
        </motion.div>
      )}
      <Toaster position="bottom-right" />
      <div
        className="pointer-events-none fixed inset-0 z-[60]"
        style={{
          backgroundImage:
            'repeating-linear-gradient(0deg, rgba(0,0,0,0.03) 0px, rgba(0,0,0,0.03) 1px, transparent 1px, transparent 2px)',
        }}
      />
      <nav className="fixed inset-x-0 top-0 z-50 flex items-center justify-between px-6 md:px-12 py-6 bg-gradient-to-b from-[#0a0a0a] to-transparent">
        <a className="flex items-center gap-3 font-mono font-bold text-lg" href="#">
          <span className="flex h-8 w-8 items-center justify-center bg-[#00ff88] text-[#0a0a0a] font-extrabold">
            V
          </span>
          VulnSeeker
        </a>
        <div className="hidden md:flex items-center gap-10 text-sm text-gray-400">
          <a href="#features" className="hover:text-[#00ff88]">Módulos</a>
          <a href="#install" className="hover:text-[#00ff88]">Despliegue</a>
          <a href="https://github.com/palmar973/VulnSeeker#readme" target="_blank" rel="noopener noreferrer" className="hover:text-[#00ff88]">Documentación</a>
          <a href="https://github.com/palmar973/VulnSeeker" target="_blank" rel="noopener noreferrer" className="hover:text-[#00ff88]">GitHub</a>
        </div>
        <div className="flex items-center gap-3">
          <a
            aria-label="Dar estrella en GitHub"
            className="hidden md:flex items-center gap-2 rounded-md border border-[#333] bg-[#111] px-4 py-2 font-mono text-sm hover:border-[#00ff88] hover:text-[#00ff88]"
            href="https://github.com/palmar973/VulnSeeker"
            target="_blank"
            rel="noopener noreferrer"
          >
            <svg viewBox="0 0 24 24" fill="currentColor" className="h-4 w-4">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
            </svg>
            Dar estrella en GitHub
          </a>
          <a
            aria-label="Clonar repositorio de VulnSeeker"
            className="flex items-center gap-2 rounded-[4px] bg-[#00ff88] px-6 py-3 font-mono text-sm font-semibold uppercase text-[#0a0a0a] shadow-[0_10px_40px_rgba(0,255,136,0.3)] transition hover:-translate-y-0.5"
            href="https://github.com/palmar973/VulnSeeker"
            target="_blank"
            rel="noopener noreferrer"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-4 w-4">
              <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3" />
            </svg>
            Clonar Repo
          </a>
        </div>
      </nav>

      <main className="relative overflow-hidden">
        <section className="relative flex min-h-screen items-center px-6 pb-16 pt-28 md:px-12">
          <canvas ref={canvasRef} className="absolute inset-0 z-0 opacity-40" />
          <div className="glow glow-1" />
          <div className="glow glow-2" />
          <div
            className="absolute inset-0 z-10 opacity-10"
            style={{
              backgroundImage:
                'linear-gradient(#333 1px, transparent 1px), linear-gradient(90deg, #333 1px, transparent 1px)',
              backgroundSize: '80px 80px',
              maskImage: 'radial-gradient(ellipse at center, black 0%, transparent 70%)',
              WebkitMaskImage: 'radial-gradient(ellipse at center, black 0%, transparent 70%)',
            }}
          />
          <div className="absolute inset-0 z-5 bg-[radial-gradient(ellipse_at_center,rgba(0,255,136,0.12),transparent_60%)]" />
          <div className="relative z-20 grid w-full gap-10 lg:grid-cols-[1.1fr_0.9fr]">
            <motion.div variants={fadeIn} initial="hidden" animate="show" className="max-w-4xl">
              <div className="inline-flex items-center gap-2 rounded border border-[#00ff88] bg-[rgba(0,255,136,0.1)] px-4 py-2 font-mono text-xs uppercase tracking-[0.2em] text-[#00ff88] mb-8">
                ● Compatible con Python 3.14
              </div>
              <h1
                className="glitch relative mb-6 text-[clamp(3rem,9vw,6.5rem)] font-black leading-[1] tracking-[-0.14em] pr-2"
                data-text="VULNSEEKER"
              >
                <span className="block">VULN</span>
                <span className="block font-mono text-[0.6em] text-[#00ff88] tracking-[0.32em]">&lt;SEEKER/&gt;</span>
              </h1>
              <p className="text-lg text-gray-400 max-w-2xl mb-10 leading-8">
                Framework DAST modular potenciado por <strong>ThreadPoolExecutor</strong> y <strong>Groq Llama 3.3</strong>.
                Análisis heurístico automatizado para SQLi, XSS y divulgación de rutas críticas.
              </p>
              <div className="hero-badges">
                <div className="hero-badge">
                  <span className="hero-badge__icon">⚡</span> CI/CD Ready
                </div>
                <div className="hero-badge">
                  <span className="hero-badge__icon">🛡️</span> OWASP Top 10
                </div>
                <div className="hero-badge">
                  <span className="hero-badge__icon">📄</span> PDF Ejecutivo
                </div>
                <div className="hero-badge">
                  <span className="hero-badge__icon">🖥️</span> GUI CTk
                </div>
              </div>
              <div className="flex flex-col sm:flex-row gap-4 mb-12">
                <a className="flex items-center justify-center gap-2 rounded-[4px] bg-[#00ff88] px-6 py-3 font-mono text-sm font-semibold uppercase text-[#0a0a0a] shadow-[0_10px_40px_rgba(0,255,136,0.3)] transition hover:-translate-y-0.5" href="#">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-4 w-4">
                    <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3" />
                  </svg>
                  Descargar
                </a>
                <a className="flex items-center justify-center gap-2 rounded-[4px] border border-[#333] px-6 py-3 font-mono text-sm font-semibold uppercase text-white transition hover:border-[#00ff88] hover:text-[#00ff88]" href="https://github.com/palmar973/VulnSeeker/tree/main/modules" target="_blank" rel="noopener noreferrer">
                  <svg viewBox="0 0 24 24" fill="currentColor" className="h-4 w-4">
                    <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
                  </svg>
                  Ver Módulos
                </a>
              </div>
              <div className="flex flex-wrap gap-10">
                {STATS.map(({ value, label }) => (
                  <div key={label} className="flex flex-col gap-1">
                    <span className="text-3xl font-extrabold font-mono">{value}</span>
                    <span className="text-xs font-mono text-gray-500">{label}</span>
                  </div>
                ))}
              </div>
            </motion.div>

            <motion.div
              variants={fadeIn}
              initial="hidden"
              animate="show"
              transition={{ delay: 0.15 }}
              className="relative hidden lg:block mt-6"
            >
              <div className="relative h-[300px] overflow-hidden rounded-xl glass-border shadow-[0_20px_60px_rgba(0,0,0,0.5)]">
                <div className="flex items-center gap-2 border-b border-[#222] bg-[#151515] px-4 py-3 text-xs text-gray-500 font-mono">
                  <span className="h-3 w-3 rounded-full bg-[#ff5f56]" />
                  <span className="h-3 w-3 rounded-full bg-[#ffbd2e]" />
                  <span className="h-3 w-3 rounded-full bg-[#27ca40]" />
                  <span className="ml-auto">vulnseeker_engine.py</span>
                </div>
                <div ref={logRef} role="log" aria-live="polite" aria-atomic="false" className="p-4 font-mono text-sm space-y-2 h-[240px] overflow-y-auto">
                  {renderLines.map((line) => (
                    <div
                      key={line.id}
                      className={
                        line.type === 'success'
                          ? 'text-[#00ff88]'
                          : line.type === 'warning'
                            ? 'text-[#ffaa00]'
                            : line.type === 'error'
                              ? 'text-[#ff3366]'
                              : line.type === 'ai'
                                ? 'text-[#8b5cf6]'
                                : 'text-gray-300'
                      }
                    >
                      {line.text}
                      <span className="ml-1 inline-block h-4 w-1 align-middle bg-[#00ff88] animate-pulse" />
                    </div>
                  ))}
                </div>
              </div>
            </motion.div>
          </div>
        </section>

        <section id="features" className="relative px-6 py-20 md:px-12">
          <motion.div variants={fadeIn} initial="hidden" whileInView="show" viewport={{ once: true }} className="text-center mb-16">
            <h2 className="text-[clamp(2rem,5vw,3.5rem)] font-extrabold tracking-[-0.08em] mb-3">
              Diseñado para la Detección
            </h2>
            <p className="text-gray-400 max-w-2xl mx-auto">
              Arquitectura de plugins basada en <code>core.interfaces.ScannerModule</code> para máxima extensibilidad.
            </p>
          </motion.div>

          <div className="grid grid-cols-12 gap-6 max-w-6xl xl:max-w-7xl mx-auto">
            <motion.div
              variants={fadeIn}
              initial="hidden"
              whileInView="show"
              viewport={{ once: true }}
              className="feature-card col-span-12 lg:col-span-6 p-10"
            >
              <div className="feature-card__number">// ARQUITECTURA NÚCLEO</div>
              <div className="feature-card__icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-9 w-9">
                  <rect x="3" y="3" width="7" height="7" />
                  <rect x="14" y="3" width="7" height="7" />
                  <rect x="14" y="14" width="7" height="7" />
                  <rect x="3" y="14" width="7" height="7" />
                </svg>
              </div>
              <h3 className="feature-card__title text-2xl">Ejecución Concurrente</h3>
              <p className="feature-card__description">
                Orquestado por <code>ThreadPoolExecutor</code> con workers configurables.
                Los módulos implementan la clase abstracta <code>ScannerModule</code> para polimorfismo estricto.
              </p>
              <div className="architecture-diagram">
                <div className="architecture-module">ENGINE.PY</div>
                <div className="architecture-connector">→</div>
                <div className="architecture-module">THREAD POOL</div>
                <div className="architecture-module">SQLi Probe</div>
                <div className="architecture-connector">→</div>
                <div className="architecture-module">Groq AI</div>
                <div className="architecture-module">Path Fuzzer</div>
                <div className="architecture-connector">→</div>
                <div className="architecture-module">SQLite DB</div>
              </div>
            </motion.div>

            <motion.div
              variants={fadeIn}
              initial="hidden"
              whileInView="show"
              viewport={{ once: true }}
              className="feature-card col-span-12 sm:col-span-6 lg:col-span-3"
            >
              <div className="feature-card__number">// MÓDULO 01</div>
              <div className="feature-card__icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-7 w-7">
                  <path d="M2 20h20M4 20l4-16M8 20l6-12M10 20l2-8" />
                  <path d="M18 8l-4 4M18 12l-4 4" />
                </svg>
              </div>
              <h3 className="feature-card__title text-xl">SQLi basado en Errores</h3>
              <p className="feature-card__description">
                Detección heurística que compara firmas de BD (MySQL, Oracle, PG) vía <code>sqli_module.py</code>.
              </p>
              <div className="feature-card__code">
                <code>payload: "' OR '1'='1"</code>
                <br />
                <code>error: "ORA-00933 matched"</code>
              </div>
            </motion.div>

            <motion.div
              variants={fadeIn}
              initial="hidden"
              whileInView="show"
              viewport={{ once: true }}
              className="feature-card col-span-12 sm:col-span-6 lg:col-span-3"
            >
              <div className="feature-card__number">// MÓDULO IA</div>
              <div className="feature-card__icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-7 w-7">
                  <path d="M12 20V10M18 20V4M6 20v-4" />
                </svg>
              </div>
              <h3 className="feature-card__title text-xl">Analista Groq AI</h3>
              <p className="feature-card__description">
                <strong>Llama 3.3 70B</strong> genera reportes ejecutivos nivel CISO mediante la API de Groq.
              </p>
              <div className="feature-card__code">
                <code>model="llama-3.3-70b"</code>
                <br />
                <code>risk_score: CRITICAL</code>
              </div>
            </motion.div>

            <motion.div
              variants={fadeIn}
              initial="hidden"
              whileInView="show"
              viewport={{ once: true }}
              className="feature-card col-span-12 sm:col-span-6 lg:col-span-3"
            >
              <div className="feature-card__number">// MÓDULO 02</div>
              <div className="feature-card__icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-7 w-7">
                  <path d="M4 4h16v16H4z" />
                  <path d="M4 9h16" />
                  <circle cx="8" cy="7" r="1" />
                  <circle cx="12" cy="7" r="1" />
                  <circle cx="16" cy="7" r="1" />
                </svg>
              </div>
              <h3 className="feature-card__title text-xl">Subdomain OSINT</h3>
              <p className="feature-card__description">
                <code>SubdomainScanner</code> usa <strong>crt.sh</strong> y <strong>HackerTarget</strong>, filtra wildcards y valida con <code>HEAD</code> HTTPS.
              </p>
              <div className="feature-card__code">
                <code>alive: 5/7</code>
                <br />
                <code>sources: crt.sh → HackerTarget</code>
              </div>
            </motion.div>

            <motion.div
              variants={fadeIn}
              initial="hidden"
              whileInView="show"
              viewport={{ once: true }}
              className="feature-card col-span-12 sm:col-span-6 lg:col-span-3"
            >
              <div className="feature-card__number">// MÓDULO 03</div>
              <div className="feature-card__icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-7 w-7">
                  <path d="M4 4h16v16H4z" />
                  <path d="M4 9h16" />
                  <path d="M9 9v11" />
                  <path d="M15 9v11" />
                </svg>
              </div>
              <h3 className="feature-card__title text-xl">Fingerprint Activo</h3>
              <p className="feature-card__description">
                <strong>TechFingerprinter</strong> lee headers, HTML y paths predictivos para deducir Server, Backend y CMS antes del ataque.
              </p>
              <div className="feature-card__code">
                <code>confidence: HIGH</code>
                <br />
                <code>server: nginx | cms: WordPress</code>
              </div>
            </motion.div>

            <motion.div
              variants={fadeIn}
              initial="hidden"
              whileInView="show"
              viewport={{ once: true }}
              className="feature-card col-span-12 sm:col-span-6 lg:col-span-3"
            >
              <div className="feature-card__number">// MÓDULO 04</div>
              <div className="feature-card__icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-7 w-7">
                  <path d="M4 6h16M4 12h16M4 18h16" />
                  <path d="M7 6v12M17 6v12" />
                </svg>
              </div>
              <h3 className="feature-card__title text-xl">Persistencia SQLite</h3>
              <p className="feature-card__description">
                <code>DatabaseManager</code> guarda <strong>scans</strong>, <strong>subdomains</strong> y <strong>vulnerabilities</strong> con migraciones automáticas.
              </p>
              <div className="feature-card__code">
                <code>tables: scans, subdomains, vulns</code>
                <br />
                <code>columns: technologies, severity</code>
              </div>
            </motion.div>

            <motion.div
              variants={fadeIn}
              initial="hidden"
              whileInView="show"
              viewport={{ once: true }}
              className="feature-card col-span-12 sm:col-span-6 lg:col-span-3"
            >
              <div className="feature-card__number">// MÓDULO 05</div>
              <div className="feature-card__icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-7 w-7">
                  <path d="M4 6h16v12H4z" />
                  <path d="M8 10h8M8 14h5" />
                </svg>
              </div>
              <h3 className="feature-card__title text-xl">Reflected XSS</h3>
              <p className="feature-card__description">
                <code>XSSScanner</code> inyecta canarios y verifica eco sin sanitización para detectar XSS reflejado.
              </p>
              <div className="feature-card__code">
                <code>payload: &lt;VulnSeekerXSS&gt;</code>
                <br />
                <code>evidence: payload in response</code>
              </div>
            </motion.div>

            <motion.div
              variants={fadeIn}
              initial="hidden"
              whileInView="show"
              viewport={{ once: true }}
              className="feature-card col-span-12 sm:col-span-6 lg:col-span-3"
            >
              <div className="feature-card__number">// MÓDULO 06</div>
              <div className="feature-card__icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-7 w-7">
                  <path d="M3 5h18M3 12h18M3 19h18" />
                  <circle cx="7" cy="12" r="2" />
                </svg>
              </div>
              <h3 className="feature-card__title text-xl">Path Fuzzer</h3>
              <p className="feature-card__description">
                <strong>PathFuzzer</strong> paraleliza la búsqueda de <code>.env</code>, <code>.git</code>, paneles admin y backups SQL.
              </p>
              <div className="feature-card__code">
                <code>threads: 8</code>
                <br />
                <code>paths: .env, .git/HEAD, backup.sql</code>
              </div>
            </motion.div>

            <motion.div
              variants={fadeIn}
              initial="hidden"
              whileInView="show"
              viewport={{ once: true }}
              className="feature-card col-span-12 sm:col-span-6 lg:col-span-3"
            >
              <div className="feature-card__number">// MÓDULO 07</div>
              <div className="feature-card__icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-7 w-7">
                  <path d="M4 5h16v14H4z" />
                  <path d="M8 9h8M8 13h5" />
                </svg>
              </div>
              <h3 className="feature-card__title text-xl">TCP Port Scanner</h3>
              <p className="feature-card__description">
                <code>PortScanner</code> prueba puertos críticos (21/22/23/3306/8080) con timeouts de 0.5s para hallazgos rápidos.
              </p>
              <div className="feature-card__code">
                <code>open: Telnet 23 → HIGH</code>
                <br />
                <code>policy: firewall deny</code>
              </div>
            </motion.div>

            <motion.div
              variants={fadeIn}
              initial="hidden"
              whileInView="show"
              viewport={{ once: true }}
              className="feature-card col-span-12 sm:col-span-6 lg:col-span-3"
            >
              <div className="feature-card__number">// MÓDULO UI</div>
              <div className="feature-card__icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-7 w-7">
                  <path d="M4 5h16v14H4z" />
                  <path d="M4 9h16M9 9v10" />
                </svg>
              </div>
              <h3 className="feature-card__title text-xl">Dashboard & Reportes</h3>
              <p className="feature-card__description">
                <strong>CustomTkinter</strong> muestra KPIs, pie/bar charts, historial y lanza AI+PDF. Exporta <code>JSON</code> + <code>PDF</code> y abre carpeta de reportes.
              </p>
              <div className="feature-card__code">
                <code>files: scan_report_*.json</code>
                <br />
                <code>pdf: vulnseeker_scan_{'{id}'}_{'{ts}'} .pdf</code>
              </div>
            </motion.div>
          </div>
        </section>

        <div className="separator" />

        <section className="relative px-6 py-16 md:px-12">
          <motion.div
            variants={fadeIn}
            initial="hidden"
            whileInView="show"
            viewport={{ once: true }}
            className="max-w-6xl mx-auto flex flex-col gap-8"
          >
            <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div>
                <p className="text-xs font-mono text-[#00ff88] tracking-[0.28em] mb-2">STACK</p>
                <h2 className="text-[clamp(2rem,4.5vw,3.1rem)] font-extrabold tracking-[-0.08em] leading-tight">
                  Integraciones listas para producción
                </h2>
                <p className="text-gray-400 max-w-2xl">
                  Enlaza tus pipelines, alertas y herramientas de explotación sin fricción. Todo versionable y auditable.
                </p>
              </div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {INTEGRATIONS.map((item) => (
                <div key={item.name} className="integration-card">
                  <div className="integration-card__top">
                    <span className="integration-card__tag">{item.tag}</span>
                    <span className="integration-card__dot" />
                  </div>
                  <h3 className="integration-card__title">{item.name}</h3>
                  <p className="integration-card__desc">{item.desc}</p>
                </div>
              ))}
            </div>
          </motion.div>
        </section>

        <section id="install" className="install bg-[#111] border-y border-[#222] px-6 py-16 md:px-12">
          <motion.div
            variants={fadeIn}
            initial="hidden"
            whileInView="show"
            viewport={{ once: true }}
            className="install__content text-center max-w-2xl mx-auto"
          >
            <h2 className="install__title text-3xl font-extrabold tracking-[-0.08em] mb-3">Despliega desde el Código</h2>
            <p className="install__description text-gray-400 mb-6">
              Clona el repositorio e instala dependencias con requirements.txt. Requiere Python 3.14+.
            </p>
            <div className="install__code relative mx-auto flex max-w-xl items-center gap-3 rounded-lg border border-[#333] bg-[#0a0a0a] px-5 py-4 font-mono text-[10px] sm:text-xs text-[#00ff88]">
              git clone https://github.com/palmar973/VulnSeeker.git && pip install -r requirements.txt
              <button
                aria-label="Copiar comando de instalación"
                onClick={handleCopy}
                className="install__copy absolute right-3 rounded border border-[#333] px-3 py-1 text-xs text-gray-400 hover:border-[#00ff88] hover:text-[#00ff88]"
              >
                Copiar
              </button>
            </div>
          </motion.div>
        </section>

        <section className="relative px-6 py-16 md:px-12">
          <motion.div
            variants={fadeIn}
            initial="hidden"
            whileInView="show"
            viewport={{ once: true }}
            className="text-center mb-12"
          >
            <h2 className="text-[clamp(2rem,4.5vw,3.25rem)] font-extrabold tracking-[-0.08em] mb-2">
              Pipeline
            </h2>
            <p className="text-gray-400 max-w-2xl mx-auto">
              Desde el descubrimiento hasta el reporte automatizado, listo para CI/CD.
            </p>
          </motion.div>
          <div className="grid gap-4 md:gap-6 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 max-w-6xl mx-auto">
            {PIPELINE.map((step, i) => (
              <motion.div
                key={step.title}
                variants={fadeIn}
                initial="hidden"
                whileInView="show"
                viewport={{ once: true }}
                transition={{ delay: i * 0.05 }}
                className="pipeline-card"
              >
                <div className="pipeline-card__badge">0{i + 1}</div>
                <h3 className="pipeline-card__title">{step.title}</h3>
                <p className="pipeline-card__desc">{step.desc}</p>
              </motion.div>
            ))}
          </div>
        </section>

        <section className="relative px-6 py-16 md:px-12">
          <motion.div variants={fadeIn} initial="hidden" whileInView="show" viewport={{ once: true }} className="text-center mb-12">
            <h2 className="text-[clamp(2rem,4.5vw,3.25rem)] font-extrabold tracking-[-0.08em] mb-2">
              Ajustes de Escaneo
            </h2>
            <p className="text-gray-400 max-w-2xl mx-auto">
              Flags y defaults alineados con <code>core.engine</code>, válidos tanto para CLI como para la GUI CTk.
            </p>
          </motion.div>
          <div className="grid gap-4 md:gap-6 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 max-w-5xl mx-auto">
            {SETTINGS.map((item) => (
              <div key={item.label} className="settings-card">
                <div className="settings-card__top">
                  <span className="settings-card__label">{item.label}</span>
                  <span className="settings-card__value">{item.value}</span>
                </div>
                <p className="settings-card__desc">{item.desc}</p>
              </div>
            ))}
          </div>
        </section>

        <footer className="footer px-6 py-12 md:px-12">
          <div className="footer__content mx-auto flex max-w-6xl flex-col gap-6 md:flex-row md:items-center md:justify-between">
            <div className="footer__brand flex items-center gap-2 font-mono font-bold">
              <span className="footer__brand-icon flex h-7 w-7 items-center justify-center bg-[#00ff88] text-[#0a0a0a] text-sm font-extrabold">
                V
              </span>
              VulnSeeker v2.4.0
            </div>
            <div className="footer__links flex flex-wrap gap-4 text-sm text-gray-500">
              <a href="https://github.com/palmar973/VulnSeeker" target="_blank" rel="noopener noreferrer" className="hover:text-[#00ff88]">GitHub</a>
              <a href="https://github.com/palmar973/VulnSeeker#readme" target="_blank" rel="noopener noreferrer" className="hover:text-[#00ff88]">Documentación</a>
            </div>
            <div className="footer__meta text-xs font-mono text-gray-500">
              Licencia MIT • Copyright 2025 <a href="https://claudiopalmar.me/" target="_blank" rel="noopener noreferrer" className="text-gray-400 hover:text-[#00ff88] transition">Claudio Palmar</a>
            </div>
          </div>
        </footer>
      </main>

      {showTop && (
        <button
          aria-label="Ir arriba"
          onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
          className="fixed bottom-6 right-6 z-50 rounded-full border border-[#00ff88] bg-[#0f0f0f] px-4 py-2 text-xs font-mono text-[#00ff88] shadow-[0_10px_30px_rgba(0,0,0,0.45)] transition hover:-translate-y-0.5 hover:bg-[#111]"
        >
          ↑ Ir arriba
        </button>
      )}

      <style jsx global>{`
        .glitch {
          position: relative;
        }
        .glitch::before,
        .glitch::after {
          content: attr(data-text);
          position: absolute;
          top: 0;
          left: 0;
          width: 100%;
          height: 100%;
        }
        .glitch::before {
          animation: glitch-1 0.3s infinite linear alternate-reverse;
          color: #ff3366;
          z-index: -1;
        }
        .glitch::after {
          animation: glitch-2 0.3s infinite linear alternate-reverse;
          color: #00ff88;
          z-index: -2;
        }
        @keyframes glitch-1 {
          0% {
            clip-path: inset(20% 0 80% 0);
            transform: translate(-2px, 1px);
          }
          20% {
            clip-path: inset(60% 0 10% 0);
            transform: translate(2px, -1px);
          }
          40% {
            clip-path: inset(40% 0 50% 0);
            transform: translate(-2px, 2px);
          }
          60% {
            clip-path: inset(80% 0 5% 0);
            transform: translate(2px, -2px);
          }
          80% {
            clip-path: inset(10% 0 70% 0);
            transform: translate(-1px, 1px);
          }
          100% {
            clip-path: inset(30% 0 50% 0);
            transform: translate(1px, -1px);
          }
        }
        @keyframes glitch-2 {
          0% {
            clip-path: inset(10% 0 60% 0);
            transform: translate(2px, -1px);
          }
          20% {
            clip-path: inset(80% 0 5% 0);
            transform: translate(-2px, 1px);
          }
          40% {
            clip-path: inset(30% 0 20% 0);
            transform: translate(2px, 2px);
          }
          60% {
            clip-path: inset(10% 0 80% 0);
            transform: translate(-2px, -2px);
          }
          80% {
            clip-path: inset(50% 0 30% 0);
            transform: translate(1px, 1px);
          }
          100% {
            clip-path: inset(70% 0 10% 0);
            transform: translate(-1px, 2px);
          }
        }
        .btn-primary {
          @apply flex items-center justify-center gap-2 rounded-[4px] bg-[#00ff88] px-6 py-3 font-mono text-sm font-semibold uppercase text-[#0a0a0a] transition hover:-translate-y-0.5;
        }
        .btn-secondary {
          @apply flex items-center justify-center gap-2 rounded-[4px] border border-[#333] px-6 py-3 font-mono text-sm font-semibold uppercase text-white hover:border-[#00ff88] hover:text-[#00ff88];
        }
        .feature-card {
          position: relative;
          padding: 2.5rem;
          background: #111111;
          border: 1px solid #333333;
          border-radius: 8px;
          overflow: hidden;
          transition: all 0.3s ease;
          cursor: default;
        }
        .feature-card::before {
          content: '';
          position: absolute;
          top: 0;
          left: 0;
          width: 100%;
          height: 3px;
          background: #00ff88;
          transform: scaleX(0);
          transform-origin: left;
          transition: transform 0.3s ease;
        }
        .feature-card:hover {
          transform: translateY(-8px);
          border-color: #00ff88;
          box-shadow: 0 20px 50px rgba(0, 0, 0, 0.4);
        }
        .feature-card:hover::before {
          transform: scaleX(1);
        }
        .feature-card__icon {
          width: 56px;
          height: 56px;
          display: flex;
          align-items: center;
          justify-content: center;
          background: rgba(0, 255, 136, 0.1);
          border: 1px solid #00ff88;
          border-radius: 8px;
          margin-bottom: 1.5rem;
          transition: all 0.3s ease;
        }
        .feature-card:hover .feature-card__icon {
          background: #00ff88;
          color: #0a0a0a;
        }
        .feature-card__number {
          font-family: 'JetBrains Mono', monospace;
          font-size: 0.75rem;
          color: #00ff88;
          margin-bottom: 1rem;
          opacity: 0.7;
        }
        .feature-card__title {
          font-size: 1.5rem;
          font-weight: 700;
          margin-bottom: 1rem;
          letter-spacing: -0.5px;
        }
        .feature-card__description {
          color: #a0a0a0;
          line-height: 1.8;
          margin-bottom: 1.5rem;
        }
        .feature-card__code {
          font-family: 'JetBrains Mono', monospace;
          font-size: 0.75rem;
          padding: 1rem;
          background: #0a0a0a;
          border-radius: 4px;
          color: #666666;
          overflow-x: auto;
          border: 1px solid #222;
        }
        .feature-card__code code {
          color: #00ff88;
        }
        .architecture-diagram {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 1rem;
          margin-top: 2rem;
        }
        .architecture-module {
          padding: 1rem;
          background: #0a0a0a;
          border: 1px solid #333333;
          border-radius: 4px;
          text-align: center;
          font-family: 'JetBrains Mono', monospace;
          font-size: 0.75rem;
          color: #a0a0a0;
          transition: all 0.15s ease;
        }
        .architecture-module:hover {
          border-color: #00ff88;
          color: #00ff88;
        }
        .architecture-connector {
          display: flex;
          align-items: center;
          justify-content: center;
          color: #00ff88;
          font-size: 1.25rem;
        }
        .pipeline-card {
          background: #111111;
          border: 1px solid #333333;
          border-radius: 8px;
          padding: 1.5rem;
          height: 100%;
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
          transition: all 0.2s ease;
        }
        .pipeline-card::before {
          content: '';
          position: absolute;
          inset: 0;
          border-radius: 8px;
          padding: 1px;
          background: linear-gradient(120deg, rgba(0,255,136,0.4), rgba(139,92,246,0.3), rgba(255,51,102,0.35));
          -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
          -webkit-mask-composite: xor;
          mask-composite: exclude;
          opacity: 0;
          transition: opacity 0.2s ease;
        }
        .pipeline-card:hover {
          border-color: #00ff88;
          transform: translateY(-6px);
          box-shadow: 0 14px 30px rgba(0, 0, 0, 0.35);
        }
        .pipeline-card:hover::before {
          opacity: 1;
        }
        .hero-badges {
          display: flex;
          flex-wrap: wrap;
          gap: 0.6rem;
          margin-bottom: 1.5rem;
        }
        .hero-badge {
          display: inline-flex;
          align-items: center;
          gap: 0.45rem;
          padding: 0.55rem 0.75rem;
          border-radius: 10px;
          border: 1px solid #1f1f1f;
          background: rgba(255, 255, 255, 0.03);
          box-shadow: 0 12px 30px rgba(0, 0, 0, 0.35);
          font-family: 'JetBrains Mono', monospace;
          font-size: 0.8rem;
          color: #e5e5e5;
        }
        .hero-badge__icon {
          display: inline-flex;
          width: 28px;
          height: 28px;
          align-items: center;
          justify-content: center;
          border-radius: 8px;
          background: rgba(0, 255, 136, 0.12);
          border: 1px solid #00ff88;
          color: #00ff88;
        }
        .glass-border {
          position: relative;
          background: linear-gradient(#0f0f0f, #0f0f0f) padding-box,
            linear-gradient(135deg, rgba(0,255,136,0.8), rgba(139,92,246,0.8), rgba(255,51,102,0.8)) border-box;
          border: 1px solid transparent;
        }
        .glow {
          position: absolute;
          filter: blur(70px);
          opacity: 0.55;
          z-index: 5;
        }
        .glow-1 {
          width: 420px;
          height: 420px;
          top: -120px;
          left: -140px;
          background: radial-gradient(circle, rgba(0,255,136,0.45), transparent 55%);
        }
        .glow-2 {
          width: 360px;
          height: 360px;
          bottom: -120px;
          right: -120px;
          background: radial-gradient(circle, rgba(139,92,246,0.4), transparent 55%);
        }
        .separator {
          width: 100%;
          height: 2px;
          background: linear-gradient(90deg, rgba(0,255,136,0) 0%, rgba(0,255,136,0.6) 40%, rgba(139,92,246,0.6) 60%, rgba(0,255,136,0) 100%);
          opacity: 0.7;
        }
        .integration-card {
          position: relative;
          background: radial-gradient(circle at 20% 20%, rgba(0,255,136,0.08), transparent 35%), #0f0f0f;
          border: 1px solid #222;
          border-radius: 10px;
          padding: 1.25rem;
          box-shadow: 0 14px 34px rgba(0, 0, 0, 0.35);
          transition: all 0.2s ease;
        }
        .integration-card::after {
          content: '';
          position: absolute;
          inset: 0;
          border-radius: 10px;
          padding: 1px;
          background: linear-gradient(120deg, rgba(0,255,136,0.4), rgba(139,92,246,0.35));
          -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
          -webkit-mask-composite: xor;
          mask-composite: exclude;
          opacity: 0;
          transition: opacity 0.2s ease;
        }
        .integration-card:hover {
          border-color: #00ff88;
          transform: translateY(-6px);
        }
        .integration-card:hover::after {
          opacity: 1;
        }
        .integration-card__top {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          margin-bottom: 0.6rem;
        }
        .integration-card__tag {
          font-family: 'JetBrains Mono', monospace;
          font-size: 0.7rem;
          padding: 0.35rem 0.6rem;
          border-radius: 6px;
          background: rgba(0,255,136,0.12);
          border: 1px solid rgba(0,255,136,0.5);
          color: #00ff88;
        }
        .integration-card__dot {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: #8b5cf6;
          box-shadow: 0 0 12px rgba(139,92,246,0.9);
          margin-left: auto;
        }
        .integration-card__title {
          font-weight: 700;
          font-size: 1.05rem;
          margin-bottom: 0.35rem;
          letter-spacing: -0.02em;
        }
        .integration-card__desc {
          color: #9e9e9e;
          line-height: 1.7;
          font-size: 0.95rem;
        }
        .settings-card {
          background: #111111;
          border: 1px solid #222;
          border-radius: 10px;
          padding: 1.1rem 1.2rem;
          box-shadow: 0 12px 30px rgba(0, 0, 0, 0.35);
          transition: all 0.2s ease;
        }
        .settings-card:hover {
          border-color: #00ff88;
          transform: translateY(-5px);
        }
        .settings-card__top {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 0.55rem;
          font-family: 'JetBrains Mono', monospace;
        }
        .settings-card__label {
          font-size: 0.9rem;
          color: #00ff88;
        }
        .settings-card__value {
          font-size: 0.95rem;
          color: #e5e5e5;
          padding: 0.2rem 0.55rem;
          border: 1px solid #333;
          border-radius: 6px;
          background: #0a0a0a;
        }
        .settings-card__desc {
          color: #9e9e9e;
          line-height: 1.6;
          font-size: 0.95rem;
        }
      `}</style>
    </div>
  );
}
