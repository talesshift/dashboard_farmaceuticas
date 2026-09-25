
// ============================================================================
// GITHUB PAGES / OFFLINE STATIC DATA ADAPTER WITH AES-256-GCM DECRYPTION
// ============================================================================
let isStaticMode = (
  window.location.protocol === 'file:' || 
  window.location.hostname.includes('github.io') ||
  window.location.hostname.includes('pages.dev') ||
  window.location.port !== '5000'
);

let sessionPassword = sessionStorage.getItem('_farma_vault_pwd') || '';
let staticDataCache = {
  stats: null,
  charts: null,
  sankey: null,
  network: null,
  empresas: null,
  especiais: null,
  catalogo: null,
  societario: null
};

async function deriveKeyFromPassword(password, salt) {
  const enc = new TextEncoder();
  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
}

async function fetchAndDecryptJson(encUrl) {
  const res = await originalFetch(encUrl);
  if (!res.ok) throw new Error(`Falha ao carregar ${encUrl} (HTTP ${res.status})`);
  const buf = await res.arrayBuffer();
  const bytes = new Uint8Array(buf);
  if (bytes.length < 28) throw new Error('Arquivo cifrado corrompido ou incompleto');
  const salt = bytes.slice(0, 16);
  const iv = bytes.slice(16, 28);
  const ciphertext = bytes.slice(28);

  const key = await deriveKeyFromPassword(sessionPassword, salt);
  const decryptedBuf = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    ciphertext
  );
  const dec = new TextDecoder('utf-8');
  return JSON.parse(dec.decode(decryptedBuf));
}

window.unlockDashboardWithPassword = async function() {
  const pwdInput = document.getElementById('crypto-password-input');
  const rememberCheck = document.getElementById('crypto-remember-check');
  const errorMsg = document.getElementById('crypto-error-msg');
  const submitBtn = document.getElementById('crypto-unlock-btn');

  const enteredPwd = (pwdInput.value || '').trim();
  if (!enteredPwd) {
    errorMsg.innerText = 'Por favor, digite a senha de acesso.';
    errorMsg.style.display = 'block';
    return;
  }

  submitBtn.disabled = true;
  submitBtn.innerText = 'Descriptografando base de dados...';
  errorMsg.style.display = 'none';

  try {
    sessionPassword = enteredPwd;
    // Tenta decifrar stats.json.enc para validar a chave
    const testStats = await fetchAndDecryptJson('data/stats.json.enc');
    staticDataCache.stats = testStats;

    if (rememberCheck && rememberCheck.checked) {
      sessionStorage.setItem('_farma_vault_pwd', enteredPwd);
    } else {
      sessionStorage.removeItem('_farma_vault_pwd');
    }

    const lockScreen = document.getElementById('crypto-lockscreen');
    if (lockScreen) {
      lockScreen.style.opacity = '0';
      setTimeout(() => {
        lockScreen.style.display = 'none';
      }, 300);
    }

    if (typeof window.startDashboardApp === 'function') {
      window.startDashboardApp();
    }
  } catch (err) {
    console.error('Falha de descriptografia:', err);
    errorMsg.innerText = 'Chave de acesso incorreta. Os dados permanecem bloqueados.';
    errorMsg.style.display = 'block';
    submitBtn.disabled = false;
    submitBtn.innerText = 'Descriptografar e Acessar';
  }
};

document.addEventListener('DOMContentLoaded', async () => {
  if (!isStaticMode) {
    const lockScreen = document.getElementById('crypto-lockscreen');
    if (lockScreen) lockScreen.style.display = 'none';
    if (typeof window.startDashboardApp === 'function') window.startDashboardApp();
    return;
  }

  // Verificar se há senha salva na sessão
  const savedPwd = sessionStorage.getItem('_farma_vault_pwd');
  if (savedPwd) {
    sessionPassword = savedPwd;
    try {
      staticDataCache.stats = await fetchAndDecryptJson('data/stats.json.enc');
      const lockScreen = document.getElementById('crypto-lockscreen');
      if (lockScreen) lockScreen.style.display = 'none';
      if (typeof window.startDashboardApp === 'function') window.startDashboardApp();
      return;
    } catch (e) {
      sessionStorage.removeItem('_farma_vault_pwd');
      sessionPassword = '';
    }
  }

  // Exibir tela de bloqueio
  const lockScreen = document.getElementById('crypto-lockscreen');
  if (lockScreen) {
    lockScreen.style.display = 'flex';
    const pwdInput = document.getElementById('crypto-password-input');
    if (pwdInput) pwdInput.focus();
  }
});

async function getStaticCatalogo() {
  if (staticDataCache.catalogo) return staticDataCache.catalogo;
  const raw = await fetchAndDecryptJson('data/catalogo.json.enc');
  const cols = raw.cols;
  staticDataCache.catalogo = raw.rows.map(r => {
    const o = {};
    for (let i = 0; i < cols.length; i++) o[cols[i]] = r[i];
    return o;
  });
  return staticDataCache.catalogo;
}

// Interceptar global fetch para decifrar os arquivos binários sob demanda
const originalFetch = window.fetch;
window.fetch = async function(url, options) {
  const urlStr = url.toString();
  
  if (isStaticMode || !urlStr.startsWith('http://127.0.0.1:5000')) {
    if (urlStr.startsWith('/api/stats') || urlStr.startsWith('api/stats')) {
      if (!staticDataCache.stats) {
        staticDataCache.stats = await fetchAndDecryptJson('data/stats.json.enc');
      }
      return new Response(JSON.stringify(staticDataCache.stats), { headers: { 'Content-Type': 'application/json' } });
    }
    if (urlStr.startsWith('/api/charts') || urlStr.startsWith('api/charts')) {
      if (!staticDataCache.charts) {
        staticDataCache.charts = await fetchAndDecryptJson('data/charts.json.enc');
      }
      return new Response(JSON.stringify(staticDataCache.charts), { headers: { 'Content-Type': 'application/json' } });
    }
    if (urlStr.startsWith('/api/sankey') || urlStr.startsWith('api/sankey')) {
      if (!staticDataCache.sankey) {
        staticDataCache.sankey = await fetchAndDecryptJson('data/sankey.json.enc');
      }
      return new Response(JSON.stringify(staticDataCache.sankey), { headers: { 'Content-Type': 'application/json' } });
    }
    if (urlStr.startsWith('/api/network') || urlStr.startsWith('api/network')) {
      if (!staticDataCache.network) {
        staticDataCache.network = await fetchAndDecryptJson('data/network.json.enc');
      }
      return new Response(JSON.stringify(staticDataCache.network), { headers: { 'Content-Type': 'application/json' } });
    }
    
    // Static Empresas handling
    if (urlStr.includes('/api/empresas') || urlStr.includes('api/empresas')) {
      if (!staticDataCache.empresas) {
        staticDataCache.empresas = await fetchAndDecryptJson('data/empresas.json.enc');
      }
      const parsedUrl = new URL(urlStr, window.location.href);
      const q = (parsedUrl.searchParams.get('q') || '').toLowerCase().trim();
      const sortBy = parsedUrl.searchParams.get('sort_by') || 'total_produtos_cmed';
      const sortOrder = parsedUrl.searchParams.get('sort_order') || 'desc';
      
      let list = staticDataCache.empresas.filter(e => {
        if (!q) return true;
        return (e.razao_social || '').toLowerCase().includes(q) ||
               (e.nome_fantasia || '').toLowerCase().includes(q) ||
               (e.cnpj_limpo || '').includes(q) ||
               (e.socios_donos_administradores || '').toLowerCase().includes(q);
      });
      
      list.sort((a, b) => {
        let va = a[sortBy] ?? '';
        let vb = b[sortBy] ?? '';
        if (typeof va === 'number' && typeof vb === 'number') {
          return sortOrder === 'asc' ? va - vb : vb - va;
        }
        return sortOrder === 'asc' ? String(va).localeCompare(String(vb)) : String(vb).localeCompare(String(va));
      });
      
      return new Response(JSON.stringify({
        total: list.length,
        items: list
      }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Static Especiais handling
    if (urlStr.includes('/api/especiais') || urlStr.includes('api/especiais')) {
      if (!staticDataCache.especiais) {
        staticDataCache.especiais = await fetchAndDecryptJson('data/especiais.json.enc');
      }
      const parsedUrl = new URL(urlStr, window.location.href);
      const q = (parsedUrl.searchParams.get('q') || '').toLowerCase().trim();
      const cat = (parsedUrl.searchParams.get('categoria') || '').toUpperCase().trim();
      const status = (parsedUrl.searchParams.get('situacao') || '').toUpperCase().trim();
      const sortBy = parsedUrl.searchParams.get('sort_by') || 'nome';
      const sortOrder = parsedUrl.searchParams.get('sort_order') || 'asc';
      const page = parseInt(parsedUrl.searchParams.get('page') || '1');
      const limit = parseInt(parsedUrl.searchParams.get('limit') || '15');

      let list = staticDataCache.especiais.filter(e => {
        if (cat && !(e.categoria_regulatoria || '').toUpperCase().includes(cat)) return false;
        if (status && !(e.situacao_registro || '').toUpperCase().includes(status)) return false;
        if (q) {
          const match = (e.nome_produto || '').toLowerCase().includes(q) ||
                        (e.razao_social_detentora || '').toLowerCase().includes(q) ||
                        (e.principio_ativo || '').toLowerCase().includes(q) ||
                        (e.numero_registro_base || '').includes(q) ||
                        (e.classe_terapeutica || '').toLowerCase().includes(q);
          if (!match) return false;
        }
        return true;
      });

      const sortMap = {
        'nome': 'nome_produto',
        'categoria': 'categoria_regulatoria',
        'principio': 'principio_ativo',
        'detentora': 'razao_social_detentora',
        'situacao': 'situacao_registro',
        'total_apresentacoes': 'total_apresentacoes',
        'preco': 'preco_medio_pf18'
      };
      const col = sortMap[sortBy] || 'nome_produto';
      list.sort((a, b) => {
        let va = a[col] ?? '';
        let vb = b[col] ?? '';
        if (typeof va === 'number' && typeof vb === 'number') {
          return sortOrder === 'asc' ? va - vb : vb - va;
        }
        return sortOrder === 'asc' ? String(va).localeCompare(String(vb)) : String(vb).localeCompare(String(va));
      });

      const total = list.length;
      const pages = Math.ceil(total / limit) || 1;
      const items = list.slice((page - 1) * limit, page * limit);

      return new Response(JSON.stringify({
        total,
        page,
        pages,
        limit,
        items
      }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Static Medicamentos & Drilldown handling via catalogo.json.enc
    if (urlStr.includes('/api/medicamentos') || urlStr.includes('api/medicamentos')) {
      const catList = await getStaticCatalogo();
      const parsedUrl = new URL(urlStr, window.location.href);
      const q = (parsedUrl.searchParams.get('q') || '').toLowerCase().trim();
      const pais = (parsedUrl.searchParams.get('pais') || '').trim();
      const tipo = (parsedUrl.searchParams.get('tipo') || '').toUpperCase().trim();
      const tarja = (parsedUrl.searchParams.get('tarja') || '').toUpperCase().trim();
      const page = parseInt(parsedUrl.searchParams.get('page') || '1');
      const limit = parseInt(parsedUrl.searchParams.get('limit') || '15');
      const sortBy = parsedUrl.searchParams.get('sort_by') || 'produto';
      const sortOrder = parsedUrl.searchParams.get('sort_order') || 'asc';

      let filtered = catList.filter(m => {
        if (pais && m.pais !== pais) return false;
        if (tipo && (m.tipo || '').toUpperCase() !== tipo) return false;
        if (tarja) {
          const mTarja = (m.tarja || '').toUpperCase();
          if (tarja.includes('PRETA') && !mTarja.includes('PRETA')) return false;
          if (tarja.includes('RETEN') && !(mTarja.includes('RETEN') || mTarja.includes('RESTRI'))) return false;
          if (tarja.includes('MIP') || tarja.includes('ISENT')) {
            if (!(mTarja.includes('ISENT') || mTarja.includes('MIP') || mTarja.includes('SEM TARJA') || mTarja.includes('(*)'))) return false;
          }
          if (tarja === 'TARJA VERMELHA') {
            if (!(mTarja.includes('VERMELHA') && !mTarja.includes('RESTRI') && !mTarja.includes('RETEN'))) return false;
          }
        }
        if (q) {
          const match = (m.produto || '').toLowerCase().includes(q) ||
                        (m.substancia || '').toLowerCase().includes(q) ||
                        (m.detentora || '').toLowerCase().includes(q) ||
                        (m.fabrica || '').toLowerCase().includes(q) ||
                        (m.registro_13 || '').includes(q);
          if (!match) return false;
        }
        return true;
      });

      filtered.sort((a, b) => {
        let va = a[sortBy] ?? '';
        let vb = b[sortBy] ?? '';
        if (typeof va === 'number' && typeof vb === 'number') {
          return sortOrder === 'asc' ? va - vb : vb - va;
        }
        return sortOrder === 'asc' ? String(va).localeCompare(String(vb)) : String(vb).localeCompare(String(va));
      });

      const total = filtered.length;
      const pages = Math.ceil(total / limit) || 1;
      const items = filtered.slice((page - 1) * limit, page * limit);

      return new Response(JSON.stringify({
        total,
        page,
        pages,
        limit,
        items
      }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Static Drilldown
    if (urlStr.includes('/api/drilldown') || urlStr.includes('api/drilldown')) {
      const catList = await getStaticCatalogo();
      const parsedUrl = new URL(urlStr, window.location.href);
      const fType = (parsedUrl.searchParams.get('filter_type') || '').toLowerCase().trim();
      const fVal = (parsedUrl.searchParams.get('filter_val') || '').trim();
      const entity = (parsedUrl.searchParams.get('entity_type') || 'medicamentos').toLowerCase().trim();
      const q = (parsedUrl.searchParams.get('q') || '').toLowerCase().trim();
      const page = parseInt(parsedUrl.searchParams.get('page') || '1');
      const limit = parseInt(parsedUrl.searchParams.get('limit') || '20');

      let filtered = catList.filter(m => {
        if (fType === 'pais') {
          if (fVal.toUpperCase().includes('NAO MAP') || fVal.toUpperCase().includes('NÃO MAP')) {
            if (m.tipo !== null && m.pais !== null) return false;
          } else {
            if ((m.pais || '').toUpperCase() !== fVal.toUpperCase()) return false;
          }
        } else if (fType === 'tipo_fabricante') {
          if ((m.tipo || '').toUpperCase() !== fVal.toUpperCase()) return false;
        } else if (fType === 'tarja') {
          const mTarja = (m.tarja || '').toUpperCase();
          const target = fVal.toUpperCase();
          if (target.includes('PRETA') && !mTarja.includes('PRETA')) return false;
          if (target.includes('RETEN') && !(mTarja.includes('RETEN') || mTarja.includes('RESTRI'))) return false;
          if (target.includes('MIP') || target.includes('ISENT')) {
            if (!(mTarja.includes('ISENT') || mTarja.includes('MIP') || mTarja.includes('SEM TARJA') || mTarja.includes('(*)'))) return false;
          }
          if (target === 'TARJA VERMELHA') {
            if (!(mTarja.includes('VERMELHA') && !mTarja.includes('RESTRI') && !mTarja.includes('RETEN'))) return false;
          }
        } else if (fType === 'forma_farmaceutica') {
          if ((m.forma || '').toUpperCase() !== fVal.toUpperCase()) return false;
        } else if (fType === 'uf') {
          if ((m.uf || '').toUpperCase() !== fVal.toUpperCase()) return false;
        } else if (fType === 'detentora') {
          if ((m.detentora || '').toUpperCase() !== fVal.toUpperCase()) return false;
        } else if (fType === 'fabrica') {
          if ((m.fabrica || '').toUpperCase() !== fVal.toUpperCase()) return false;
        }
        return true;
      });

      if (entity === 'empresas') {
        const empMap = {};
        filtered.forEach(m => {
          const key = m.detentora || 'Desconhecida';
          if (!empMap[key]) {
            empMap[key] = {
              detentora: key,
              razao_social: key,
              cnpj: m.cnpj_detentora || '-',
              total_produtos: 0,
              produtos_set: new Set()
            };
          }
          empMap[key].total_produtos++;
          empMap[key].produtos_set.add(m.produto);
        });
        let list = Object.values(empMap).map(e => ({
          detentora: e.detentora,
          razao_social: e.razao_social,
          cnpj: e.cnpj,
          total_apresentacoes: e.total_produtos,
          total_produtos: e.produtos_set.size
        }));
        if (q) {
          list = list.filter(e => e.detentora.toLowerCase().includes(q) || (e.cnpj && e.cnpj.includes(q)));
        }
        list.sort((a, b) => b.total_apresentacoes - a.total_apresentacoes);
        const total = list.length;
        const pages = Math.ceil(total / limit) || 1;
        const items = list.slice((page - 1) * limit, page * limit);
        return new Response(JSON.stringify({
          filter_type: fType,
          filter_val: fVal,
          entity_type: entity,
          total,
          page,
          pages,
          limit,
          items
        }), { headers: { 'Content-Type': 'application/json' } });
      }

      if (entity === 'fabricas') {
        const fabMap = {};
        filtered.forEach(m => {
          const key = m.fabrica || 'Não Mapeada';
          if (!fabMap[key]) {
            fabMap[key] = {
              fabrica: key,
              razao_social: key,
              cnpj: m.cnpj_fabrica || '-',
              pais: m.pais || 'BRASIL',
              tipo: m.tipo || 'NACIONAL',
              uf: m.uf || '-',
              total_produtos: 0,
              detentoras_set: new Set()
            };
          }
          fabMap[key].total_produtos++;
          if (m.detentora) fabMap[key].detentoras_set.add(m.detentora);
        });
        let list = Object.values(fabMap).map(f => ({
          fabrica: f.fabrica,
          razao_social: f.razao_social,
          cnpj: f.cnpj,
          pais: f.pais,
          tipo: f.tipo,
          uf: f.uf,
          total_apresentacoes: f.total_produtos,
          total_detentoras_atendidas: f.detentoras_set.size
        }));
        if (q) {
          list = list.filter(f => f.fabrica.toLowerCase().includes(q) || (f.pais && f.pais.toLowerCase().includes(q)));
        }
        list.sort((a, b) => b.total_apresentacoes - a.total_apresentacoes);
        const total = list.length;
        const pages = Math.ceil(total / limit) || 1;
        const items = list.slice((page - 1) * limit, page * limit);
        return new Response(JSON.stringify({
          filter_type: fType,
          filter_val: fVal,
          entity_type: entity,
          total,
          page,
          pages,
          limit,
          items
        }), { headers: { 'Content-Type': 'application/json' } });
      }

      // Default: entity === 'medicamentos'
      if (q) {
        filtered = filtered.filter(m => (m.produto || '').toLowerCase().includes(q) || (m.substancia || '').toLowerCase().includes(q) || (m.registro_13 || '').includes(q));
      }
      filtered.sort((a, b) => (a.produto || '').localeCompare(b.produto || ''));
      const total = filtered.length;
      const pages = Math.ceil(total / limit) || 1;
      const items = filtered.slice((page - 1) * limit, page * limit);
      return new Response(JSON.stringify({
        filter_type: fType,
        filter_val: fVal,
        entity_type: entity,
        total,
        page,
        pages,
        limit,
        items
      }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Static Societário Lookup
    if (urlStr.includes('/api/societario') || urlStr.includes('api/societario')) {
      if (!staticDataCache.societario) {
        staticDataCache.societario = await fetchAndDecryptJson('data/societario.json.enc');
      }
      const rawIdent = decodeURIComponent(urlStr.split('/societario/')[1] || '').trim();
      const identLimpo = rawIdent.replace(/[^0-9]/g, '');
      const identNorm = (rawIdent || '').toUpperCase();

      let found = null;
      if (identLimpo.length >= 8) {
        found = staticDataCache.societario.find(e => (e.cnpj_limpo || '').includes(identLimpo));
      }
      if (!found) {
        found = staticDataCache.societario.find(e => {
          const rz = (e.razao_social || '').toUpperCase();
          const nf = (e.nome_fantasia || '').toUpperCase();
          return rz === identNorm || nf === identNorm || rz.includes(identNorm) || identNorm.includes(rz.split(' ')[0]);
        });
      }

      if (!found) {
        const encodedQuery = encodeURIComponent(rawIdent + " pharmaceutical");
        return new Response(JSON.stringify({
          razao_social: rawIdent,
          nome_fantasia: "",
          cnpj_formatado: "SEDE NO EXTERIOR",
          tipo_entidade: "FÁBRICA INTERNACIONAL",
          is_internacional: true,
          situacao_cadastral: "PLANTA HOMOLOGADA PELA ANVISA",
          data_inicio_atividade: "-",
          cnae_principal: "Produção Farmacêutica Internacional",
          cnae_descricao: "Processo produtivo farmacêutico homologado",
          capital_social: 0,
          telefone: null,
          email: "",
          website: null,
          website_busca: `https://www.google.com/search?q=${encodedQuery}`,
          endereco_completo: "Sede Industrial Cadastrada na ANVISA",
          municipio: "-",
          uf: "Exterior",
          cep: "-",
          total_socios: 0,
          socios: [],
          detentoras_brasil: []
        }), { headers: { 'Content-Type': 'application/json' } });
      }

      return new Response(JSON.stringify(found), { headers: { 'Content-Type': 'application/json' } });
    }

    // Static Medicamento Modal
    if (urlStr.includes('/api/medicamento/') || urlStr.includes('api/medicamento/')) {
      const catList = await getStaticCatalogo();
      const reg = urlStr.split('/medicamento/')[1] || '';
      const med = catList.find(m => (m.registro_13 || '').includes(reg)) || {};
      return new Response(JSON.stringify({
        medicamento: {
          produto_nome: med.produto || 'Medicamento Registrado',
          substancia: med.substancia || '-',
          numero_registro_13: med.registro_13 || reg,
          categoria_regulatoria: med.categoria || 'Sintético / ANVISA',
          forma_farmaceutica: med.forma || '-',
          embalagem_primaria: med.embalagem || '-',
          tarja: med.tarja || '-',
          pf_18: med.pf_18 || 0,
          url_consulta_anvisa: med.url_anvisa || ''
        },
        detentora: {
          razao_social: med.detentora || '-',
          cnpj_formatado: med.cnpj_detentora || '-'
        },
        fabricantes: [
          {
            razao_social_fabricante: med.fabrica || 'Fabricante Homologado',
            tipo_fabricante: med.tipo || 'NACIONAL',
            pais_fabricante: med.pais || 'BRASIL',
            uf_fabricante: med.uf || '-'
          }
        ]
      }), { headers: { 'Content-Type': 'application/json' } });
    }
  }

  // Fallback to real fetch (for local server mode)
  try {
    return await originalFetch(url, options);
  } catch (err) {
    if (!isStaticMode) {
      console.warn('Falha no servidor local Flask, ativando fallback estático...');
      isStaticMode = true;
      return window.fetch(url, options);
    }
    throw err;
  }
};

/* ==========================================================================
   PHARMA DATA BR — MASTER DASHBOARD CONTROLLER (VANILLA JS + CHART.JS + VIS.JS)
   ========================================================================== */

let charts = {};
let networkInstance = null;

// Global State for Tab 2 (Medicamentos Explorer)
let currentPage = 1;
let currentFilters = {
  q: '',
  pais: '',
  tipo: '',
  tarja: '',
  sortBy: 'produto',
  sortOrder: 'asc'
};

// Global State for Tab 3 (Empresas)
let empresasFilters = {
  q: '',
  sortBy: 'total_produtos_cmed',
  sortOrder: 'desc'
};

// Global State for Tab 1 (Overview & Drilldown)
let includeUnmapped = false;
let drilldownState = {
  filterType: '',
  filterVal: '',
  entityType: 'medicamentos',
  q: '',
  sortBy: 'produto',
  sortOrder: 'asc',
  page: 1,
  limit: 20,
  totalPages: 1
};

// Formatting helpers
const formatBRL = (val) => {
  if (val === null || val === undefined || isNaN(val)) return 'R$ 0,00';
  return new Intl.NumberFormat('pt-BR', { style: 'currency', currency: 'BRL' }).format(val);
};

const formatNumber = (val) => {
  if (val === null || val === undefined || isNaN(val)) return '0';
  return new Intl.NumberFormat('pt-BR').format(val);
};

const setElemText = (id, text) => {
  const el = document.getElementById(id);
  if (el) el.innerText = text;
};

// DOM Content Loaded
window.startDashboardApp = function() {
  initNavigation();
  loadStats();
  loadCharts();
  initGoogleChartsAndSankey();
  initNetworkGraph();
  loadDrilldown();
  loadMedicamentos();
  loadEmpresas();
  loadEspeciais();
  initSearchAndFilters();
  initSqlStudio();
  initOverviewToolbar();
  initNetworkToggles();
};

// Navigation / Tabs
function initNavigation() {
  const navBtns = document.querySelectorAll('.nav-item button');
  navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      
      document.querySelectorAll('.nav-item').forEach(li => li.classList.remove('active'));
      btn.parentElement.classList.add('active');

      document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
      const activeEl = document.getElementById(targetTab);
      if (activeEl) activeEl.classList.add('active');

      const titles = {
        'tab-overview': { title: 'Panorama Executivo', sub: 'Visão consolidada da indústria farmacêutica brasileira, preços e cadeias produtivas' },
        'tab-medicamentos': { title: 'Explorador de Medicamentos', sub: 'Catálogo de medicamentos cruzando CMED, ANVISA oficial e fábricas reais' },
        'tab-empresas': { title: 'Laboratórios & Quadro Societário', sub: '260 laboratórios farmacêuticos com dados cadastrais, donos e capital social' },
        'tab-especiais': { title: 'Medicamentos Especiais & Fitoterápicos', sub: 'Fitoterápicos, Dinamizados, Biológicos, Específicos e Radiofármacos regulados pela ANVISA' },
        'tab-sql': { title: 'SQL Studio Interativo', sub: 'Execute consultas analíticas customizadas diretamente no banco SQLite' },
        'tab-schema': { title: 'Arquitetura do Banco Mestre', sub: 'Estrutura relacional unificada e documentação dos modelos de dados' }
      };

      if (titles[targetTab]) {
        setElemText('header-title', titles[targetTab].title);
        setElemText('header-subtitle', titles[targetTab].sub);
      }
    });
  });
}

// 1. Load Stats KPIs
async function loadStats() {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();

    setElemText('kpi-total-cmed', formatNumber(data.total_cmed_apresentacoes));
    setElemText('kpi-total-empresas', formatNumber(data.total_empresas_detentoras));
    setElemText('kpi-total-fabricantes', formatNumber(data.total_fabricantes_unicos));
    setElemText('kpi-total-paises', `${data.total_paises_fabricacao} Países Mapeados`);
    setElemText('kpi-capital-total', formatBRL(data.capital_social_acumulado));
    
    // Vínculos Importação & Terceirização
    const totalVinculos = data.vinculos_importados + data.vinculos_nacionais;
    const percImport = totalVinculos > 0 ? ((data.vinculos_importados / totalVinculos) * 100).toFixed(1) : 0;
    setElemText('kpi-perc-import', `${percImport}% dos Vínculos`);

    // Cobertura Regulatória Direta
    setElemText('kpi-cobertura-txt', `${formatNumber(data.total_mapeados_cmed)} / ${formatNumber(data.total_cmed_apresentacoes)}`);

    // KPIs Especiais
    if (data.total_fitoterapicos) setElemText('kpi-esp-fito', formatNumber(data.total_fitoterapicos));
    if (data.total_biologicos) setElemText('kpi-esp-biol', formatNumber(data.total_biologicos));
    if (data.total_dinamizados) setElemText('kpi-esp-dinam', formatNumber(data.total_dinamizados));

  } catch (err) {
    console.error('Erro ao carregar KPIs:', err);
  }
}

// Overview Toolbar: Toggle Unmapped
function initOverviewToolbar() {
  const toggle = document.getElementById('toggle-unmapped');
  if (toggle) {
    toggle.addEventListener('change', (e) => {
      includeUnmapped = e.target.checked;
      loadCharts();
    });
  }

  document.querySelectorAll('.chart-click-hint').forEach(el => {
    el.title = 'Clique para ver o detalhamento dinâmico na tabela abaixo';
    el.addEventListener('click', (e) => {
      e.stopPropagation();
      scrollToDrilldown();
    });
  });
}

// 2. Load Charts
async function loadCharts() {
  try {
    const res = await fetch(`/api/charts?include_unmapped=${includeUnmapped}`);
    const data = await res.json();

    // Palette Colors
    const palette = ['#10b981', '#f59e0b', '#6366f1', '#ec4899', '#06b6d4', '#8b5cf6'];
    const unmappedColor = '#94a3b8'; // Slate grey for unmapped

    // -------------------------------------------------------------
    // Chart 1: Modelos de Produção (Donut) - Multi-métrica
    // -------------------------------------------------------------
    if (charts.modelos) charts.modelos.destroy();
    const ctxModelos = document.getElementById('chartModelos').getContext('2d');
    const modeloColors = data.modelos.map(m => m.is_unmapped ? unmappedColor : (
      m.modelo.includes('Própria') ? '#10b981' : (m.modelo.includes('Terceirização') ? '#f59e0b' : '#6366f1')
    ));
    const totalModelosSum = data.modelos.reduce((acc, cur) => acc + cur.total, 0) || 1;

    charts.modelos = new Chart(ctxModelos, {
      type: 'doughnut',
      data: {
        labels: data.modelos.map(m => m.modelo),
        datasets: [{
          data: data.modelos.map(m => m.total),
          backgroundColor: modeloColors,
          borderWidth: 2,
          borderColor: '#ffffff',
          hoverOffset: 8
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom', labels: { boxWidth: 12, font: { family: 'Inter', size: 11 } } },
          tooltip: {
            callbacks: {
              label: (ctx) => {
                const item = data.modelos[ctx.dataIndex];
                const pct = ((item.total / totalModelosSum) * 100).toFixed(1);
                return [
                  ` ${item.modelo}:`,
                  ` • Medicamentos: ${formatNumber(item.total)} (${pct}%)`,
                  ` • Empresas Detentoras: ${formatNumber(item.total_empresas || 0)}`,
                  ` • Plantas Fabris Mapeadas: ${formatNumber(item.total_fabricas || 0)}`
                ];
              }
            }
          }
        },
        onClick: (evt, elements) => {
          if (elements.length > 0) {
            const index = elements[0].index;
            const item = data.modelos[index];
            triggerDrilldown('modelo', item.raw_key || item.modelo);
          }
        }
      }
    });

    // -------------------------------------------------------------
    // Chart 2: Top Países de Fabricação (Bar) - Multi-métrica
    // -------------------------------------------------------------
    if (charts.paises) charts.paises.destroy();
    const ctxPaises = document.getElementById('chartPaises').getContext('2d');
    const paisesColors = data.paises.map(p => p.is_unmapped ? unmappedColor : '#4f46e5');

    charts.paises = new Chart(ctxPaises, {
      type: 'bar',
      data: {
        labels: data.paises.map(p => p.pais),
        datasets: [{
          label: 'Apresentações Fabris',
          data: data.paises.map(p => p.total),
          backgroundColor: paisesColors,
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (ctx) => {
                const p = data.paises[ctx.dataIndex];
                return [
                  ` ${p.pais}:`,
                  ` • Medicamentos Produzidos: ${formatNumber(p.total)}`,
                  ` • Plantas Fabris no País: ${formatNumber(p.total_fabricas || 0)}`,
                  ` • Empresas Contratantes: ${formatNumber(p.total_empresas || 0)}`
                ];
              }
            }
          }
        },
        scales: {
          x: { grid: { display: false }, ticks: { font: { size: 10, family: 'Inter' } } },
          y: { grid: { color: '#f1f5f9' }, ticks: { font: { size: 11, family: 'Inter' } } }
        },
        onClick: (evt, elements) => {
          if (elements.length > 0) {
            const index = elements[0].index;
            const pais = data.paises[index].pais;
            triggerDrilldown('pais', pais);
          }
        }
      }
    });

    // -------------------------------------------------------------
    // Chart 3: Polos Fabris Nacionais por UF (Bar) - Multi-métrica
    // -------------------------------------------------------------
    if (charts.topUfs) charts.topUfs.destroy();
    const ctxUfs = document.getElementById('chartUfNacional').getContext('2d');
    charts.topUfs = new Chart(ctxUfs, {
      type: 'bar',
      data: {
        labels: data.top_ufs.map(u => `Estado: ${u.uf}`),
        datasets: [{
          label: 'Apresentações Fabris',
          data: data.top_ufs.map(u => u.total),
          backgroundColor: '#059669',
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (ctx) => {
                const u = data.top_ufs[ctx.dataIndex];
                return [
                  ` Estado: ${u.uf}`,
                  ` • Medicamentos Fabricados: ${formatNumber(u.total)}`,
                  ` • Plantas Fabris no Estado: ${formatNumber(u.total_fabricas || 0)}`,
                  ` • Empresas Atuantes: ${formatNumber(u.total_empresas || 0)}`
                ];
              }
            }
          }
        },
        scales: {
          x: { grid: { display: false }, ticks: { font: { size: 11, family: 'Inter' } } },
          y: { grid: { color: '#f1f5f9' } }
        },
        onClick: (evt, elements) => {
          if (elements.length > 0) {
            const index = elements[0].index;
            const uf = data.top_ufs[index].uf;
            triggerDrilldown('uf', uf);
          }
        }
      }
    });

    // -------------------------------------------------------------
    // Chart 4: Preço Médio Teto (PF 18%) por Origem (Bar) - Multi-métrica
    // -------------------------------------------------------------
    if (charts.precosOrigem) charts.precosOrigem.destroy();
    const ctxPreco = document.getElementById('chartPrecoOrigem').getContext('2d');
    charts.precosOrigem = new Chart(ctxPreco, {
      type: 'bar',
      data: {
        labels: data.precos_origem.map(p => p.origem),
        datasets: [{
          label: 'Preço Médio Teto (PF 18%)',
          data: data.precos_origem.map(p => p.preco_medio),
          backgroundColor: ['#6366f1', '#10b981', '#94a3b8'],
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (ctx) => {
                const p = data.precos_origem[ctx.dataIndex];
                return [
                  ` ${p.origem}:`,
                  ` • Preço Médio Teto: ${formatBRL(p.preco_medio)}`,
                  ` • Apresentações: ${formatNumber(p.total)}`,
                  ` • Empresas Envolvidas: ${formatNumber(p.total_empresas || 0)}`
                ];
              }
            }
          }
        },
        scales: {
          x: { grid: { display: false } },
          y: { 
            grid: { color: '#f1f5f9' },
            ticks: { callback: (val) => `R$ ${formatNumber(val)}` }
          }
        },
        onClick: (evt, elements) => {
          if (elements.length > 0) {
            const index = elements[0].index;
            const origem = data.precos_origem[index].origem;
            if (origem.includes('Importado')) triggerDrilldown('modelo', 'IMPORTACAO');
            else if (origem.includes('Nacional')) triggerDrilldown('modelo', 'TERCEIRIZACAO NACIONAL (CMO)');
            else triggerDrilldown('modelo', 'NAO MAPEADO');
          }
        }
      }
    });

    // -------------------------------------------------------------
    // Chart 5: Formas Farmacêuticas (Horizontal Bar) - Multi-métrica
    // -------------------------------------------------------------
    if (charts.formas) charts.formas.destroy();
    const ctxFormas = document.getElementById('chartFormas').getContext('2d');
    charts.formas = new Chart(ctxFormas, {
      type: 'bar',
      data: {
        labels: data.formas.map(f => f.forma),
        datasets: [{
          label: 'Apresentações',
          data: data.formas.map(f => f.total),
          backgroundColor: '#8b5cf6',
          borderRadius: 6
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (ctx) => {
                const f = data.formas[ctx.dataIndex];
                return [
                  ` Forma: ${f.forma}`,
                  ` • Apresentações Registradas: ${formatNumber(f.total)}`,
                  ` • Empresas Ofertantes: ${formatNumber(f.total_empresas || 0)}`,
                  ` • Plantas Fabris Aptas: ${formatNumber(f.total_fabricas || 0)}`
                ];
              }
            }
          }
        },
        scales: {
          x: { grid: { color: '#f1f5f9' } },
          y: { grid: { display: false } }
        },
        onClick: (evt, elements) => {
          if (elements.length > 0) {
            const index = elements[0].index;
            const forma = data.formas[index].forma;
            triggerDrilldown('forma', forma);
          }
        }
      }
    });

    // -------------------------------------------------------------
    // Chart 6: Embalagens Primárias Oficiais - Multi-métrica
    // -------------------------------------------------------------
    if (charts.embalagens) charts.embalagens.destroy();
    const ctxEmbalagens = document.getElementById('chartEmbalagens').getContext('2d');
    charts.embalagens = new Chart(ctxEmbalagens, {
      type: 'bar',
      data: {
        labels: data.embalagens.map(e => e.tipo),
        datasets: [{
          label: 'Apresentações',
          data: data.embalagens.map(e => e.total),
          backgroundColor: '#0284c7',
          borderRadius: 6
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (ctx) => {
                const e = data.embalagens[ctx.dataIndex];
                return [
                  ` Embalagem: ${e.tipo}`,
                  ` • Apresentações: ${formatNumber(e.total)}`,
                  ` • Empresas Ofertantes: ${formatNumber(e.total_empresas || 0)}`,
                  ` • Fábricas Produtoras: ${formatNumber(e.total_fabricas || 0)}`
                ];
              }
            }
          }
        },
        scales: {
          x: { grid: { color: '#f1f5f9' } },
          y: { grid: { display: false } }
        },
        onClick: (evt, elements) => {
          if (elements.length > 0) {
            const index = elements[0].index;
            const tipo = data.embalagens[index].tipo;
            triggerDrilldown('embalagem', tipo);
          }
        }
      }
    });

    // -------------------------------------------------------------
    // Chart 7: Top Classes Terapêuticas & Farmacológicas (NOVO)
    // -------------------------------------------------------------
    if (charts.classes) charts.classes.destroy();
    const elemClasses = document.getElementById('chartClasses');
    if (elemClasses && data.classes_terapeuticas) {
      const ctxClasses = elemClasses.getContext('2d');
      charts.classes = new Chart(ctxClasses, {
        type: 'bar',
        data: {
          labels: data.classes_terapeuticas.map(c => c.classe),
          datasets: [{
            label: 'Apresentações Registradas',
            data: data.classes_terapeuticas.map(c => c.total),
            backgroundColor: '#3b82f6',
            borderRadius: 6
          }]
        },
        options: {
          indexAxis: 'y',
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              callbacks: {
                label: (ctx) => {
                  const item = data.classes_terapeuticas[ctx.dataIndex];
                  return [
                    ` Classe: ${item.classe}`,
                    ` • Apresentações Registradas: ${formatNumber(item.total)}`,
                    ` • Laboratórios Concorrentes: ${formatNumber(item.total_empresas || 0)}`,
                    ` • Preço Médio Teto (PF 18%): ${formatBRL(item.preco_medio)}`
                  ];
                }
              }
            }
          },
          scales: {
            x: { grid: { color: '#f1f5f9' }, ticks: { font: { size: 10, family: 'Inter' } } },
            y: { grid: { display: false }, ticks: { font: { size: 10, family: 'Inter' } } }
          },
          onClick: (evt, elements) => {
            if (elements.length > 0) {
              const index = elements[0].index;
              const item = data.classes_terapeuticas[index];
              triggerDrilldown('classe', item.classe);
            }
          }
        }
      });
    }

    // -------------------------------------------------------------
    // Chart 8: Classificação Regulatória por Tarja Sanitária (NOVO)
    // -------------------------------------------------------------
    if (charts.tarjas) charts.tarjas.destroy();
    const elemTarjas = document.getElementById('chartTarjas');
    if (elemTarjas && data.tarjas) {
      const ctxTarjas = elemTarjas.getContext('2d');
      const tarjaColors = data.tarjas.map(t => {
        const name = (t.tarja || '').toUpperCase();
        if (name.includes('PRETA')) return '#0f172a'; // Preto regulatório
        if (name.includes('RETEN') || name.includes('RESTRI')) return '#dc2626'; // Vermelho escuro com retenção de receita
        if (name.includes('VERMELHA')) return '#ef4444'; // Vermelho clássico de prescrição
        if (name.includes('ISENT') || name.includes('MIP') || name.includes('SEM TARJA') || name.includes('(*)')) return '#10b981'; // Verde (Isento de Prescrição / MIP)
        return '#64748b'; // Cinza neutro
      });

      charts.tarjas = new Chart(ctxTarjas, {
        type: 'doughnut',
        data: {
          labels: data.tarjas.map(t => t.tarja),
          datasets: [{
            data: data.tarjas.map(t => t.total),
            backgroundColor: tarjaColors,
            borderWidth: 2,
            borderColor: '#ffffff',
            hoverOffset: 8
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { position: 'bottom', labels: { boxWidth: 12, font: { family: 'Inter', size: 11 } } },
            tooltip: {
              callbacks: {
                label: (ctx) => {
                  const item = data.tarjas[ctx.dataIndex];
                  return [
                    ` Tarja: ${item.tarja}`,
                    ` • Medicamentos Registrados: ${formatNumber(item.total)}`,
                    ` • Laboratórios Registrantes: ${formatNumber(item.total_empresas || 0)}`,
                    ` • Preço Médio Teto (PF 18%): ${formatBRL(item.preco_medio)}`
                  ];
                }
              }
            }
          },
          onClick: (evt, elements) => {
            if (elements.length > 0) {
              const index = elements[0].index;
              const item = data.tarjas[index];
              triggerDrilldown('tarja', item.tarja);
            }
          }
        }
      });
    }

    // -------------------------------------------------------------
    // Chart 9: Moléculas / Princípios Ativos Mais Concorridos (NOVO)
    // -------------------------------------------------------------
    if (charts.moleculas) charts.moleculas.destroy();
    const elemMoleculas = document.getElementById('chartMoleculas');
    if (elemMoleculas && data.moleculas) {
      const ctxMoleculas = elemMoleculas.getContext('2d');
      charts.moleculas = new Chart(ctxMoleculas, {
        type: 'bar',
        data: {
          labels: data.moleculas.map(m => m.molecula || m.substancia),
          datasets: [
            {
              label: 'Marcas / Laboratórios Detentores',
              data: data.moleculas.map(m => m.total_empresas),
              backgroundColor: '#2563eb',
              borderRadius: 4
            },
            {
              label: 'Plantas Fabris Produtoras',
              data: data.moleculas.map(m => m.total_fabricas),
              backgroundColor: '#10b981',
              borderRadius: 4
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { position: 'top', labels: { boxWidth: 14, font: { family: 'Inter', size: 12, weight: '600' } } },
            tooltip: {
              callbacks: {
                afterBody: (items) => {
                  if (!items.length) return '';
                  const item = data.moleculas[items[0].dataIndex];
                  return `Total de Apresentações Comerciais: ${formatNumber(item.total_medicamentos || item.total)}`;
                }
              }
            }
          },
          scales: {
            x: { grid: { display: false }, ticks: { font: { size: 11, family: 'Inter' } } },
            y: { grid: { color: '#f1f5f9' }, ticks: { font: { size: 11, family: 'Inter' } } }
          },
          onClick: (evt, elements) => {
            if (elements.length > 0) {
              const index = elements[0].index;
              const item = data.moleculas[index];
              triggerDrilldown('substancia', item.molecula || item.substancia);
            }
          }
        }
      });
    }

    // Populate country filter dropdown in Tab 2
    const selectPais = document.getElementById('filter-pais');
    if (selectPais && selectPais.options.length <= 1) {
      data.paises.filter(p => !p.is_unmapped).forEach(p => {
        const opt = document.createElement('option');
        opt.value = p.pais;
        opt.innerText = p.pais;
        selectPais.appendChild(opt);
      });
    }

  } catch (err) {
    console.error('Erro ao renderizar gráficos:', err);
  }
}

// -------------------------------------------------------------
// Interactive Vis.Network Graph (Empresas ↔ Fábricas)
// -------------------------------------------------------------
let networkFilters = {
  all_empresas: false,
  all_fabricas: false,
  all_connections: false
};

async function initNetworkGraph() {
  const container = document.getElementById('network-container');
  if (!container || typeof vis === 'undefined') return;

  const tEmp = document.getElementById('toggle-net-empresas');
  const tFab = document.getElementById('toggle-net-fabricas');
  const tAll = document.getElementById('toggle-net-all-links');

  if (tEmp) networkFilters.all_empresas = tEmp.checked;
  if (tFab) networkFilters.all_fabricas = tFab.checked;
  if (tAll) networkFilters.all_connections = tAll.checked;

  try {
    const params = new URLSearchParams({
      all_empresas: networkFilters.all_empresas,
      all_fabricas: networkFilters.all_fabricas,
      all_connections: networkFilters.all_connections
    });

    const res = await fetch(`/api/network?${params}`);
    const data = await res.json();

    const nodes = new vis.DataSet(data.nodes);
    const edges = new vis.DataSet(data.edges);

    const networkData = { nodes, edges };
    const options = {
      physics: {
        stabilization: { iterations: 100 },
        barnesHut: {
          gravitationalConstant: -4000,
          centralGravity: 0.25,
          springConstant: 0.04,
          springLength: 100,
          damping: 0.09
        }
      },
      interaction: {
        hover: true,
        zoomView: true,
        dragView: true,
        tooltipDelay: 150
      },
      nodes: {
        borderWidth: 2,
        shadow: true
      },
      groups: {
        empresa: { color: { background: '#2563eb', border: '#1d4ed8' }, shape: 'dot' },
        fabrica_propria: { color: { background: '#10b981', border: '#059669' }, shape: 'box' },
        fabrica_terceirizada: { color: { background: '#f59e0b', border: '#d97706' }, shape: 'diamond' },
        fabrica_internacional: { color: { background: '#8b5cf6', border: '#7c3aed' }, shape: 'triangle' },
        singular: { color: { background: '#ef4444', border: '#dc2626' }, shape: 'dot' }
      },
      edges: {
        smooth: { type: 'continuous' },
        shadow: false
      }
    };

    if (networkInstance) {
      networkInstance.destroy();
      networkInstance = null;
    }

    networkInstance = new vis.Network(container, networkData, options);

    // On node click -> trigger dynamic drilldown below
    networkInstance.on('click', (params) => {
      if (params.nodes.length > 0) {
        const nodeId = params.nodes[0];
        const node = nodes.get(nodeId);
        if (node) {
          if (node.group && node.group.includes('empresa')) {
            triggerDrilldown('empresa', node.full_name || node.label);
          } else {
            triggerDrilldown('fabrica', node.full_name || node.label);
          }
        }
      }
    });

  } catch (err) {
    console.error('Erro ao inicializar Grafo de Conexões:', err);
  }
}

function initNetworkToggles() {
  ['toggle-net-empresas', 'toggle-net-fabricas', 'toggle-net-all-links'].forEach(id => {
    const el = document.getElementById(id);
    if (el && !el.dataset.bound) {
      el.dataset.bound = 'true';
      el.addEventListener('change', () => initNetworkGraph());
    }
  });
}

function resetNetworkView() {
  if (networkInstance) {
    networkInstance.fit({ animation: { duration: 600, easingFunction: 'easeInOutQuad' } });
  }
}

// -------------------------------------------------------------
// Interactive Sankey Diagram (Laboratórios Detentores -> Fábricas)
// -------------------------------------------------------------
let sankeyChart = null;
let sankeyData = null;
let sankeyLimit = 30;
let sankeyColorMode = 'gradient';
let sankeyOpacity = 0.75;

function initGoogleChartsAndSankey() {
  if (typeof google !== 'undefined' && google.charts) {
    google.charts.load('current', { packages: ['sankey'] });
    google.charts.setOnLoadCallback(() => {
      initSankeyGraph();
    });
  } else {
    window.addEventListener('load', () => {
      if (typeof google !== 'undefined' && google.charts) {
        google.charts.load('current', { packages: ['sankey'] });
        google.charts.setOnLoadCallback(() => {
          initSankeyGraph();
        });
      }
    });
  }
}

async function initSankeyGraph(limit = sankeyLimit) {
  sankeyLimit = limit;
  const container = document.getElementById('sankey-container');
  if (!container) return;

  try {
    const res = await fetch(`/api/sankey?limit=${limit}`);
    const data = await res.json();
    sankeyData = data;
    renderSankeyChart();
  } catch (err) {
    console.error('Erro ao carregar dados do Sankey:', err);
    container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#64748b;font-size:13px;">Falha ao carregar fluxos industriais. Verifique a conexão com o servidor.</div>';
  }
}

function renderSankeyChart() {
  const container = document.getElementById('sankey-container');
  if (!container || !sankeyData || !sankeyData.rows || !sankeyData.rows.length) return;
  if (typeof google === 'undefined' || !google.visualization || !google.visualization.Sankey) return;

  const dataTable = new google.visualization.DataTable();
  dataTable.addColumn('string', 'Laboratório Detentor');
  dataTable.addColumn('string', 'Planta Fabril Real');
  dataTable.addColumn('number', 'Medicamentos Mapeados');

  dataTable.addRows(sankeyData.rows);

  // Paleta executiva vibrante e com alto contraste
  const vibrantPalette = [
    '#1d4ed8', '#059669', '#7c3aed', '#d97706', '#0891b2',
    '#dc2626', '#4f46e5', '#0d9488', '#ea580c', '#0284c7',
    '#16a34a', '#9333ea', '#be123c', '#0f766e', '#b45309'
  ];

  const options = {
    height: 660,
    sankey: {
      node: {
        label: {
          fontName: 'Inter',
          fontSize: 11,
          color: '#0f172a',
          bold: true
        },
        labelPadding: 12,
        nodePadding: 24,
        width: 20,
        colors: vibrantPalette
      },
      link: {
        colorMode: sankeyColorMode, // 'gradient' or 'source'
        colors: vibrantPalette,
        color: {
          fillOpacity: sankeyOpacity, // 0.75 ou 0.92 (traços espessos, ricos e perfeitamente visíveis)
          stroke: '#475569',          // borda nítida de delimitação
          strokeWidth: 0.8
        }
      }
    }
  };

  sankeyChart = new google.visualization.Sankey(container);

  google.visualization.events.addListener(sankeyChart, 'select', () => {
    const sel = sankeyChart.getSelection();
    if (!sel || !sel.length) return;
    const item = sel[0];
    if (item.name) {
      const rawName = item.name;
      if (rawName.includes(' [Fab]')) {
        const fab = rawName.replace(' [Fab]', '').trim();
        triggerDrilldown('fabrica', fab);
      } else {
        triggerDrilldown('empresa', rawName.trim());
      }
    } else if (item.row !== null && item.row !== undefined) {
      const emp = dataTable.getValue(item.row, 0);
      triggerDrilldown('empresa', emp);
    }
  });

  sankeyChart.draw(dataTable, options);
}

function setSankeyLimit(limit) {
  sankeyLimit = limit;
  document.querySelectorAll('#sankey-controls .btn-sankey-density').forEach(btn => btn.classList.remove('active'));
  const btn = document.getElementById(`btn-sankey-top${limit}`);
  if (btn) btn.classList.add('active');
  initSankeyGraph(limit);
}

function setSankeyColorMode(mode) {
  sankeyColorMode = mode;
  document.querySelectorAll('#sankey-controls .btn-sankey-colormode').forEach(btn => btn.classList.remove('active'));
  const btn = document.getElementById(`btn-sankey-mode-${mode}`);
  if (btn) btn.classList.add('active');
  renderSankeyChart();
}

function setSankeyOpacity(op) {
  sankeyOpacity = op;
  document.querySelectorAll('#sankey-controls .btn-sankey-opacity').forEach(btn => btn.classList.remove('active'));
  const opKey = op >= 0.85 ? 'max' : 'high';
  const btn = document.getElementById(`btn-sankey-op-${opKey}`);
  if (btn) btn.classList.add('active');
  renderSankeyChart();
}

window.setSankeyLimit = setSankeyLimit;
window.setSankeyColorMode = setSankeyColorMode;
window.setSankeyOpacity = setSankeyOpacity;
window.renderSankeyChart = renderSankeyChart;

function switchRelView(viewType) {
  const sankeyWrapper = document.getElementById('sankey-wrapper');
  const networkWrapper = document.getElementById('network-wrapper');
  const sankeyControls = document.getElementById('sankey-controls');
  const networkControls = document.getElementById('network-controls');
  const btnSankey = document.getElementById('btn-view-sankey');
  const btnNetwork = document.getElementById('btn-view-network');
  const relTitle = document.getElementById('rel-title');

  if (viewType === 'sankey') {
    if (btnSankey) btnSankey.classList.add('active');
    if (btnNetwork) btnNetwork.classList.remove('active');
    if (sankeyWrapper) sankeyWrapper.style.display = 'block';
    if (networkWrapper) networkWrapper.style.display = 'none';
    if (sankeyControls) sankeyControls.style.display = 'flex';
    if (networkControls) networkControls.style.display = 'none';
    if (relTitle) relTitle.innerText = 'Fluxo Industrial: Laboratórios Detentores  Plantas Fabris (Sankey)';
    setTimeout(() => {
      renderSankeyChart();
    }, 50);
  } else {
    if (btnNetwork) btnNetwork.classList.add('active');
    if (btnSankey) btnSankey.classList.remove('active');
    if (sankeyWrapper) sankeyWrapper.style.display = 'none';
    if (networkWrapper) networkWrapper.style.display = 'block';
    if (sankeyControls) sankeyControls.style.display = 'none';
    if (networkControls) networkControls.style.display = 'flex';
    if (relTitle) relTitle.innerText = 'Mapa Interativo de Conexões: Laboratórios Detentores e Plantas Fabris (Rede)';
    if (!networkInstance) {
      initNetworkGraph();
    } else {
      setTimeout(() => {
        networkInstance.fit();
      }, 50);
    }
  }
}

window.switchRelView = switchRelView;

window.addEventListener('resize', () => {
  const sankeyWrapper = document.getElementById('sankey-wrapper');
  if (sankeyWrapper && sankeyWrapper.style.display !== 'none') {
    renderSankeyChart();
  }
});

// -------------------------------------------------------------
// Dynamic Drilldown Engine (Underneath Charts in Overview)
// -------------------------------------------------------------
function triggerDrilldown(filterType, filterVal) {
  drilldownState.filterType = filterType;
  drilldownState.filterVal = filterVal;
  drilldownState.page = 1;
  drilldownState.q = '';

  const searchInput = document.getElementById('drilldown-search-input');
  if (searchInput) searchInput.value = '';

  const badgeText = `Filtro Ativo: ${filterType.toUpperCase()} = ${filterVal}`;
  setElemText('drilldown-badge', badgeText);
  setElemText('drilldown-heading', `Detalhamento: ${filterVal}`);
  setElemText('drilldown-subheading', `Mostrando entidades vinculadas ao critério selecionado no gráfico. Alterne entre Remédios, Fábricas ou Detentoras.`);

  loadDrilldown();

  // Smooth scroll to drilldown card
  const drillSection = document.getElementById('drilldown-section');
  if (drillSection) {
    drillSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

function resetDrilldown() {
  drilldownState.filterType = '';
  drilldownState.filterVal = '';
  drilldownState.page = 1;
  drilldownState.q = '';

  const searchInput = document.getElementById('drilldown-search-input');
  if (searchInput) searchInput.value = '';

  setElemText('drilldown-badge', 'Detalhamento Dinâmico');
  setElemText('drilldown-heading', 'Exibindo todos os dados do catálogo');
  setElemText('drilldown-subheading', 'Clique em qualquer barra, fatia ou nó dos gráficos acima para filtrar os dados instantaneamente.');

  loadDrilldown();
}

function switchDrilldownEntity(entityType) {
  drilldownState.entityType = entityType;
  drilldownState.page = 1;

  document.querySelectorAll('#drilldown-section .drill-tab').forEach(b => {
    b.classList.toggle('active', b.getAttribute('data-type') === entityType);
  });

  loadDrilldown();
}

function scrollToDrilldown() {
  const el = document.getElementById('drilldown-section');
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}
window.scrollToDrilldown = scrollToDrilldown;

function sortDrilldown(col) {
  if (drilldownState.sortBy === col) {
    drilldownState.sortOrder = drilldownState.sortOrder === 'asc' ? 'desc' : 'asc';
  } else {
    drilldownState.sortBy = col;
    drilldownState.sortOrder = 'asc';
  }
  drilldownState.page = 1;
  loadDrilldown();
}

async function loadDrilldown() {
  const thead = document.getElementById('drilldown-thead');
  const tbody = document.getElementById('drilldown-tbody');
  tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 30px; color: var(--text-muted);">Carregando dados da seleção...</td></tr>`;

  try {
    const params = new URLSearchParams({
      filter_type: drilldownState.filterType,
      filter_val: drilldownState.filterVal,
      entity_type: drilldownState.entityType,
      q: drilldownState.q,
      sort_by: drilldownState.sortBy,
      sort_order: drilldownState.sortOrder,
      page: drilldownState.page,
      limit: drilldownState.limit
    });

    const res = await fetch(`/api/drilldown?${params}`);
    const data = await res.json();

    // Update entity counts
    if (data.counts) {
      setElemText('drill-count-meds', formatNumber(data.counts.medicamentos));
      setElemText('drill-count-fabs', formatNumber(data.counts.fabricas));
      setElemText('drill-count-emps', formatNumber(data.counts.empresas));
    }

    drilldownState.totalPages = data.pages || 1;
    const start = (data.page - 1) * data.limit + 1;
    const end = Math.min(data.page * data.limit, data.total);
    setElemText('drilldown-page-info', `Página ${data.page} de ${data.pages} (${formatNumber(data.total)} itens)`);
    setElemText('drilldown-summary-text', `Mostrando ${formatNumber(start)} - ${formatNumber(end)} de ${formatNumber(data.total)} registros`);

    // Setup headers and rows depending on entity
    if (drilldownState.entityType === 'fabricas') {
      renderDrilldownFabricas(thead, tbody, data.items);
    } else if (drilldownState.entityType === 'empresas') {
      renderDrilldownEmpresas(thead, tbody, data.items);
    } else {
      renderDrilldownMedicamentos(thead, tbody, data.items);
    }

    const btnPrev = document.getElementById('btn-drill-prev');
    const btnNext = document.getElementById('btn-drill-next');
    if (btnPrev) btnPrev.disabled = data.page <= 1;
    if (btnNext) btnNext.disabled = data.page >= data.pages;

  } catch (err) {
    console.error('Erro ao carregar drilldown:', err);
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--danger); padding: 30px;">Erro ao carregar dados do drilldown.</td></tr>`;
  }
}

function renderDrilldownMedicamentos(thead, tbody, items) {
  const getSortIcon = (col) => {
    if (drilldownState.sortBy !== col) return '↕';
    return drilldownState.sortOrder === 'asc' ? '▲' : '▼';
  };

  thead.innerHTML = `
    <tr>
      <th class="sortable-th" onclick="sortDrilldown('produto')">Medicamento & Princípio <span class="sort-icon">${getSortIcon('produto')}</span></th>
      <th class="sortable-th" onclick="sortDrilldown('detentora')">Detentora da Marca <span class="sort-icon">${getSortIcon('detentora')}</span></th>
      <th class="sortable-th" onclick="sortDrilldown('fabrica')">Fábrica Real (ANVISA) <span class="sort-icon">${getSortIcon('fabrica')}</span></th>
      <th class="sortable-th" onclick="sortDrilldown('pais')">Origem <span class="sort-icon">${getSortIcon('pais')}</span></th>
      <th class="sortable-th" onclick="sortDrilldown('tarja')">Tarja <span class="sort-icon">${getSortIcon('tarja')}</span></th>
      <th class="sortable-th" onclick="sortDrilldown('pf_18')">Preço Teto PF 18% <span class="sort-icon">${getSortIcon('pf_18')}</span></th>
      <th>Ação</th>
    </tr>
  `;

  if (!items || items.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 40px; color: var(--text-muted);">Nenhum medicamento encontrado para os critérios selecionados.</td></tr>`;
    return;
  }

  tbody.innerHTML = '';
  items.forEach(m => {
    const tr = document.createElement('tr');
    tr.addEventListener('click', () => openMedicamentoModal(m.registro_13));

    let tipoBadge = `<span class="badge badge-success">Nacional</span>`;
    if (m.tipo === 'INTERNACIONAL') {
      tipoBadge = `<span class="badge badge-purple">${m.pais}</span>`;
    }

    let tarjaBadge = `<span class="badge badge-secondary">${m.tarja}</span>`;
    if (m.tarja && m.tarja.includes('Vermelha')) tarjaBadge = `<span class="badge badge-warning">Vermelha</span>`;
    else if (m.tarja && m.tarja.includes('Preta')) tarjaBadge = `<span class="badge" style="background:#1e293b; color:#fff;">Preta</span>`;

    tr.innerHTML = `
      <td>
        <div style="font-weight: 700; color: var(--primary); font-size: 13px;">${m.produto}</div>
        <div style="font-size: 11px; color: var(--text-muted);">${m.substancia || '-'}</div>
      </td>
      <td>
        <div style="font-weight: 500; font-size: 12px;">${m.detentora}</div>
      </td>
      <td>
        <div style="font-weight: 600; font-size: 12px; color: var(--text-main);">${m.fabrica}</div>
        <div style="font-size: 11px; color: var(--text-muted);">${m.uf !== '-' ? `UF: ${m.uf}` : ''}</div>
      </td>
      <td>${tipoBadge}</td>
      <td>${tarjaBadge}</td>
      <td style="font-weight: 700; color: var(--text-main); font-size: 13px;">${formatBRL(m.pf_18)}</td>
      <td>
        <div style="display: flex; gap: 6px; align-items: center;">
          <button class="btn-secondary btn-sm" onclick="event.stopPropagation(); openMedicamentoModal('${m.registro_13}')">
            Raio-X
          </button>
          <button class="btn-secondary btn-sm" style="color: var(--primary); font-weight: 600;" onclick="event.stopPropagation(); openSocietarioModal('${(m.detentora || m.fabrica).replace(/'/g, "\\'")}')">
            QSA
          </button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function renderDrilldownFabricas(thead, tbody, items) {
  const getSortIcon = (col) => {
    if (drilldownState.sortBy !== col) return '↕';
    return drilldownState.sortOrder === 'asc' ? '▲' : '▼';
  };

  thead.innerHTML = `
    <tr>
      <th class="sortable-th" onclick="sortDrilldown('fabrica_real')">Razão Social da Fábrica <span class="sort-icon">${getSortIcon('fabrica_real')}</span></th>
      <th class="sortable-th" onclick="sortDrilldown('tipo_fabricante')">Tipo <span class="sort-icon">${getSortIcon('tipo_fabricante')}</span></th>
      <th class="sortable-th" onclick="sortDrilldown('pais_fabrica')">País de Localização <span class="sort-icon">${getSortIcon('pais_fabrica')}</span></th>
      <th class="sortable-th" onclick="sortDrilldown('uf_fabrica')">UF / Cidade <span class="sort-icon">${getSortIcon('uf_fabrica')}</span></th>
      <th class="sortable-th" onclick="sortDrilldown('total_meds')">Remédios Produzidos <span class="sort-icon">${getSortIcon('total_meds')}</span></th>
      <th>Marcas Atendidas</th>
      <th>Ação</th>
    </tr>
  `;

  if (!items || items.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 40px; color: var(--text-muted);">Nenhuma fábrica encontrada para os critérios selecionados.</td></tr>`;
    return;
  }

  tbody.innerHTML = '';
  items.forEach(f => {
    const tr = document.createElement('tr');
    const badge = f.tipo === 'INTERNACIONAL'
      ? `<span class="badge badge-purple">Internacional</span>`
      : `<span class="badge badge-success">Nacional</span>`;

    tr.innerHTML = `
      <td>
        <div style="font-weight: 700; color: var(--text-main); font-size: 13px;">${f.fabrica}</div>
      </td>
      <td>${badge}</td>
      <td style="font-weight: 500;">${f.pais}</td>
      <td><span class="badge badge-info">${f.uf}</span> ${f.cidade}</td>
      <td style="font-weight: 700; color: var(--primary); text-align: center; font-size: 14px;">${formatNumber(f.total_meds)}</td>
      <td style="font-weight: 600; text-align: center;">${f.total_marcas} marcas</td>
      <td>
        <div style="display: flex; gap: 6px; align-items: center;">
          <button class="btn-secondary btn-sm" onclick="event.stopPropagation(); triggerDrilldown('fabrica', '${f.fabrica.replace(/'/g, "\\'")}')">
            Ver Remédios
          </button>
          <button class="btn-secondary btn-sm" style="color: var(--primary); font-weight: 600;" onclick="event.stopPropagation(); openSocietarioModal('${(f.cnpj || f.fabrica).replace(/'/g, "\\'")}')">
            QSA & Contato
          </button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function renderDrilldownEmpresas(thead, tbody, items) {
  const getSortIcon = (col) => {
    if (drilldownState.sortBy !== col) return '↕';
    return drilldownState.sortOrder === 'asc' ? '▲' : '▼';
  };

  thead.innerHTML = `
    <tr>
      <th class="sortable-th" onclick="sortDrilldown('detentora_marca')">Empresa Detentora <span class="sort-icon">${getSortIcon('detentora_marca')}</span></th>
      <th>CNPJ Formatado</th>
      <th class="sortable-th" onclick="sortDrilldown('uf_detentora')">UF Sede <span class="sort-icon">${getSortIcon('uf_detentora')}</span></th>
      <th class="sortable-th" onclick="sortDrilldown('total_meds')">Total de Medicamentos <span class="sort-icon">${getSortIcon('total_meds')}</span></th>
      <th>Capital Social</th>
      <th>Sócios & Administradores</th>
      <th>Ação</th>
    </tr>
  `;

  if (!items || items.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 40px; color: var(--text-muted);">Nenhuma empresa encontrada para os critérios selecionados.</td></tr>`;
    return;
  }

  tbody.innerHTML = '';
  items.forEach(e => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>
        <div style="font-weight: 700; color: var(--text-main); font-size: 13px;">${e.detentora}</div>
      </td>
      <td><code>${e.cnpj || '-'}</code></td>
      <td><span class="badge badge-info">${e.uf}</span></td>
      <td style="font-weight: 700; color: var(--primary); text-align: center; font-size: 14px;">${formatNumber(e.total_meds)}</td>
      <td style="font-weight: 600;">${formatBRL(e.capital_social)}</td>
      <td style="font-size: 11px; color: var(--text-muted); max-width: 250px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${e.socios || ''}">
        ${e.socios || 'Não informado'}
      </td>
      <td>
        <div style="display: flex; gap: 6px; align-items: center;">
          <button class="btn-secondary btn-sm" onclick="event.stopPropagation(); triggerDrilldown('empresa', '${e.detentora.replace(/'/g, "\\'")}')">
            Ver Remédios
          </button>
          <button class="btn-secondary btn-sm" style="color: var(--primary); font-weight: 600;" onclick="event.stopPropagation(); openSocietarioModal('${(e.cnpj || e.detentora).replace(/'/g, "\\'")}')">
            QSA & Contato
          </button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function changeDrillPage(delta) {
  const newPage = drilldownState.page + delta;
  if (newPage >= 1 && newPage <= drilldownState.totalPages) {
    drilldownState.page = newPage;
    loadDrilldown();
  }
}

// -------------------------------------------------------------
// TAB 2: EXPLORADOR DE MEDICAMENTOS (FULL TABLE)
// -------------------------------------------------------------
function sortMedicamentosTab(col) {
  if (currentFilters.sortBy === col) {
    currentFilters.sortOrder = currentFilters.sortOrder === 'asc' ? 'desc' : 'asc';
  } else {
    currentFilters.sortBy = col;
    currentFilters.sortOrder = 'asc';
  }

  // Update header arrow icons
  document.querySelectorAll('.sort-icon').forEach(i => i.innerText = '↕');
  const activeIcon = document.getElementById(`sort-med-${col}`);
  if (activeIcon) activeIcon.innerText = currentFilters.sortOrder === 'asc' ? '▲' : '▼';

  currentPage = 1;
  loadMedicamentos();
}

async function loadMedicamentos() {
  const tbody = document.getElementById('medicamentos-table-body');
  tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 40px; color: var(--text-muted);">Carregando dados oficiais do banco relacional...</td></tr>`;

  try {
    const params = new URLSearchParams({
      page: currentPage,
      limit: 15,
      q: currentFilters.q,
      pais: currentFilters.pais,
      tipo: currentFilters.tipo,
      tarja: currentFilters.tarja,
      sort_by: currentFilters.sortBy,
      sort_order: currentFilters.sortOrder
    });

    const res = await fetch(`/api/medicamentos?${params}`);
    const data = await res.json();

    if (!data.items || data.items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 40px; color: var(--text-muted);">Nenhum medicamento encontrado para os critérios selecionados.</td></tr>`;
      setElemText('table-pagination-info', '0 de 0 registros');
      return;
    }

    tbody.innerHTML = '';
    data.items.forEach(item => {
      const tr = document.createElement('tr');
      tr.addEventListener('click', () => openMedicamentoModal(item.registro_13));

      let tipoBadge = `<span class="badge badge-success">Nacional</span>`;
      if (item.tipo_fabricante === 'INTERNACIONAL') {
        tipoBadge = `<span class="badge badge-purple">${item.pais_fabrica || 'Importado'}</span>`;
      }

      let tarjaBadge = `<span class="badge badge-secondary">${item.tarja}</span>`;
      if (item.tarja && item.tarja.includes('Vermelha')) tarjaBadge = `<span class="badge badge-warning">Vermelha</span>`;
      else if (item.tarja && item.tarja.includes('Preta')) tarjaBadge = `<span class="badge" style="background:#1e293b; color:#fff;">Preta</span>`;

      tr.innerHTML = `
        <td>
          <div style="font-weight: 700; color: var(--primary); font-size: 14px;">${item.produto}</div>
          <div style="font-size: 12px; color: var(--text-muted);">${item.substancia || '-'}</div>
        </td>
        <td>
          <div style="font-weight: 500;">${item.detentora}</div>
          <div style="display: flex; gap: 6px; align-items: center; margin-top: 2px;">
            <span style="font-size: 11px; color: var(--text-light);">${item.cnpj_detentora || ''} (${item.uf_detentora || '-'})</span>
            <button class="btn-secondary btn-sm" style="font-size: 10px; padding: 2px 6px; color: var(--primary);" onclick="event.stopPropagation(); openSocietarioModal('${(item.cnpj_detentora || item.detentora).replace(/'/g, "\\'")}')">QSA</button>
          </div>
        </td>
        <td>
          <div style="font-weight: 600; color: var(--text-main);">${item.fabrica_real}</div>
          <div style="display: flex; gap: 6px; align-items: center; margin-top: 4px;">
            ${tipoBadge}
            <button class="btn-secondary btn-sm" style="font-size: 10px; padding: 2px 6px;" onclick="event.stopPropagation(); openSocietarioModal('${(item.cnpj_fabrica || item.fabrica_real || item.fabrica).replace(/'/g, "\\'")}')">QSA Fábrica</button>
          </div>
        </td>
        <td>
          <div style="font-size: 12px; font-weight: 500;">${item.forma}</div>
          <div style="font-size: 11px; color: var(--text-muted);">${item.embalagem}</div>
        </td>
        <td>${tarjaBadge}</td>
        <td style="font-weight: 700; color: var(--text-main);">${formatBRL(item.pf_18)}</td>
        <td>
          <div style="display: flex; gap: 6px; align-items: center;">
            <button class="btn-secondary btn-sm" onclick="event.stopPropagation(); openMedicamentoModal('${item.registro_13}')">
              Raio-X
            </button>
            <button class="btn-secondary btn-sm" style="color: var(--primary); font-weight: 600;" onclick="event.stopPropagation(); openSocietarioModal('${(item.cnpj_detentora || item.detentora).replace(/'/g, "\\'")}')">
              QSA
            </button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });

    const start = (data.page - 1) * data.limit + 1;
    const end = Math.min(data.page * data.limit, data.total);
    setElemText('table-pagination-info', `Mostrando ${formatNumber(start)} - ${formatNumber(end)} de ${formatNumber(data.total)} medicamentos`);

    document.getElementById('btn-prev').disabled = data.page <= 1;
    document.getElementById('btn-next').disabled = data.page >= data.pages;

  } catch (err) {
    console.error('Erro ao listar medicamentos:', err);
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--danger); padding: 30px;">Erro ao carregar dados do servidor.</td></tr>`;
  }
}

// -------------------------------------------------------------
// TAB 3: LABORATÓRIOS & RECEITA FEDERAL
// -------------------------------------------------------------
function sortEmpresasTab(col) {
  if (empresasFilters.sortBy === col) {
    empresasFilters.sortOrder = empresasFilters.sortOrder === 'asc' ? 'desc' : 'asc';
  } else {
    empresasFilters.sortBy = col;
    empresasFilters.sortOrder = 'desc';
  }

  // Update icons
  document.querySelectorAll('.sort-icon').forEach(i => i.innerText = '↕');
  const activeIcon = document.getElementById(`sort-emp-${col}`);
  if (activeIcon) activeIcon.innerText = empresasFilters.sortOrder === 'asc' ? '▲' : '▼';

  loadEmpresas();
}

async function loadEmpresas() {
  const tbody = document.getElementById('empresas-table-body');
  try {
    const params = new URLSearchParams({
      sort_by: empresasFilters.sortBy,
      sort_order: empresasFilters.sortOrder,
      q: empresasFilters.q
    });

    const res = await fetch(`/api/empresas?${params}`);
    const data = await res.json();

    tbody.innerHTML = '';
    if (!data || data.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 40px; color: var(--text-muted);">Nenhum laboratório encontrado.</td></tr>`;
      return;
    }

    data.forEach(e => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>
          <div style="font-weight: 700; color: var(--text-main);">${e.razao_social}</div>
          <div style="font-size: 11px; color: var(--text-muted);">${e.nome_fantasia || ''}</div>
        </td>
        <td><code>${e.cnpj_formatado}</code></td>
        <td><span class="badge badge-info">${e.uf || '-'}</span> ${e.cidade || ''}</td>
        <td style="font-weight: 600;">${formatBRL(e.capital_social)}</td>
        <td style="font-weight: 700; color: var(--primary); text-align: center;">${formatNumber(e.total_produtos_cmed)}</td>
        <td style="font-size: 12px; color: var(--text-muted); max-width: 320px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${e.socios_donos_administradores || ''}">
          ${e.socios_donos_administradores || 'Não informado'}
        </td>
        <td>
          <button class="btn-primary btn-sm" onclick="event.stopPropagation(); openSocietarioModal('${(e.cnpj_limpo || e.razao_social).replace(/'/g, "\\'")}')">
            Ver QSA & Contatos
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Erro ao listar empresas:', err);
  }
}

// -------------------------------------------------------------
// Modal Raio-X do Medicamento
// -------------------------------------------------------------
async function openMedicamentoModal(registro) {
  const modal = document.getElementById('modal-medicamento');
  modal.classList.add('open');

  setElemText('modal-produto-nome', 'Carregando ficha técnica 360°...');
  setElemText('modal-substancia', '');

  try {
    const res = await fetch(`/api/medicamento/${registro}`);
    const data = await res.json();
    const p = data.dados_cmed_anvisa;
    const fabs = data.fabricantes || [];

    setElemText('modal-produto-nome', p.PRODUTO || p.produto_nome);
    setElemText('modal-substancia', `${p.SUBSTÂNCIA || p.substancia} | Registro CMED: ${p.REGISTRO || p.registro_13}`);

    setElemText('m-preco-pf18', formatBRL(p.pf_18));
    setElemText('m-preco-pmvg18', formatBRL(p.pmvg_18));
    setElemText('m-ggrem', p.codigo_ggrem || '-');
    setElemText('m-ean', p.ean_1 || '-');
    setElemText('m-classe-terap', p.classe_terapeutica || '-');

    setElemText('m-detentora-nome', p.emp_razao || p.laboratorio_nome || '-');
    setElemText('m-detentora-cnpj', p.cnpj_limpo || '-');
    setElemText('m-detentora-socios', p.socios || 'Não informado');
    setElemText('m-detentora-capital', formatBRL(p.capital_social));
    setElemText('m-detentora-contato', `${p.telefone || ''} | ${p.email || ''}`);

    let formas = p.formas_farmaceuticas;
    let vias = p.vias_administracao;
    try { formas = jsonParseSafe(formas); } catch (e) {}
    try { vias = jsonParseSafe(vias); } catch (e) {}

    setElemText('m-anvisa-forma', Array.isArray(formas) ? formas.join(', ') : (formas || '-'));
    setElemText('m-anvisa-via', Array.isArray(vias) ? vias.join(', ') : (vias || '-'));
    setElemText('m-anvisa-embalagem-prim', p.embalagem_primaria_tipo || '-');
    setElemText('m-anvisa-embalagem-detalhes', p.embalagem_primaria_detalhes || 'Sem especificação adicional');
    setElemText('m-anvisa-embalagem-sec', p.embalagem_secundaria_tipo || '-');

    const linkAnvisa = document.getElementById('m-link-anvisa');
    if (linkAnvisa) {
      if (p.url_consulta_anvisa) {
        linkAnvisa.href = p.url_consulta_anvisa;
        linkAnvisa.style.display = 'inline-flex';
      } else {
        linkAnvisa.style.display = 'none';
      }
    }

    const btnDetQSA = document.getElementById('btn-m-detentora-qsa');
    if (btnDetQSA) {
      btnDetQSA.onclick = (e) => {
        e.stopPropagation();
        openSocietarioModal(p.cnpj_limpo || p.emp_razao || p.laboratorio_nome);
      };
    }

    const fabList = document.getElementById('modal-fabricantes-list');
    fabList.innerHTML = '';
    if (fabs.length === 0) {
      fabList.innerHTML = '<div style="color: var(--text-muted); font-size: 13px;">Nenhuma fábrica registrada nos dados abertos para este registro.</div>';
    } else {
      fabs.forEach(f => {
        const item = document.createElement('div');
        item.style.padding = '10px 14px';
        item.style.borderRadius = 'var(--radius-sm)';
        item.style.backgroundColor = '#fff';
        item.style.border = '1px solid var(--border-color)';
        item.style.marginBottom = '8px';
        item.style.display = 'flex';
        item.style.justifyContent = 'space-between';
        item.style.alignItems = 'center';
        item.style.flexWrap = 'wrap';
        item.style.gap = '8px';

        const badge = f.tipo_fabricante === 'INTERNACIONAL' 
          ? `<span class="badge badge-purple">Importado: ${f.pais_fabricante}</span>`
          : `<span class="badge badge-success">Fábrica Nacional: ${f.cidade_fabricante || ''}/${f.uf_fabricante || ''}</span>`;

        item.innerHTML = `
          <div>
            <div style="font-weight: 700; font-size: 13px;">${f.razao_social_fabricante}</div>
            <div style="font-size: 11px; color: var(--text-muted);">${f.etapa_fabricacao || 'Fabricação completa'} ${f.endereco_fabricante ? ' - ' + f.endereco_fabricante : ''}</div>
          </div>
          <div style="display: flex; gap: 8px; align-items: center;">
            ${badge}
            <button class="btn-secondary btn-sm" style="color: var(--primary); font-weight: 600;" onclick="event.stopPropagation(); openSocietarioModal('${(f.cnpj_fabricante_limpo || f.razao_social_fabricante).replace(/'/g, "\\'")}')">
              QSA & Contato
            </button>
          </div>
        `;
        fabList.appendChild(item);
      });
    }

  } catch (err) {
    console.error('Erro ao carregar detalhes do medicamento:', err);
  }
}

function jsonParseSafe(str) {
  if (!str) return str;
  try { return JSON.parse(str); } catch (e) { return str; }
}

function closeModal() {
  document.getElementById('modal-medicamento').classList.remove('open');
}

// -------------------------------------------------------------
// MODAL: QUADRO SOCIETÁRIO & CONTATOS (QSA 360°)
// -------------------------------------------------------------
async function openSocietarioModal(identificador) {
  if (!identificador) return;
  const modal = document.getElementById('modal-societario');
  if (!modal) return;
  modal.classList.add('open');

  setElemText('soc-razao-social', 'Carregando dados societários...');
  setElemText('soc-nome-fantasia', '');
  setElemText('soc-cnpj', '...');
  setElemText('soc-telefone', '...');
  setElemText('soc-email', '...');
  setElemText('soc-endereco', 'Carregando endereço...');
  setElemText('soc-capital', '...');
  setElemText('soc-inicio-ativ', '...');
  setElemText('soc-cnae', '...');
  setElemText('soc-cnae-desc', '...');
  setElemText('soc-total-socios', '...');
  document.getElementById('soc-socios-list').innerHTML = '<div style="color: var(--text-muted); font-size: 13px; padding: 10px;">Buscando sócios e administradores na base federal...</div>';
  document.getElementById('soc-produtos-list').innerHTML = '<div style="color: var(--text-muted); font-size: 13px; padding: 10px;">Carregando medicamentos vinculados...</div>';

  try {
    const encodedId = encodeURIComponent(identificador.trim());
    const res = await fetch(`/api/societario/${encodedId}`);
    if (!res.ok) {
      setElemText('soc-razao-social', `Registro não localizado para '${identificador}'`);
      document.getElementById('soc-socios-list').innerHTML = '<div style="color: var(--text-muted); padding: 10px;">Nenhum dado cadastral disponível para esta entidade no momento.</div>';
      document.getElementById('soc-produtos-list').innerHTML = '';
      return;
    }
    const data = await res.json();

    // Badges de Tipo e Situação
    const tipo = data.tipo_entidade || 'DETENTORA';
    let tipoClass = 'badge-success';
    let tipoLabel = 'Fábrica Nacional';
    if (tipo === 'AMBAS') {
      tipoClass = 'badge-purple';
      tipoLabel = 'Detentora & Fábrica Própria';
    } else if (tipo === 'DETENTORA') {
      tipoClass = 'badge-info';
      tipoLabel = 'Empresa Detentora da Marca';
    } else if (tipo.includes('INTERNACIONAL') || data.is_internacional) {
      tipoClass = 'badge-purple';
      tipoLabel = `Fábrica Internacional (${data.uf || 'Exterior'})`;
    }
    const tipoBadge = document.getElementById('soc-tipo-badge');
    tipoBadge.className = `badge ${tipoClass}`;
    tipoBadge.innerText = tipoLabel;

    const sitBadge = document.getElementById('soc-situacao-badge');
    sitBadge.innerText = data.situacao_cadastral || 'ATIVA';
    sitBadge.className = (data.situacao_cadastral || '').toUpperCase().includes('ATIVA') ? 'badge badge-success' : 'badge badge-warning';

    setElemText('soc-razao-social', data.razao_social || identificador);
    setElemText('soc-nome-fantasia', data.nome_fantasia ? `Nome Fantasia: ${data.nome_fantasia}` : '');
    setElemText('soc-cnpj', data.cnpj_formatado || data.cnpj_limpo || 'SEDE NO EXTERIOR');

    // Contatos (Telefone, Email, Endereço)
    const tel = data.telefone && data.telefone.trim() ? data.telefone.trim() : null;
    const email = data.email && data.email.trim() ? data.email.trim().toLowerCase() : null;
    
    const telElem = document.getElementById('soc-telefone');
    if (tel) {
      telElem.innerHTML = `<a href="tel:${tel.replace(/\D/g, '')}" style="color: var(--text-main); text-decoration: underline; font-weight: 700;">${tel}</a>`;
    } else if (data.is_internacional) {
      telElem.innerText = 'Consulte o laboratório importador no Brasil abaixo';
    } else {
      telElem.innerText = 'Telefone não cadastrado na Receita';
    }

    const emailElem = document.getElementById('soc-email');
    if (email) {
      emailElem.innerText = email;
      emailElem.href = `mailto:${email}`;
      emailElem.style.display = 'inline';
    } else {
      const qEncoded = encodeURIComponent(`${data.razao_social} contato sac email site oficial`);
      emailElem.innerText = 'Buscar Canal de Atendimento / SAC';
      emailElem.href = `https://www.google.com/search?q=${qEncoded}`;
      emailElem.target = '_blank';
      emailElem.style.display = 'inline';
      emailElem.style.textDecoration = 'underline';
    }

    setElemText('soc-endereco', data.endereco_completo || `${data.municipio || ''} - ${data.uf || ''}`);

    // Website Button
    const websiteBtn = document.getElementById('soc-website-btn');
    if (data.website) {
      websiteBtn.href = data.website;
      websiteBtn.innerText = 'Acessar Website Oficial';
      websiteBtn.style.display = 'inline-flex';
    } else if (data.website_busca) {
      websiteBtn.href = data.website_busca;
      websiteBtn.innerText = data.is_internacional ? 'Buscar Planta Fabril Global' : 'Buscar Portal Oficial';
      websiteBtn.style.display = 'inline-flex';
    } else {
      websiteBtn.style.display = 'none';
    }

    // Corporate Facts
    if (data.is_internacional) {
      setElemText('soc-capital', 'Capital Estrangeiro');
      setElemText('soc-inicio-ativ', `Sede: ${data.uf || 'Exterior'}`);
      setElemText('soc-cnae', 'Produção Internacional');
      setElemText('soc-cnae-desc', data.cnae_descricao || 'Planta fabril homologada pela ANVISA no exterior');
      setElemText('soc-total-socios', '-');
      setElemText('soc-qsa-heading', 'Estrutura Internacional & Detentoras no Brasil');
      const badgeOrigem = document.getElementById('soc-badge-origem');
      if (badgeOrigem) {
        badgeOrigem.innerText = 'Homologação ANVISA / Exterior';
        badgeOrigem.className = 'badge badge-purple';
      }
    } else {
      setElemText('soc-capital', formatBRL(data.capital_social || 0));
      setElemText('soc-inicio-ativ', data.data_inicio_atividade ? `Início de atividade: ${data.data_inicio_atividade}` : 'Início de atividade: não informado');
      setElemText('soc-cnae', data.cnae_principal ? `CNAE: ${data.cnae_principal}` : 'CNAE Farmacêutico');
      setElemText('soc-cnae-desc', data.cnae_descricao || 'Fabricação de produtos farmacêuticos');
      
      const socios = data.socios || [];
      setElemText('soc-total-socios', socios.length);
      setElemText('soc-qsa-heading', 'Quadro de Sócios e Administradores Registrados');
      const badgeOrigem = document.getElementById('soc-badge-origem');
      if (badgeOrigem) {
        badgeOrigem.innerText = 'Receita Federal do Brasil';
        badgeOrigem.className = 'badge badge-secondary';
      }
    }

    // Render Sócios / Estrutura
    const sociosList = document.getElementById('soc-socios-list');
    sociosList.innerHTML = '';

    if (data.is_internacional) {
      let htmlInternacional = `
        <div style="padding: 14px 16px; background: #faf5ff; border: 1px solid #e9d5ff; border-radius: var(--radius-sm); margin-bottom: 12px; font-size: 13px; color: #581c87; line-height: 1.5;">
          <strong>Unidade Fabril Estrangeira:</strong> Esta planta é sediada em <strong>${data.uf || 'país do exterior'}</strong> e opera sob homologação sanitária aprovada pela ANVISA. Empresas estrangeiras não têm Quadro de Sócios (QSA) perante a Receita Federal do Brasil. Os responsáveis legais e regulatórios no país são os laboratórios detentores listados a seguir:
        </div>
      `;

      const detentoras = data.detentoras_brasil || [];
      if (detentoras.length > 0) {
        htmlInternacional += `<div style="font-size: 12px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-bottom: 8px;">Laboratórios Detentores / Importadores Registrados no Brasil:</div>`;
        detentoras.forEach(d => {
          htmlInternacional += `
            <div style="padding: 12px 16px; border-radius: var(--radius-sm); background: #ffffff; border: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 8px;">
              <div>
                <div style="font-weight: 700; font-size: 14px; color: var(--primary);">${d.razao_social}</div>
                <div style="font-size: 12px; color: var(--text-muted); margin-top: 3px;">
                  CNPJ: <strong>${d.cnpj || '-'}</strong> • UF: <strong>${d.uf || '-'}</strong>
                  ${d.telefone ? ` • Telefone: <a href="tel:${d.telefone.replace(/\D/g, '')}" style="color: #059669; font-weight: 700; text-decoration: none;">${d.telefone}</a>` : ''}
                </div>
                ${d.socios ? `<div style="font-size: 11px; color: var(--text-light); margin-top: 4px;">Principais Diretores/Sócios: ${d.socios}</div>` : ''}
              </div>
              <div>
                <button class="btn-primary btn-sm" onclick="openSocietarioModal('${(d.cnpj || d.razao_social).replace(/'/g, "\\'")}')">
                  Ver QSA da Detentora
                </button>
              </div>
            </div>
          `;
        });
      } else {
        htmlInternacional += `<div style="color: var(--text-muted); font-size: 13px; padding: 8px;">Consulte os medicamentos vinculados abaixo para ver as detentoras responsáveis.</div>`;
      }
      sociosList.innerHTML = htmlInternacional;

    } else {
      const socios = data.socios || [];
      if (socios.length === 0) {
        sociosList.innerHTML = `
          <div style="padding: 12px; background: var(--bg-card-subtle); border-radius: var(--radius-sm); color: var(--text-muted); font-size: 13px;">
            ${data.socios_resumo || 'Sem registro detalhado de sócios na base aberta da Receita Federal.'}
          </div>
        `;
      } else {
        socios.forEach(s => {
          const item = document.createElement('div');
          item.style.padding = '10px 14px';
          item.style.borderRadius = 'var(--radius-sm)';
          item.style.backgroundColor = '#fff';
          item.style.border = '1px solid var(--border-color)';
          item.style.display = 'flex';
          item.style.justifyContent = 'space-between';
          item.style.alignItems = 'center';
          item.style.flexWrap = 'wrap';
          item.style.gap = '8px';

          const cargoBadge = `<span class="badge badge-info" style="font-size: 11px;">${s.qualificacao_socio || 'Sócio'}</span>`;
          const extraInfo = [];
          if (s.faixa_etaria && s.faixa_etaria !== 'Não se aplica' && s.faixa_etaria !== 'Não informada') extraInfo.push(s.faixa_etaria);
          if (s.pais) extraInfo.push(`País: ${s.pais}`);
          if (s.data_entrada_sociedade && s.data_entrada_sociedade !== '-') extraInfo.push(`Entrada: ${s.data_entrada_sociedade}`);
          if (s.nome_representante_legal) extraInfo.push(`Rep. Legal: ${s.nome_representante_legal}`);

          item.innerHTML = `
            <div>
              <div style="font-weight: 700; font-size: 13px; color: var(--text-main);">${s.nome_socio}</div>
              <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">
                ${extraInfo.length > 0 ? extraInfo.join(' • ') : 'Pessoa Física / Jurídica'}
              </div>
            </div>
            <div>${cargoBadge}</div>
          `;
          sociosList.appendChild(item);
        });
      }
    }

    // Render Produtos Vinculados
    const prodsList = document.getElementById('soc-produtos-list');
    const prods = data.produtos_vinculados || [];
    if (prods.length === 0) {
      prodsList.innerHTML = '<div style="color: var(--text-muted); font-size: 13px; padding: 10px;">Nenhum produto individual listado para esta unidade.</div>';
    } else {
      let html = `
        <table class="modern-table" style="font-size: 12px; margin-top: 6px;">
          <thead>
            <tr>
              <th>Medicamento</th>
              <th>Papel da Entidade</th>
              <th>Etapa / Categoria</th>
              <th>Registro</th>
            </tr>
          </thead>
          <tbody>
      `;
      prods.forEach(p => {
        const papelBadge = (p.papel || '').includes('Detentora') 
          ? `<span class="badge badge-info">${p.papel}</span>` 
          : `<span class="badge badge-success">${p.papel || 'Fábrica'}</span>`;
        
        html += `
          <tr style="cursor: pointer;" onclick="openMedicamentoModal('${p.registro_13 || p.numero_registro_base}')">
            <td style="font-weight: 700; color: var(--primary);">${p.produto_nome || p.nome_produto}</td>
            <td>${papelBadge}</td>
            <td style="color: var(--text-muted);">${p.etapa_fabricacao || p.anvisa_categoria_regulatoria || p.categoria_regulatoria || 'Fabricação'}</td>
            <td><code>${p.registro_13 || p.numero_registro_base || '-'}</code></td>
          </tr>
        `;
      });
      html += '</tbody></table>';
      prodsList.innerHTML = html;
    }

  } catch (err) {
    console.error('Erro ao abrir dados societários:', err);
    setElemText('soc-razao-social', 'Erro ao carregar dados societários');
  }
}

function closeSocietarioModal() {
  const modal = document.getElementById('modal-societario');
  if (modal) modal.classList.remove('open');
}

// Global modal background and Escape key listener
window.addEventListener('click', (e) => {
  const mMed = document.getElementById('modal-medicamento');
  if (e.target === mMed) closeModal();
  const mSoc = document.getElementById('modal-societario');
  if (e.target === mSoc) closeSocietarioModal();
});
window.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeModal();
    closeSocietarioModal();
  }
});

// -------------------------------------------------------------
// Filters & Search Inputs
// -------------------------------------------------------------
function initSearchAndFilters() {
  // Tab 2 search input
  const searchInput = document.getElementById('search-medicamento');
  let timeout = null;
  searchInput.addEventListener('input', (e) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => {
      currentFilters.q = e.target.value.trim();
      currentPage = 1;
      loadMedicamentos();
    }, 300);
  });

  document.getElementById('filter-pais').addEventListener('change', (e) => {
    currentFilters.pais = e.target.value;
    currentPage = 1;
    loadMedicamentos();
  });

  document.getElementById('filter-tipo').addEventListener('change', (e) => {
    currentFilters.tipo = e.target.value;
    currentPage = 1;
    loadMedicamentos();
  });

  document.getElementById('filter-tarja').addEventListener('change', (e) => {
    currentFilters.tarja = e.target.value;
    currentPage = 1;
    loadMedicamentos();
  });

  document.getElementById('btn-prev').addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage--;
      loadMedicamentos();
    }
  });

  document.getElementById('btn-next').addEventListener('click', () => {
    currentPage++;
    loadMedicamentos();
  });

  // Drilldown search input
  const drillSearch = document.getElementById('drilldown-search-input');
  let drillTimeout = null;
  drillSearch.addEventListener('input', (e) => {
    clearTimeout(drillTimeout);
    drillTimeout = setTimeout(() => {
      drilldownState.q = e.target.value.trim();
      drilldownState.page = 1;
      loadDrilldown();
    }, 300);
  });

  // Tab 3 Empresas search input
  const searchEmpresa = document.getElementById('search-empresa');
  let empTimeout = null;
  if (searchEmpresa) {
    searchEmpresa.addEventListener('input', (e) => {
      clearTimeout(empTimeout);
      empTimeout = setTimeout(() => {
        empresasFilters.q = e.target.value.trim();
        loadEmpresas();
      }, 300);
    });
  }

  // Tab Especiais filters
  const searchEsp = document.getElementById('search-especial');
  let espTimeout = null;
  if (searchEsp) {
    searchEsp.addEventListener('input', (e) => {
      clearTimeout(espTimeout);
      espTimeout = setTimeout(() => {
        especiaisFilters.q = e.target.value.trim();
        especiaisFilters.page = 1;
        loadEspeciais();
      }, 300);
    });
  }

  const catEsp = document.getElementById('filter-especial-cat');
  if (catEsp) {
    catEsp.addEventListener('change', (e) => {
      especiaisFilters.categoria = e.target.value;
      especiaisFilters.page = 1;
      loadEspeciais();
    });
  }

  const statusEsp = document.getElementById('filter-especial-status');
  if (statusEsp) {
    statusEsp.addEventListener('change', (e) => {
      especiaisFilters.situacao = e.target.value;
      especiaisFilters.page = 1;
      loadEspeciais();
    });
  }

  const btnEspPrev = document.getElementById('btn-esp-prev');
  if (btnEspPrev) {
    btnEspPrev.addEventListener('click', () => {
      if (especiaisFilters.page > 1) {
        especiaisFilters.page--;
        loadEspeciais();
      }
    });
  }

  const btnEspNext = document.getElementById('btn-esp-next');
  if (btnEspNext) {
    btnEspNext.addEventListener('click', () => {
      if (especiaisFilters.page < especiaisFilters.totalPages) {
        especiaisFilters.page++;
        loadEspeciais();
      }
    });
  }
}

// -------------------------------------------------------------
// TAB: MEDICAMENTOS ESPECIAIS & FITOTERÁPICOS (MOTIVO 3)
// -------------------------------------------------------------
let especiaisFilters = {
  q: '',
  categoria: '',
  situacao: '',
  sortBy: 'nome',
  sortOrder: 'asc',
  page: 1,
  limit: 15,
  totalPages: 1
};

function sortEspeciaisTab(col) {
  if (especiaisFilters.sortBy === col) {
    especiaisFilters.sortOrder = especiaisFilters.sortOrder === 'asc' ? 'desc' : 'asc';
  } else {
    especiaisFilters.sortBy = col;
    especiaisFilters.sortOrder = 'asc';
  }

  document.querySelectorAll('.sort-icon').forEach(i => i.innerText = '↕');
  const activeIcon = document.getElementById(`sort-esp-${col}`);
  if (activeIcon) activeIcon.innerText = especiaisFilters.sortOrder === 'asc' ? '▲' : '▼';

  especiaisFilters.page = 1;
  loadEspeciais();
}

async function loadEspeciais() {
  const tbody = document.getElementById('especiais-table-body');
  if (!tbody) return;

  tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 40px; color: var(--text-muted);">Carregando medicamentos especiais...</td></tr>`;

  try {
    const params = new URLSearchParams({
      page: especiaisFilters.page,
      limit: especiaisFilters.limit,
      q: especiaisFilters.q,
      categoria: especiaisFilters.categoria,
      situacao: especiaisFilters.situacao,
      sort_by: especiaisFilters.sortBy,
      sort_order: especiaisFilters.sortOrder
    });

    const res = await fetch(`/api/especiais?${params}`);
    const data = await res.json();

    if (!data.items || data.items.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 40px; color: var(--text-muted);">Nenhum medicamento especial encontrado para os critérios selecionados.</td></tr>`;
      setElemText('especiais-pagination-info', '0 de 0 registros');
      return;
    }

    especiaisFilters.totalPages = data.pages || 1;
    tbody.innerHTML = '';

    data.items.forEach(item => {
      const tr = document.createElement('tr');

      // Category badge
      let catBadge = `<span class="badge badge-secondary">${item.categoria_regulatoria || 'Especial'}</span>`;
      const cat = (item.categoria_regulatoria || '').toUpperCase();
      if (cat.includes('FITO')) catBadge = `<span class="badge badge-success">Fitoterápico</span>`;
      else if (cat.includes('BIOL')) catBadge = `<span class="badge badge-purple">Biológico</span>`;
      else if (cat.includes('DINAM')) catBadge = `<span class="badge badge-info">Dinamizado</span>`;
      else if (cat.includes('RADIO')) catBadge = `<span class="badge badge-warning">Radiofármaco</span>`;
      else if (cat.includes('ESPEC')) catBadge = `<span class="badge" style="background:#e2e8f0; color:#334155;">Específico</span>`;

      // Status badge
      const isAtivo = (item.situacao_registro || '').toUpperCase() === 'ATIVO';
      const statusBadge = isAtivo 
        ? `<span class="badge badge-success">Ativo</span>`
        : `<span class="badge" style="background:#f1f5f9; color:#94a3b8;">Inativo</span>`;

      tr.innerHTML = `
        <td>
          <div style="font-weight: 700; color: var(--text-main); font-size: 14px;">${item.nome_produto}</div>
          <div style="font-size: 12px; color: var(--text-muted);">${item.principio_ativo || '-'}</div>
        </td>
        <td>${catBadge}</td>
        <td>
          <div style="font-weight: 600; font-size: 12px;">${item.razao_social_detentora}</div>
          <div style="font-size: 11px; color: var(--text-light);">${item.cnpj_detentora_limpo || ''}</div>
        </td>
        <td>
          <div style="font-size: 12px; color: var(--text-muted);">${item.classe_terapeutica || '-'}</div>
          <div style="font-size: 11px; color: var(--text-light);">Proc: ${item.numero_processo || '-'}</div>
        </td>
        <td>${statusBadge}</td>
        <td style="font-weight: 700; color: var(--primary); text-align: center;">${formatNumber(item.total_apresentacoes)}</td>
        <td>
          <div style="display: flex; gap: 6px; align-items: center;">
            <button class="btn-secondary btn-sm" style="color: var(--primary); font-weight: 600;" onclick="event.stopPropagation(); openSocietarioModal('${(item.cnpj_detentora_limpo || item.razao_social_detentora).replace(/'/g, "\\'")}')">
              QSA
            </button>
            ${item.url_consulta_anvisa ? `
              <a href="${item.url_consulta_anvisa}" target="_blank" class="btn-secondary btn-sm" style="text-decoration: none;">
                Ver na ANVISA
              </a>
            ` : '-'}
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });

    const start = (data.page - 1) * data.limit + 1;
    const end = Math.min(data.page * data.limit, data.total);
    setElemText('especiais-pagination-info', `Mostrando ${formatNumber(start)} - ${formatNumber(end)} de ${formatNumber(data.total)} itens`);

    const btnPrev = document.getElementById('btn-esp-prev');
    const btnNext = document.getElementById('btn-esp-next');
    if (btnPrev) btnPrev.disabled = data.page <= 1;
    if (btnNext) btnNext.disabled = data.page >= data.pages;

  } catch (err) {
    console.error('Erro ao listar medicamentos especiais:', err);
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--danger); padding: 30px;">Erro ao carregar dados.</td></tr>`;
  }
}

// -------------------------------------------------------------
// SQL Studio
// -------------------------------------------------------------
function initSqlStudio() {
  const runBtn = document.getElementById('btn-run-sql');
  const textarea = document.getElementById('sql-query-input');
  const resultsContainer = document.getElementById('sql-results');
  const statusEl = document.getElementById('sql-status');

  runBtn.addEventListener('click', async () => {
    const query = textarea.value.trim();
    if (!query) return;

    statusEl.innerText = 'Executando consulta SQL no banco SQLite...';
    resultsContainer.innerHTML = '';

    try {
      const res = await fetch('/api/sql', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query })
      });
      const data = await res.json();

      if (data.error) {
        statusEl.innerHTML = `<span style="color: var(--danger);">Erro: ${data.error}</span>`;
        return;
      }

      statusEl.innerHTML = `Consulta executada. Retornadas <strong>${data.total_rows} linhas</strong> em <strong>${data.execution_time_ms} ms</strong>.`;

      let tableHtml = '<div class="table-responsive"><table class="modern-table"><thead><tr>';
      data.columns.forEach(col => { tableHtml += `<th>${col}</th>`; });
      tableHtml += '</tr></thead><tbody>';

      data.rows.forEach(row => {
        tableHtml += '<tr>';
        row.forEach(val => {
          let formatted = val;
          if (typeof val === 'number') formatted = formatNumber(val);
          tableHtml += `<td>${formatted !== null ? formatted : '-'}</td>`;
        });
        tableHtml += '</tr>';
      });

      tableHtml += '</tbody></table></div>';
      resultsContainer.innerHTML = tableHtml;

    } catch (err) {
      statusEl.innerHTML = `<span style="color: var(--danger);">Erro de comunicação com o servidor: ${err}</span>`;
    }
  });

  document.querySelectorAll('.preset-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const sql = chip.getAttribute('data-sql');
      textarea.value = sql;
      runBtn.click();
    });
  });
}
