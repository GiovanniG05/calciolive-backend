require('dotenv').config();
const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// Supabase client
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// Middleware
app.use(cors());
app.use(express.json());

// OTP store in-memory
const otpStore = new Map(); // email -> { code, expires, userId, token }

// ── MIDDLEWARE AUTH ──────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token mancante' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token non valido' });
  }
}

// ── REGISTER ────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { email, password, username, nome, cognome, squadra_preferita, squadra_crest } = req.body;

  if (!email || !password || !username || !nome || !cognome) {
    return res.status(400).json({ error: 'Tutti i campi sono obbligatori' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'La password deve essere di almeno 6 caratteri' });
  }

  try {
    // Controlla se email o username esistono già
    const { data: existing } = await supabase
      .from('users')
      .select('id')
      .or(`email.eq.${email},username.eq.${username}`)
      .single();

    if (existing) {
      return res.status(409).json({ error: 'Email o username già in uso' });
    }

    // Hash password
    const password_hash = await bcrypt.hash(password, 12);

    // Inserisci utente
    const { data: user, error } = await supabase
      .from('users')
      .insert({ email, password_hash, username, nome, cognome, squadra_preferita: squadra_preferita ?? '', squadra_crest: squadra_crest ?? '' })
      .select('id, email, username, nome, cognome, squadra_preferita, squadra_crest, created_at')
      .single();

    if (error) throw error;

    // Genera token
    const token = jwt.sign(
      { id: user.id, email: user.email, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({ user, token });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Errore durante la registrazione' });
  }
});

// ── LOGIN ────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email e password obbligatorie' });
  }

  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, username, nome, cognome, squadra_preferita, squadra_crest, role, password_hash, created_at')
      .eq('email', email)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'Credenziali non valide' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Credenziali non valide' });
    }

    // Genera OTP per tutti gli utenti
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + 10 * 60 * 1000; // 10 minuti
    const tempToken = jwt.sign(
      { id: user.id, email: user.email, username: user.username, role: user.role ?? 'user' },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    otpStore.set(user.email, {
      code: otp,
      expires,
      userId: user.id,
      token: tempToken,
      userData: {
        id: user.id,
        email: user.email,
        username: user.username,
        nome: user.nome,
        cognome: user.cognome,
        squadra_preferita: user.squadra_preferita,
        squadra_crest: user.squadra_crest,
        role: user.role ?? 'user',
        created_at: user.created_at
      }
    });

    // Manda email OTP
    try {
      await resend.emails.send({
        from: 'CalcioLive <noreply@resend.dev>',
        to: user.email,
        subject: 'Il tuo codice di accesso CalcioLive',
        html: `
          <div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:32px;background:#0d1117;border-radius:16px;color:white">
            <h2 style="color:#4ade80;margin:0 0 8px">CalcioLive</h2>
            <p style="color:rgba(255,255,255,.6);margin:0 0 24px">Il tuo codice di verifica:</p>
            <div style="font-size:2.5rem;font-weight:900;letter-spacing:8px;color:white;text-align:center;background:rgba(255,255,255,.08);padding:20px;border-radius:12px;margin-bottom:24px">${otp}</div>
            <p style="color:rgba(255,255,255,.4);font-size:.85rem">Questo codice scade tra 10 minuti. Non condividerlo con nessuno.</p>
          </div>
        `
      });
    } catch (emailErr) {
      console.error('Email error:', emailErr);
    }

    res.json({ requires_2fa: true, email: user.email });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Errore durante il login' });
  }
});

// ── VERIFY OTP ────────────────────────────────────────────────────
app.post('/api/auth/verify-otp', async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ error: 'Email e codice obbligatori' });

  const entry = otpStore.get(email);
  if (!entry) return res.status(400).json({ error: 'Codice non valido o scaduto' });
  if (Date.now() > entry.expires) {
    otpStore.delete(email);
    return res.status(400).json({ error: 'Codice scaduto — effettua nuovamente il login' });
  }
  if (entry.code !== code) return res.status(400).json({ error: 'Codice non corretto' });

  otpStore.delete(email);
  res.json({ user: entry.userData, token: entry.token });
});

// ── ME ───────────────────────────────────────────────────────────
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, username, nome, cognome, squadra_preferita, squadra_crest, role, created_at')
      .eq('id', req.user.id)
      .single();

    if (error || !user) return res.status(404).json({ error: 'Utente non trovato' });
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: 'Errore server' });
  }
});

// ── FAVORITES COMPETIZIONI ───────────────────────────────────────
app.get('/api/favorites', authMiddleware, async (req, res) => {
  const { data, error } = await supabase
    .from('favorites')
    .select('*')
    .eq('user_id', req.user.id);

  if (error) return res.status(500).json({ error: 'Errore nel recupero preferiti' });
  res.json({ favorites: data });
});

app.post('/api/favorites', authMiddleware, async (req, res) => {
  const { competition_code } = req.body;
  if (!competition_code) return res.status(400).json({ error: 'competition_code obbligatorio' });

  const { data, error } = await supabase
    .from('favorites')
    .upsert({ user_id: req.user.id, competition_code })
    .select()
    .single();

  if (error) return res.status(500).json({ error: 'Errore nel salvataggio' });
  res.status(201).json({ favorite: data });
});

app.delete('/api/favorites/:code', authMiddleware, async (req, res) => {
  const { error } = await supabase
    .from('favorites')
    .delete()
    .eq('user_id', req.user.id)
    .eq('competition_code', req.params.code);

  if (error) return res.status(500).json({ error: 'Errore nella rimozione' });
  res.json({ success: true });
});

// ── FAVORITE TEAMS ───────────────────────────────────────────────
app.get('/api/favorite-teams', authMiddleware, async (req, res) => {
  const { data, error } = await supabase
    .from('favorite_teams')
    .select('*')
    .eq('user_id', req.user.id);

  if (error) return res.status(500).json({ error: 'Errore nel recupero squadre preferite' });
  res.json({ teams: data });
});

app.post('/api/favorite-teams', authMiddleware, async (req, res) => {
  const { team_id, team_name, team_crest } = req.body;
  if (!team_id || !team_name) return res.status(400).json({ error: 'team_id e team_name obbligatori' });

  const { data, error } = await supabase
    .from('favorite_teams')
    .upsert({ user_id: req.user.id, team_id, team_name, team_crest })
    .select()
    .single();

  if (error) return res.status(500).json({ error: 'Errore nel salvataggio' });
  res.status(201).json({ team: data });
});

app.delete('/api/favorite-teams/:teamId', authMiddleware, async (req, res) => {
  const { error } = await supabase
    .from('favorite_teams')
    .delete()
    .eq('user_id', req.user.id)
    .eq('team_id', req.params.teamId);

  if (error) return res.status(500).json({ error: 'Errore nella rimozione' });
  res.json({ success: true });
});

// ── UPDATE PROFILE ───────────────────────────────────────────────
app.put('/api/auth/profile', authMiddleware, async (req, res) => {
  const { nome, cognome, squadra_preferita, squadra_crest } = req.body;
  if (!nome || !cognome) return res.status(400).json({ error: 'Nome e cognome obbligatori' });

  try {
    const { data: user, error } = await supabase
      .from('users')
      .update({ nome, cognome, squadra_preferita: squadra_preferita ?? '', squadra_crest: squadra_crest ?? '' })
      .eq('id', req.user.id)
      .select('id, email, username, nome, cognome, squadra_preferita, squadra_crest, created_at')
      .single();

    if (error) throw error;
    res.json({ user });
  } catch (err) {
    console.error('Update profile error:', err);
    res.status(500).json({ error: 'Errore durante l aggiornamento' });
  }
});

// ── CHANGE PASSWORD ───────────────────────────────────────────────
app.put('/api/auth/password', authMiddleware, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Tutti i campi sono obbligatori' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'La nuova password deve essere di almeno 6 caratteri' });

  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('password_hash')
      .eq('id', req.user.id)
      .single();

    if (error || !user) return res.status(404).json({ error: 'Utente non trovato' });

    const valid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Password attuale non corretta' });

    const password_hash = await bcrypt.hash(newPassword, 12);
    await supabase.from('users').update({ password_hash }).eq('id', req.user.id);

    res.json({ success: true });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ error: 'Errore durante il cambio password' });
  }
});

// ── PROXY FOOTBALL-DATA GENERALE ─────────────────────────────────
app.get('/api/football', async (req, res) => {
  try {
    const path = req.query.path;
    if (!path) return res.status(400).json({ error: 'path mancante' });
    const url = new URL(`https://api.football-data.org/v4/${path}`);
    // Aggiungi tutti gli altri query params tranne 'path'
    Object.entries(req.query).forEach(([k, v]) => {
      if (k !== 'path') url.searchParams.set(k, v);
    });
    const response = await fetch(url.toString(), {
      headers: { 'X-Auth-Token': process.env.FOOTBALL_API_KEY }
    });
    if (!response.ok) return res.status(response.status).json({ error: 'Errore API' });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Errore server' });
  }
});

// ── PROXY TEAMS PER CAMPIONATO ────────────────────────────────────
app.get('/api/teams/:competition', async (req, res) => {
  try {
    const response = await fetch(
      `https://api.football-data.org/v4/competitions/${req.params.competition}/teams`,
      { headers: { 'X-Auth-Token': process.env.FOOTBALL_API_KEY } }
    );
    if (!response.ok) return res.status(response.status).json({ error: 'Errore API' });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Errore server' });
  }
});

// ── ADMIN MIDDLEWARE ──────────────────────────────────────────────
function adminMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token mancante' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ error: 'Accesso negato' });
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Token non valido' });
  }
}

// ── ADMIN ROUTES ───────────────────────────────────────────────────
app.get('/api/admin/users', adminMiddleware, async (req, res) => {
  const { data, error } = await supabase
    .from('users')
    .select('id, email, username, nome, cognome, squadra_preferita, squadra_crest, role, created_at')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: 'Errore nel recupero utenti' });
  res.json({ users: data });
});

app.put('/api/admin/users/:id/role', adminMiddleware, async (req, res) => {
  const { role } = req.body;
  if (!['user', 'admin'].includes(role)) return res.status(400).json({ error: 'Ruolo non valido' });
  const { error } = await supabase.from('users').update({ role }).eq('id', req.params.id);
  if (error) return res.status(500).json({ error: 'Errore aggiornamento ruolo' });
  res.json({ success: true });
});

app.delete('/api/admin/users/:id', adminMiddleware, async (req, res) => {
  const { error } = await supabase.from('users').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: 'Errore eliminazione utente' });
  res.json({ success: true });
});

// ── HEALTH CHECK ─────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));