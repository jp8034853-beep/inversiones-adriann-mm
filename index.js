import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { pool } from './db.js';
import { requireAuth, adminOnly } from './auth.js';

dotenv.config();
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  console.error('Configura JWT_SECRET con al menos 32 caracteres.');
  process.exit(1);
}
const app = express();
app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN === '*' ? true : process.env.CORS_ORIGIN?.split(',') }));
app.use(express.json({ limit: '1mb' }));

app.get('/health', (_req,res) => res.json({ ok:true, app:'Inversiones Adriann M&M API' }));

app.post('/auth/login', async (req,res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const { rows } = await pool.query('SELECT * FROM users WHERE username=$1 AND active=TRUE', [username]);
  const user = rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error:'Usuario o contraseña incorrectos.' });
  const token = jwt.sign({ sub:user.id }, process.env.JWT_SECRET, { expiresIn:'12h' });
  res.json({ token, user:{ id:user.id, username:user.username, fullName:user.full_name, role:user.role } });
});

app.use(requireAuth);
app.get('/me', (req,res) => res.json({ user:req.user }));

app.get('/workers', adminOnly, async (_req,res) => {
  const { rows } = await pool.query("SELECT id,username,full_name AS \"fullName\",active,created_at AS \"createdAt\" FROM users WHERE role='worker' ORDER BY full_name");
  res.json(rows);
});
app.post('/workers', adminOnly, async (req,res) => {
  const { username, password, fullName } = req.body;
  if (!username || !fullName || !password || String(password).length < 12) return res.status(400).json({ error:'Nombre, usuario y contraseña de al menos 12 caracteres son obligatorios.' });
  try {
    const hash = await bcrypt.hash(password,12);
    const { rows } = await pool.query("INSERT INTO users(username,password_hash,full_name,role) VALUES($1,$2,$3,'worker') RETURNING id,username,full_name AS \"fullName\",active", [String(username).trim().toLowerCase(),hash,String(fullName).trim()]);
    res.status(201).json(rows[0]);
  } catch (e) { res.status(409).json({ error:'No se pudo crear. Comprueba que el usuario no esté repetido.' }); }
});
app.patch('/workers/:id/active', adminOnly, async (req,res) => {
  const active = Boolean(req.body.active);
  const { rows } = await pool.query("UPDATE users SET active=$1 WHERE id=$2 AND role='worker' RETURNING id,username,active", [active,req.params.id]);
  if (!rows[0]) return res.status(404).json({ error:'Trabajador no encontrado.' });
  res.json(rows[0]);
});

app.get('/clients', async (req,res) => {
  const params = [];
  let where = '';
  if (req.user.role !== 'admin') { params.push(req.user.id); where = 'WHERE c.worker_id=$1'; }
  const { rows } = await pool.query(
    `SELECT c.id,c.full_name AS "fullName",c.national_id AS "nationalId",c.phone,c.address,c.neighborhood,c.worker_id AS "workerId",u.full_name AS "workerName",c.created_at AS "createdAt"
     FROM clients c JOIN users u ON u.id=c.worker_id ${where} ORDER BY c.created_at DESC`, params);
  res.json(rows);
});
app.post('/clients', async (req,res) => {
  const { fullName,nationalId,phone,address,neighborhood } = req.body;
  if (!fullName || !nationalId || !phone) return res.status(400).json({ error:'Nombre, cédula y teléfono son obligatorios.' });
  const workerId = req.user.role === 'admin' ? (req.body.workerId || req.user.id) : req.user.id;
  const { rows } = await pool.query(
    `INSERT INTO clients(full_name,national_id,phone,address,neighborhood,worker_id)
     VALUES($1,$2,$3,$4,$5,$6)
     RETURNING id,full_name AS "fullName",national_id AS "nationalId",phone,address,neighborhood,worker_id AS "workerId"`,
    [fullName,nationalId,phone,address || null,neighborhood || null,workerId]);
  res.status(201).json(rows[0]);
});

app.post('/charges', async (req,res) => {
  const { clientId,description,totalAmount,weeklyInstallment,startDate,paymentWeekday } = req.body;
  if (!clientId || !description || !(Number(totalAmount)>0) || !(Number(weeklyInstallment)>0) || !startDate || !Number.isInteger(Number(paymentWeekday)) || Number(paymentWeekday)<0 || Number(paymentWeekday)>6)
    return res.status(400).json({ error:'Completa los datos del cobro y la cuota semanal.' });
  const client = await pool.query('SELECT id,worker_id FROM clients WHERE id=$1',[clientId]);
  if (!client.rows[0]) return res.status(404).json({ error:'Cliente no encontrado.' });
  if (req.user.role !== 'admin' && client.rows[0].worker_id !== req.user.id) return res.status(403).json({ error:'Este cliente no pertenece a tu cartera.' });
  const workerId = client.rows[0].worker_id;
  const { rows } = await pool.query(
    `INSERT INTO charges(client_id,worker_id,description,total_amount,weekly_installment,start_date,payment_weekday,created_by)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8)
     RETURNING id,client_id AS "clientId",description,total_amount AS "totalAmount",weekly_installment AS "weeklyInstallment",start_date AS "startDate",payment_weekday AS "paymentWeekday"`,
    [clientId,workerId,description,Number(totalAmount),Number(weeklyInstallment),startDate,Number(paymentWeekday),req.user.id]);
  res.status(201).json(rows[0]);
});

app.post('/charges/:id/payments', async (req,res) => {
  const amount = Number(req.body.amount);
  if (!(amount>0)) return res.status(400).json({ error:'El abono debe ser mayor que cero.' });
  const { rows: chargeRows } = await pool.query('SELECT id,worker_id,total_amount FROM charges WHERE id=$1',[req.params.id]);
  const charge = chargeRows[0];
  if (!charge) return res.status(404).json({ error:'Cobro no encontrado.' });
  if (req.user.role !== 'admin' && charge.worker_id !== req.user.id) return res.status(403).json({ error:'Este cobro no pertenece a tu cartera.' });
  const { rows: paidRows } = await pool.query('SELECT COALESCE(SUM(amount),0) AS paid FROM payments WHERE charge_id=$1',[charge.id]);
  const balance = Number(charge.total_amount) - Number(paidRows[0].paid);
  if (amount > balance) return res.status(400).json({ error:'El abono supera el saldo pendiente.' });
  const lat = req.body.gps?.latitude ?? null, lng = req.body.gps?.longitude ?? null;
  const { rows } = await pool.query(
    `INSERT INTO payments(charge_id,amount,gps_lat,gps_lng,note,recorded_by)
     VALUES($1,$2,$3,$4,$5,$6)
     RETURNING id,charge_id AS "chargeId",amount,paid_at AS "paidAt",gps_lat AS latitude,gps_lng AS longitude,recorded_by AS "recordedBy"`,
    [charge.id,amount,lat,lng,req.body.note || null,req.user.id]);
  res.status(201).json({ payment:rows[0], balanceAfter:balance-amount });
});

app.get('/reports/summary', async (req,res) => {
  const params = [];
  const filter = req.user.role === 'admin' ? '' : 'WHERE c.worker_id=$1';
  if (req.user.role !== 'admin') params.push(req.user.id);
  const { rows } = await pool.query(
    `SELECT COALESCE(SUM(c.total_amount),0) AS "totalCharged",
      COALESCE(SUM(p.paid),0) AS "totalPaid",
      COALESCE(SUM(c.total_amount-p.paid),0) AS "totalBalance"
     FROM charges c
     LEFT JOIN (SELECT charge_id,SUM(amount) AS paid FROM payments GROUP BY charge_id) p ON p.charge_id=c.id
     ${filter}`,params);
  res.json(rows[0]);
});

app.use((err,_req,res,_next) => {
  console.error(err);
  res.status(500).json({ error:'Ocurrió un error interno.' });
});
const port = Number(process.env.PORT || 3000);
app.listen(port,'0.0.0.0',() => console.log(`API lista en puerto ${port}`));
