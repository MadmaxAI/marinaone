const postgres = require('postgres');
const sql = postgres(process.env.DATABASE_URL, { ssl: 'require' });
(async () => {
  try {
    const resumo = await sql`
      SELECT
        (SELECT COUNT(*) FROM marina_demo.spots WHERE type='seca') AS total_secas,
        (SELECT COUNT(*) FROM marina_demo.spots WHERE type='seca' AND vessel_id IS NOT NULL) AS com_embarcacao,
        (SELECT COUNT(*) FROM marina_demo.spots WHERE type='seca' AND status='occupied') AS ocupadas,
        (SELECT COUNT(*) FROM marina_demo.contracts c JOIN marina_demo.spots s ON c.spot_id=s.id WHERE s.type='seca' AND c.status='active') AS contratos_ativos,
        (SELECT MIN(id) FROM marina_demo.spots WHERE type='seca') AS id_min,
        (SELECT MAX(id) FROM marina_demo.spots WHERE type='seca') AS id_max
    `;
    console.log('RESUMO:', JSON.stringify(resumo[0], null, 2));

    const detalhe = await sql`
      SELECT s.id, s.number, s.status, s.vessel_id, v.name AS vessel_name,
             c.id AS contract_id, c.status AS contract_status,
             (SELECT COUNT(*) FROM marina_demo.financial_charges fc WHERE fc.contract_id=c.id AND fc.status='pending') AS parcelas_pendentes,
             (SELECT COUNT(*) FROM marina_demo.queue_operations q WHERE q.vessel_id=s.vessel_id AND q.status IN ('waiting','in_progress')) AS ops_ativas
      FROM marina_demo.spots s
      LEFT JOIN marina_demo.vessels v ON v.id=s.vessel_id
      LEFT JOIN marina_demo.contracts c ON c.spot_id=s.id AND c.status='active'
      WHERE s.type='seca' AND s.vessel_id IS NOT NULL
      ORDER BY s.id
    `;
    console.log('VAGAS OCUPADAS:', JSON.stringify(detalhe, null, 2));
  } catch(e) {
    console.error('ERRO:', e.message);
  }
  await sql.end();
})();
