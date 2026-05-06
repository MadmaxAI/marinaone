-- Sincroniza contracts.spot_id para contratos ativos que têm spot_id NULL
-- mas cuja embarcação já está atribuída a uma vaga via spots.vessel_id.
-- Idempotente: só atualiza onde spot_id ainda é NULL.
UPDATE contracts ct
SET spot_id = s.id
FROM spots s
WHERE s.vessel_id = ct.vessel_id
  AND ct.spot_id IS NULL
  AND ct.status = 'active';
