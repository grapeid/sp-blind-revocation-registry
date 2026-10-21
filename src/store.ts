import pg from 'pg';

export interface Registry {
  prefix: string;
  issuerAid: string;
  issuerPubB64: string;
  lastSyncSeq: number;
  status: string;
}

export interface BrrStore {
  migrate(): Promise<void>;
  close(): Promise<void>;
  enroll(prefix: string, issuerAid: string, issuerPubB64: string): Promise<void>;
  getRegistry(prefix: string): Promise<Registry | null>;
  insertEvent(prefix: string, blindedId: string, eventType: string, seq: number): Promise<void>;
  revokedIds(prefix: string): Promise<string[]>;
  recordAnchor(root: string, enabled: boolean): Promise<void>;
  latestAnchor(): Promise<Record<string, unknown> | null>;
}

export async function openStore(): Promise<BrrStore> {
  const dsn = process.env.DATABASE_URL;
  if (!dsn) {
    throw new Error('DATABASE_URL is not set — a PostgreSQL connection string is required');
  }
  const pool = new pg.Pool({
    connectionString: dsn,
    ssl: dsn.includes('localhost') ? undefined : { rejectUnauthorized: false },
  });
  return new PostgresStore(pool);
}

class PostgresStore implements BrrStore {
  constructor(private readonly pool: pg.Pool) {}

  async migrate(): Promise<void> {
    await this.pool.query(`
CREATE TABLE IF NOT EXISTS registries (
    registry_prefix TEXT PRIMARY KEY,
    issuer_aid TEXT NOT NULL,
    issuer_pubkey_b64 TEXT NOT NULL,
    enrolled_at TEXT NOT NULL,
    last_sync_seq INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS accumulator_entries (
    registry_prefix TEXT NOT NULL,
    blinded_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    sequence_number INTEGER NOT NULL,
    inserted_at TEXT NOT NULL,
    PRIMARY KEY (registry_prefix, blinded_id)
);
CREATE TABLE IF NOT EXISTS anchor_log (
    anchor_id TEXT PRIMARY KEY,
    merkle_root TEXT NOT NULL,
    anchor_time TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    note TEXT
);
`);
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  async enroll(prefix: string, issuerAid: string, issuerPubB64: string): Promise<void> {
    const now = new Date().toISOString();
    await this.pool.query(
      `INSERT INTO registries (registry_prefix, issuer_aid, issuer_pubkey_b64, enrolled_at, status)
       VALUES ($1, $2, $3, $4, 'active')
       ON CONFLICT (registry_prefix) DO UPDATE SET
         issuer_aid=EXCLUDED.issuer_aid,
         issuer_pubkey_b64=EXCLUDED.issuer_pubkey_b64,
         status='active'`,
      [prefix, issuerAid, issuerPubB64, now],
    );
  }

  async getRegistry(prefix: string): Promise<Registry | null> {
    const res = await this.pool.query(
      `SELECT registry_prefix, issuer_aid, issuer_pubkey_b64, last_sync_seq, status
       FROM registries WHERE registry_prefix=$1`,
      [prefix],
    );
    if (res.rows.length === 0) return null;
    const row = res.rows[0];
    return {
      prefix: row.registry_prefix,
      issuerAid: row.issuer_aid,
      issuerPubB64: row.issuer_pubkey_b64,
      lastSyncSeq: row.last_sync_seq,
      status: row.status,
    };
  }

  async insertEvent(prefix: string, blindedId: string, eventType: string, seq: number): Promise<void> {
    const now = new Date().toISOString();
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      if (eventType === 'rev') {
        await client.query(
          `INSERT INTO accumulator_entries (registry_prefix, blinded_id, event_type, sequence_number, inserted_at)
           VALUES ($1, $2, 'revoked', $3, $4)
           ON CONFLICT (registry_prefix, blinded_id) DO UPDATE SET
             event_type='revoked', sequence_number=EXCLUDED.sequence_number, inserted_at=EXCLUDED.inserted_at`,
          [prefix, blindedId, seq, now],
        );
      } else {
        await client.query(
          `INSERT INTO accumulator_entries (registry_prefix, blinded_id, event_type, sequence_number, inserted_at)
           VALUES ($1, $2, 'issued', $3, $4)
           ON CONFLICT (registry_prefix, blinded_id) DO UPDATE SET
             event_type=CASE WHEN accumulator_entries.event_type='revoked' THEN 'revoked' ELSE 'issued' END,
             sequence_number=EXCLUDED.sequence_number`,
          [prefix, blindedId, seq, now],
        );
      }
      await client.query(
        `UPDATE registries SET last_sync_seq=$1 WHERE registry_prefix=$2 AND last_sync_seq < $1`,
        [seq, prefix],
      );
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async revokedIds(prefix: string): Promise<string[]> {
    const res = await this.pool.query(
      `SELECT blinded_id FROM accumulator_entries
       WHERE registry_prefix=$1 AND event_type='revoked' ORDER BY blinded_id`,
      [prefix],
    );
    return res.rows.map((r) => r.blinded_id as string);
  }

  async recordAnchor(root: string, enabled: boolean): Promise<void> {
    const id = `anchor-${Date.now()}${Math.floor(Math.random() * 1e6)}`;
    let note = 'BLOCKED: blockchain anchoring disabled — local log only';
    if (enabled) note = 'BLOCKED: on-chain TX not implemented';
    await this.pool.query(
      `INSERT INTO anchor_log (anchor_id, merkle_root, anchor_time, enabled, note) VALUES ($1,$2,$3,$4,$5)`,
      [id, root, new Date().toISOString(), enabled ? 1 : 0, note],
    );
  }

  async latestAnchor(): Promise<Record<string, unknown> | null> {
    const res = await this.pool.query(
      `SELECT merkle_root, anchor_time, enabled, note FROM anchor_log
       ORDER BY anchor_time DESC LIMIT 1`,
    );
    if (res.rows.length === 0) return null;
    const row = res.rows[0];
    return {
      merkle_root: row.merkle_root,
      anchor_time: row.anchor_time,
      anchoring_enabled: row.enabled === 1,
      note: row.note,
    };
  }
}