import { describe, expect, it } from 'vitest';
import { databaseTls } from './store.js';

describe('the database connection', () => {
  it("checks a remote database's certificate", () => {
    expect(databaseTls('postgres://u:p@db.example.org:5432/brr', {})).toEqual({ rejectUnauthorized: true });
  });

  it('a host merely containing "localhost" is still remote', () => {
    expect(databaseTls('postgres://u:p@localhost.example.org/brr', {})).toEqual({ rejectUnauthorized: true });
  });

  it('needs no TLS for a database on this machine', () => {
    expect(databaseTls('postgres://u:p@localhost:5432/brr', {})).toBeUndefined();
  });

  it('skips the check only when the operator says so', () => {
    expect(databaseTls('postgres://u:p@db.example.org/brr', { BRR_DB_TLS_INSECURE: '1' })).toEqual({
      rejectUnauthorized: false,
    });
  });
});
