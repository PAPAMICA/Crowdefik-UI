# Backup Strategy — Crowdefik UI

## PostgreSQL

### Manual backup

```bash
# Dump a single database (compressed)
docker exec crowdefik-db pg_dump -U crowdefik crowdefik | gzip > backup-$(date +%Y%m%d-%H%M%S).sql.gz

# Restore
gunzip -c backup-YYYYMMDD-HHMMSS.sql.gz | docker exec -i crowdefik-db psql -U crowdefik crowdefik
```

### Full dump (all databases + roles)

```bash
docker exec crowdefik-db pg_dumpall -U crowdefik | gzip > backup-full-$(date +%Y%m%d-%H%M%S).sql.gz
```

### Scheduled backup with cron + rotation (keep 30 days)

Add this line to `/etc/cron.d/crowdefik-backup`:

```cron
0 3 * * * root docker exec crowdefik-db pg_dump -U crowdefik crowdefik | gzip > /_data/backups/crowdefik-$(date +\%Y\%m\%d).sql.gz && find /_data/backups -name 'crowdefik-*.sql.gz' -mtime +30 -delete
```

Make sure the backup directory exists:

```bash
mkdir -p /_data/backups
```

## Redis

Redis data is persisted to the `crowdefik-redis` Docker volume using:
- **RDB snapshot** every 60 seconds if at least 1 key changed (`--save 60 1`)
- **AOF** (append-only file) for durability (`--appendonly yes`)

To manually export Redis data:

```bash
docker exec crowdefik-redis redis-cli BGSAVE
docker cp crowdefik-redis:/data/dump.rdb ./redis-backup-$(date +%Y%m%d).rdb
```

## Verification

After a backup, verify the dump is readable:

```bash
gunzip -c backup-YYYYMMDD-HHMMSS.sql.gz | head -20
```

## Notes

- Store backups **off-server** (S3, NFS mount, remote SSH) for disaster recovery.
- Test restores periodically in a staging environment.
- Consider encrypting backups that contain sensitive settings (API keys are stored encrypted in the DB, but still).
