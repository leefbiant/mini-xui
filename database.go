package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// openStatsStore imports legacy JSON exactly once, committing data and marker together.
func openStatsStore(path, legacyPath string) (*sql.DB, map[string]statRecord, error) {
	if legacyPath != "" {
		dbAbs, e1 := filepath.Abs(path)
		legacyAbs, e2 := filepath.Abs(legacyPath)
		if e1 != nil || e2 != nil {
			return nil, nil, errors.New("无效的数据库或旧统计文件路径")
		}
		if dbAbs == legacyAbs {
			return nil, nil, errors.New("数据库路径不能与旧统计文件相同")
		}
		dbInfo, e1 := os.Stat(dbAbs)
		legacyInfo, e2 := os.Stat(legacyAbs)
		if e1 == nil && e2 == nil && os.SameFile(dbInfo, legacyInfo) {
			return nil, nil, errors.New("数据库与旧统计文件不能指向同一文件")
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, nil, err
	}
	if err = f.Close(); err != nil {
		return nil, nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, nil, err
	}
	db.SetMaxOpenConns(1)
	fail := func(err error) (*sql.DB, map[string]statRecord, error) { _ = db.Close(); return nil, nil, err }
	if _, err = db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		return fail(err)
	}
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS traffic (name TEXT PRIMARY KEY, total INTEGER NOT NULL, last INTEGER NOT NULL)`); err != nil {
		return fail(err)
	}
	tx, err := db.Begin()
	if err != nil {
		return fail(err)
	}
	var marker string
	err = tx.QueryRow(`SELECT value FROM metadata WHERE key='legacy_import'`).Scan(&marker)
	if errors.Is(err, sql.ErrNoRows) {
		var count int
		if err = tx.QueryRow(`SELECT count(*) FROM traffic`).Scan(&count); err != nil {
			_ = tx.Rollback()
			return fail(err)
		}
		if count == 0 && legacyPath != "" {
			b, readErr := os.ReadFile(legacyPath)
			if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
				_ = tx.Rollback()
				return fail(readErr)
			}
			if readErr == nil {
				var legacy map[string]statRecord
				if err = json.Unmarshal(b, &legacy); err != nil {
					_ = tx.Rollback()
					return fail(fmt.Errorf("旧流量文件无效: %w", err))
				}
				for name, v := range legacy {
					if _, err = tx.Exec(`INSERT INTO traffic(name,total,last) VALUES(?,?,?)`, name, v.Total, v.Last); err != nil {
						_ = tx.Rollback()
						return fail(err)
					}
				}
			}
		}
		_, err = tx.Exec(`INSERT INTO metadata(key,value) VALUES('legacy_import','done')`)
	}
	if err != nil {
		_ = tx.Rollback()
		return fail(err)
	}
	if err = tx.Commit(); err != nil {
		return fail(err)
	}
	rows, err := db.Query(`SELECT name,total,last FROM traffic`)
	if err != nil {
		return fail(err)
	}
	defer rows.Close()
	stats := map[string]statRecord{}
	for rows.Next() {
		var name string
		var r statRecord
		if err = rows.Scan(&name, &r.Total, &r.Last); err != nil {
			return fail(err)
		}
		stats[name] = r
	}
	if err = rows.Err(); err != nil {
		return fail(err)
	}
	return db, stats, nil
}

func saveStats(db *sql.DB, stats map[string]statRecord) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO traffic(name,total,last) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET total=excluded.total,last=excluded.last`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for name, r := range stats {
		if _, err = stmt.Exec(name, r.Total, r.Last); err != nil {
			return err
		}
	}
	return tx.Commit()
}
