package keycert

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"signbird/key-certificate-service/internal/db"
)

func migrate(ctx context.Context, pool *pgxpool.Pool, legacyDir, password string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, db.SchemaSQL, pgx.QueryExecModeSimpleProtocol); err != nil {
		return err
	}
	queries := db.New(tx)
	keys, err := queries.ListKeysMissingPKCS12(ctx)
	if err != nil {
		return err
	}
	if len(keys) > 0 && (legacyDir == "" || password == "") {
		return errors.New("set SIGNBIRD_KEYSTORE_DIR and SIGNBIRD_PKCS12_PASSWORD to import existing PKCS#12 files")
	}
	store := keystore{password: password}
	for _, key := range keys {
		if !keyID.MatchString(key.KeyID) || key.ObjectRef != key.KeyID+".p12" {
			return fmt.Errorf("invalid legacy PKCS#12 reference for key %q", key.KeyID)
		}
		container, err := os.ReadFile(filepath.Join(legacyDir, key.ObjectRef))
		if errors.Is(err, os.ErrNotExist) && key.Status == "PENDING" {
			continue
		}
		if err != nil {
			return fmt.Errorf("read legacy PKCS#12 for key %s: %w", key.KeyID, err)
		}
		privateKey, err := store.decode(container)
		if err != nil {
			return fmt.Errorf("decode legacy PKCS#12 for key %s: %w", key.KeyID, err)
		}
		publicKey, err := publicKeyPEM(privateKey)
		if err != nil {
			return err
		}
		if key.Status == "ACTIVE" && key.PublicKey != publicKey {
			return fmt.Errorf("legacy PKCS#12 public key differs from registered key %s", key.KeyID)
		}
		if err := queries.InsertPKCS12(ctx, db.InsertPKCS12Params{ObjectRef: key.ObjectRef, Container: container}); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
