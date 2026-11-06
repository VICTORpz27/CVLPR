-- Exécuter UNE seule fois dans la console D1 de cvl-idees.
-- Vérifier d'abord avec PRAGMA table_info(users);
-- Si must_change_password existe déjà, NE PAS réexécuter ALTER TABLE.
ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;
