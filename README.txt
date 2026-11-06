Mise à jour CVL - Gestion des Super Admins avec SETUP_SECRET

Fichiers à remplacer : src/worker.js et public/admin.js.
Si la migration comptes précédente n’a pas été faite : exécuter migration-comptes.sql UNE FOIS seulement dans D1 après vérification PRAGMA table_info(users).
Le HTML gestion-cvl.html existant de la mise à jour comptes fonctionne sans changement.
Création, suppression, réinitialisation et changement de rôle vers/depuis superadmin exigent SETUP_SECRET.
Un Super Admin connecté ne peut supprimer son propre compte ni le dernier Super Admin.
Ne partagez pas SETUP_SECRET dans GitHub ou des captures.
