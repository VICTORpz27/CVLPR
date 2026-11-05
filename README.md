# Boîte à idées — CVL Pierre Rouges

Application Cloudflare Workers + Static Assets + D1 + Workers AI + Turnstile.

## Fonctionnalités
- Page publique responsive, animations douces, compteur central fidèle à la maquette, formulaire anonyme ou identifié.
- Compteur des suggestions classées `approved` uniquement.
- Filtrage exact des doublons sur 24 heures, limitation des envois par source et Turnstile.
- Classement IA en catégories ou spam / à vérifier ; si IA indisponible, les suggestions restent enregistrées pour examen.
- Dashboard privé, comptes individuels, rôles `superadmin`, `admin`, `member`, `reader`, modération manuelle.

## Déploiement
1. Installer Node.js 20+ puis `npm install`.
2. Se connecter à Cloudflare : `npx wrangler login`.
3. Créer la base : `npx wrangler d1 create cvl-idees` et copier l'ID retourné dans `wrangler.jsonc`.
4. Initialiser : `npm run db:remote`.
5. Créer un widget Cloudflare Turnstile et noter la clé publique et la clé secrète. Configurer la clé publique : `npx wrangler secret put TURNSTILE_SITE_KEY` et la clé secrète : `npx wrangler secret put TURNSTILE_SECRET`.
6. Configurer les secrets : `npx wrangler secret put SETUP_SECRET` (clé aléatoire forte) et `npx wrangler secret put RATE_LIMIT_SALT` (autre valeur aléatoire).
7. Déployer : `npm run deploy`.
8. Ouvrir `https://<nom-du-worker>.<sous-domaine>.workers.dev/gestion-cvl.html` et créer le premier Super Admin avec `SETUP_SECRET`.
9. Ouvrir la page d'accueil, envoyer une suggestion de test et vérifier sa classification dans le dashboard.

**Important :** ce projet est déployé sur Cloudflare Workers Static Assets (hébergement statique inclus), et non sur un projet Pages séparé. Cela simplifie le déploiement en une seule commande et conserve l'objectif d'un hébergement dans les quotas gratuits.

## Sécurité et exploitation
- Ne jamais mettre les secrets dans le dépôt ni les transmettre à des élèves.
- L'URL d'administration est volontairement absente de la navigation publique, mais sa sécurité repose sur les contrôles côté serveur.
- L'IA peut se tromper : modération humaine prévue. Les doublons sémantiques (même idée reformulée) ne sont **pas** encore fusionnés automatiquement ; seuls les doublons textuels normalisés sont détectés.
- Les suggestions anonymes ne stockent pas de nom, prénom ou classe ; les adresses IP ne sont pas enregistrées dans la table des suggestions. Les empreintes temporaires de limitation sont conservées dans `rate_limits` : prévoir leur purge régulière.
- Prévoir avant mise en production une politique RGPD, une durée de conservation, une procédure de suppression, la validation du lycée et des tests de sécurité. Les informations personnelles peuvent apparaître dans le texte libre : afficher un avertissement et définir une procédure de modération.
- Les quotas gratuits Cloudflare varient : surveiller D1, Workers et Workers AI dans le tableau de bord Cloudflare.
- Pour une exploitation à long terme, ajouter une procédure de sauvegarde D1, un mécanisme de réinitialisation des mots de passe et une authentification multifacteur pour les administrateurs.
