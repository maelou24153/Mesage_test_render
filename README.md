# Messagerie web

## Lancer
```
npm install
npm start        # puis ouvre http://localhost:3000
```
Sur Render : « Web Service », build `npm install`, start `npm start`.

## Réglages (variables d'environnement)
| Variable | Rôle |
|---|---|
| `DATA_KEY` | **À définir.** Phrase secrète (16 caractères minimum) qui chiffre `data.json`. Ne la perds pas : sans elle les messages sont illisibles. Sans cette variable, le serveur crée une clé dans `data/secret.key` (moins sûr, car elle est à côté des données). |
| `DATA_DIR` | Dossier des données (messages, médias, copies). Mets-le sur un **disque persistant** (sinon tout est effacé à chaque redéploiement sur Render gratuit). |
| `TRUST_PROXY` | `1` si le site est derrière un proxy HTTPS. Activé automatiquement sur Render. Active la redirection vers HTTPS et la lecture de l'IP réelle. |
| `PROXY_HOPS` | Nombre de proxys devant le serveur (1 par défaut). Si tous les utilisateurs semblent avoir la même IP dans les journaux, augmente ou diminue cette valeur. |
| `MAX_MEDIA_MB` | Espace maximum pour photos et vocaux (3000 par défaut). |

## Ce qui est protégé
- **Comptes** : mot de passe obligatoire (8 caractères minimum, mots de passe courants refusés), stocké haché (scrypt). Création de compte et connexion sont séparées. Messages d'erreur identiques que le pseudo existe ou non.
- **Sessions** : après connexion, un jeton aléatoire remplace le mot de passe (valable 7 jours, 10 appareils maximum, seul son hachage est stocké). Changer de mot de passe ou se déconnecter invalide les jetons.
- **Anti force brute** : blocage de 15 minutes après plusieurs échecs, par connexion et par pseudo. Limites sur la création de comptes, de salons, les recherches de numéros, les nouvelles conversations, les messages et les fichiers.
- **Messages privés** : il faut connaître le numéro à 6 chiffres. Aucune liste des utilisateurs n'est exposée, ni dans les salons ni ailleurs. Chacun peut bloquer une personne.
- **Salons privés** : mot de passe demandé une seule fois par personne (6 caractères minimum), avec limite d'essais.
- **Messages** : jamais supprimés. Une modification garde l'ancienne version côté serveur. Les caractères de contrôle et d'inversion de texte sont retirés.
- **Données** : fichier chiffré (AES-256-GCM), écriture atomique, une copie par jour (les 60 dernières sont gardées), droits 600. Si le fichier est illisible (mauvaise clé), le serveur s'arrête au lieu de l'écraser.
- **Médias** : photos et vocaux vérifiés (vrais formats uniquement), liens signés qui expirent au bout de 2 h.
- **Navigateur** : politique de sécurité stricte (pas de script extérieur), pas d'affichage dans une autre page, connexions WebSocket acceptées seulement depuis ce site, HTTPS imposé derrière un proxy.

## Limites à connaître
- Le serveur peut lire les messages : ce n'est pas du chiffrement de bout en bout.
- Pas de récupération de mot de passe (il n'y a ni e-mail ni téléphone) : un mot de passe perdu = compte perdu.
- Un lien de photo ou de vocal reste utilisable jusqu'à 2 h après avoir été affiché à quelqu'un.
- Tous les messages sont gardés en mémoire et le fichier est réécrit entièrement à chaque sauvegarde : prévu pour quelques centaines d'utilisateurs, pas pour des milliers.
- Garde les dépendances à jour (`npm audit`, `npm update`).
