# Exemple TanStack JS connecté à rauth

Ce dossier contient un client React basé sur TanStack :

- TanStack Router pour les routes publiques/protégées
- TanStack Query pour la session et les appels API
- TanStack Form pour les formulaires (connexion, inscription, TOTP, notes)
- Flux d'auth complet : inscription, connexion, challenge TOTP, déconnexion
- Intégration de l'API métier `/api/notes`

## 1) Lancer le backend Rust

Depuis la racine du workspace :

```bash
cargo run -p rauth-example-full-app
```

Le backend écoute sur `http://127.0.0.1:3000`.

## 2) Lancer le frontend TanStack

Dans ce dossier :

```bash
npm install
npm run dev
```

Puis ouvrir l'URL affichée par Vite (en général `http://127.0.0.1:5173`).

Le proxy Vite redirige `/api/*` vers le backend Rust.

## Détails techniques

- Fichier principal : `src/main.tsx`
- Proxy API : `vite.config.ts`
- UI : `src/styles.css`

Les routes sont protégées côté client via `beforeLoad` de TanStack Router, qui vérifie la session en s'appuyant sur TanStack Query.
