# 🛠️ Ateliers Pratiques : Secure Programming sur mds-social-api

Ce document regroupe les ateliers pratiques à réaliser sur l'API **mds-social-api** pour implémenter les défenses clés du module *Secure Programming*.

---

## 🏗️ Préparation et Installation

Assurez-vous que votre API est à jour et que vous êtes sur une branche de travail dédiée aux correctifs de sécurité.

### Dépendances globales de sécurité :
```bash
npm install express-rate-limit cookie-parser csurf helmet
```
*(Note : `csurf` est utilisé à des fins pédagogiques pour illustrer le mécanisme du CSRF Token.)*

---

## 🧩 Atelier 1 : SQL Injection (Proof of Concept)

**Objectif : ** Tester la vulnérabilité d'une requête non préparée et confirmer la bonne pratique avec `mysql2`.

### 1. Créer une faille volontaire (à des fins de test uniquement)

Dans `controllers/AuthController.js`, ajoutez une méthode **vulnérable** :

```javascript
// 🚨 VULNÉRABLE - À NE JAMAIS UTILISER EN PRODUCTION
export const loginVulnerable = async (req, res) => {
    const { email } = req.body;
    // Concaténation directe = DANGER SQL Injection
    const query = `SELECT id, email FROM users WHERE email = '${email}'`; 
    
    try {
        const [users] = await db.query(query);
        if (users.length > 0) {
            console.log('Utilisateur trouvé via injection SQL:', users[0].email);
            return res.status(200).json({ message: 'Connexion réussie (via faille !)', user: users[0] });
        }
        res.status(401).json({ message: 'Identifiants invalides' });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
};

// N'oubliez pas de router cette méthode dans UserRoutes.js pour le test
```

### 2. Attaquer via Postman

1. Lancez le serveur.
2. Dans Postman, envoyez une requête **POST** vers `/api/login-vulnerable` (ou la route que vous avez définie).
3. Utilisez ce corps pour le test d'injection :
    ```json
    { "email": "' OR '1'='1" }
    ```
4. **Observation : ** La requête devrait renvoyer le premier utilisateur de la table.

### 3. Correction

* Supprimez la route et la fonction `loginVulnerable`.
* Vérifiez que votre fonction `login` utilise systématiquement les requêtes préparées avec `?` :
    ```javascript
    // ✅ Exemple de requête préparée (Sécurisé)
    const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
    ```

---

## 🧩 Atelier 2 : Hardening (Helmet, Rate Limit & CORS)

**Objectif : ** Implémenter des défenses contre les attaques DoS/Brute Force, et sécuriser les headers HTTP.

### 1. Protection des Headers avec Helmet

Dans votre fichier principal `index.js` (ou `app.js`) :

```javascript
import helmet from "helmet";
// ... imports ...

const app = express();
// ... autres middlewares ...

// 🛡️ 1. Active Helmet pour sécuriser les headers HTTP
app.use(helmet()); 
```

### 2. Protection Anti-Brute Force (Rate Limiter)

1. Créez le middleware `middlewares/limiter.js` :
    ```javascript
    import rateLimit from 'express-rate-limit';

    export const loginLimiter = rateLimit({
        windowMs: 15 * 60 * 1000, // Période de 15 minutes
        max: 5, // Limite à 5 tentatives de login par IP
        message: { 
            message: "Trop de tentatives de connexion. Réessayez dans 15 minutes." 
        },
        standardHeaders: true,
        legacyHeaders: false,
    });
    ```
2. Appliquez-le sur la route de connexion dans `routes/UserRoutes.js` (ou `AuthRoutes.js`) :
    ```javascript
    import { loginLimiter } from "../middlewares/limiter.js";
    // ...
    router.post('/login', loginLimiter, login);
    ```
3. **Test : ** Dans Postman, essayez de vous connecter plus de 5 fois en 15 minutes. Le 6ème essai doit retourner un statut `429 Too Many Requests`.

### 3. Mise en place de la Sécurité CORS

La mise en place de CORS est essentielle pour prévenir les requêtes indésirables provenant de domaines non autorisés.

1. Installez `cors` si ce n'est pas déjà fait : `npm install cors`.
2. Dans votre fichier principal `index.js` (ou `app.js`), ajoutez la configuration CORS **avant** toute route :

```javascript
import cors from "cors";
// ... imports ...

// 🔒 Configuration CORS
const allowedOrigins = [
    'http://localhost:3000', // Votre domaine de développement Front-end
    '[https://votre-app-front.com](https://votre-app-front.com)' // Votre domaine de production Front-end
];

const corsOptions = {
    origin: (origin, callback) => {
        // Permettre les requêtes sans 'origin' (ex: Postman, mobile, ou same-origin)
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
    credentials: true, // IMPORTANT : Autoriser l'envoi de cookies HttpOnly
    optionsSuccessStatus: 204
};

// 🛡️ 4. Active CORS avec la configuration stricte
app.use(cors(corsOptions));

---

## 🧩 Atelier 3 : Refonte Authentification & CSRF

**Objectif : ** Migrer le stockage du token de `LocalStorage` (vulnérable XSS) aux cookies `HttpOnly` et ajouter la protection CSRF.

### 1. Configuration des middlewares dans `index.js`

Ajoutez et configurez `cookie-parser` et `csurf` **avant** vos routes API :

```javascript
import cookieParser from "cookie-parser";
import csurf from "csurf";

// ... autres imports ...

const app = express();

// 🍪 1. Lire et gérer les cookies
app.use(cookieParser());

// 🛡️ 2. Configuration CSRF
const csrfProtection = csurf({ 
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Mettre à true si HTTPS
        sameSite: 'strict'
    }
});

// Appliquer CSRF globalement (GET exclues par défaut)
app.use(csrfProtection);

// 🔑 3. Route pour que le front-end récupère le token CSRF
app.get('/api/csrf-token', (req, res) => {
    // Le token CSRF est généré et renvoyé au client pour les requêtes POST/PUT/DELETE
    res.json({ csrfToken: req.csrfToken() }); 
});

// 🚨 4. Gestion d'erreur spécifique CSRF (à insérer dans votre middleware errorHandler.js si possible)
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).json({ message: 'Session invalide ou token CSRF manquant/expiré.' });
    }
    next(err);
});

// ... app.use('/api/users', userRoutes); et autres routes ...
```

### 2. Modification du contrôleur de Login (`controllers/AuthController.js`)

Changez la manière dont le token est renvoyé après une connexion réussie.

```javascript
// Remplacer l'envoi de token dans le JSON par l'envoi dans un cookie sécurisé
export const login = async (req, res) => {
    // ... code de vérification du mot de passe existant ...

    // Création du token JWT
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // 🍪 Envoi via Cookie HttpOnly
    res.cookie('token', token, {
        httpOnly: true, // 🛡️ Protection contre le XSS
        secure: process.env.NODE_ENV === 'production', // HTTPS obligatoire en prod
        sameSite: 'strict', // 🛡️ Mitigation CSRF basique
        maxAge: 3600000 // 1 heure en ms
    });

    // 🗑️ Ne plus renvoyer le token dans le corps
    res.json({ message: "Connecté avec succès. Token envoyé via cookie." });
};

// Ajoutez un contrôleur de déconnexion
export const logout = (req, res) => {
    res.clearCookie("token");
    res.json({ message: "Déconnexion réussie." });
};
```

### 3. Adaptation du Middleware d'Auth (`middlewares/isAuth.js`)

Le middleware doit maintenant lire le cookie.

```javascript
// Remplacer la lecture du header Authorization par la lecture du cookie
export const isAuth = (req, res, next) => {
    const token = req.cookies.token; // 🍪 Lecture du cookie

    if (!token) {
        return res.status(401).json({ message: 'Accès refusé. Token manquant.' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ message: 'Token invalide.' });
        req.user = decoded;
        next();
    });
};
```

### 4. Test d'Intégration (CSRF)

1. **Récupérer le CSRF Token : **
* Faites un `GET /api/csrf-token` dans Postman. Copiez la valeur de `csrfToken`.
2. **Tester une Route Protégée (POST/PUT/DELETE) : **
* Tentez un `POST /api/posts` (ou toute autre route protégée par `isAuth`).
* **Test 1 (CSRF Échoué) : ** Envoyez sans aucun header CSRF -> Doit retourner `403` avec le message "Session invalide ou token CSRF manquant/expiré."
* **Test 2 (CSRF Réussi) : ** Ajoutez le header `X-CSRF-Token` avec la valeur copiée à l'étape 1. -> Doit retourner `201 Created` (Succès).

---

## 🧩 Atelier 4 : Hygiène Numérique & Audit

**Objectif : ** Examiner l'environnement et la gestion des secrets.

### 1. Audit de la Gestion des Secrets

1. Vérifiez votre fichier `.gitignore` : le fichier `.env` **doit** y figurer.
2. Créez un fichier **public** `.env.example` qui contient toutes les clés (`DB_HOST`, `JWT_SECRET`, etc.) mais avec des valeurs vides ou factices (ex: `JWT_SECRET=VOTRE_SECRET_ICI`).

### 2. Audit de Code assisté par IA

1. Ouvrez ChatGPT ou GitHub Copilot (avec fonction Chat).
2. Collez un contrôleur critique (ex: `UserController.js` ou `AuthController.js`).
3. Utilisez le prompt suivant :

    > ** "Agis comme un expert en cybersécurité OWASP. Analyse ce code Express.js, trouve les vulnérabilités potentielles (SQLi, XSS, etc.) et propose des correctifs en justifiant la catégorie OWASP concernée."**

4. **Discussion : ** Analysez si l'IA a trouvé des failles et critiquez les propositions.

### 3. Pratique des Mots de Passe Forts

1. Installez l'outil de gestion de mots de passe **Bitwarden**
2. Utilisez le générateur de mots de passe de Bitwarden pour créer des identifiants complexes :
* Un mot de passe de 20+ caractères pour l'utilisateur Admin de votre BDD.
* Un mot de passe de 20+ caractères pour le compte de test de votre API.

### 4. Audit de Dépendances

Exécutez l'outil d'audit de Node.js pour vérifier les failles dans vos dépendances :
```bash
npm audit
```
* **Action : ** Appliquez les correctifs suggérés (souvent `npm audit fix`).
