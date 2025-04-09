const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const multer = require('multer');

// Création de l'application Express
const app = express();
const PORT = process.env.PORT || 20060;

// Configuration des dossiers pour stocker les pastes et les fichiers
const PASTES_DIR = path.join(__dirname, 'data', 'pastes');
const FILES_DIR = path.join(__dirname, 'data', 'files');

// Créer les dossiers s'ils n'existent pas
if (!fs.existsSync(PASTES_DIR)) {
    fs.mkdirSync(PASTES_DIR, { recursive: true });
}
if (!fs.existsSync(FILES_DIR)) {
    fs.mkdirSync(FILES_DIR, { recursive: true });
}

// Configuration de multer pour l'upload de fichiers
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        // Générer un ID unique pour le paste
        const pasteId = req.pasteId || crypto.randomBytes(6).toString('hex');
        
        // Stocker l'ID du paste dans la requête pour l'utiliser plus tard
        req.pasteId = pasteId;
        
        // Créer le dossier pour les fichiers de ce paste
        const pasteFilesDir = path.join(FILES_DIR, pasteId);
        if (!fs.existsSync(pasteFilesDir)) {
            fs.mkdirSync(pasteFilesDir, { recursive: true });
        }
        
        cb(null, pasteFilesDir);
    },
    filename: function (req, file, cb) {
        // Utiliser le nom original du fichier
        cb(null, file.originalname);
    }
});

// Limiter la taille des fichiers à 30 Mo
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 30 * 1024 * 1024 // 30 Mo
    }
});

// Middleware pour parser le corps des requêtes
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Servir les fichiers statiques
app.use(express.static(path.join(__dirname, 'public')));

// Middleware pour gérer les erreurs d'upload
app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({
                success: false,
                error: 'La taille du fichier dépasse la limite de 30 Mo.'
            });
        }
    }
    next(err);
});

// Route pour créer un nouveau paste
app.post('/api/paste', upload.array('files', 5), (req, res) => {
    try {
        const { content, syntax, expiration, password, title } = req.body;
        
        // Vérifier si le contenu ou les fichiers sont fournis
        if ((!content || content.trim() === '') && (!req.files || req.files.length === 0)) {
            return res.status(400).json({
                success: false,
                error: 'Le contenu ou les fichiers sont requis.'
            });
        }
        
        // Générer un ID unique pour le paste
        const pasteId = req.pasteId || crypto.randomBytes(6).toString('hex');
        
        // Créer l'objet paste
        const paste = {
            id: pasteId,
            content: content || '',
            syntax: syntax || 'plaintext',
            expiration: expiration || 'never',
            createdAt: new Date().toISOString(),
            title: title || '',
            isPasswordProtected: !!password,
            files: req.files ? req.files.map(file => ({
                id: crypto.randomBytes(6).toString('hex'),
                name: file.originalname,
                size: file.size,
                path: file.path
            })) : []
        };
        
        // Ajouter le hash du mot de passe si fourni
        if (password) {
            const salt = crypto.randomBytes(16).toString('hex');
            const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
            paste.passwordHash = hash;
            paste.passwordSalt = salt;
        }
        
        // Sauvegarder le paste dans un fichier
        const pastePath = path.join(PASTES_DIR, `${pasteId}.json`);
        fs.writeFileSync(pastePath, JSON.stringify(paste, null, 2));
        
        // Retourner l'ID du paste
        res.json({
            success: true,
            id: pasteId
        });
    } catch (error) {
        console.error('Erreur lors de la création du paste:', error);
        res.status(500).json({
            success: false,
            error: 'Une erreur est survenue lors de la création du paste.'
        });
    }
});

// Route pour récupérer un paste
app.get('/api/paste/:id', (req, res) => {
    try {
        const { id } = req.params;
        
        // Vérifier si le paste existe
        const pastePath = path.join(PASTES_DIR, `${id}.json`);
        if (!fs.existsSync(pastePath)) {
            return res.status(404).json({
                success: false,
                error: 'Paste introuvable.'
            });
        }
        
        // Lire le paste
        const pasteData = fs.readFileSync(pastePath, 'utf8');
        const paste = JSON.parse(pasteData);
        
        // Vérifier si le paste a expiré
        if (paste.expiration !== 'never') {
            const createdAt = new Date(paste.createdAt);
            const now = new Date();
            
            let expirationDate;
            switch (paste.expiration) {
                case '10m':
                    expirationDate = new Date(createdAt.getTime() + 10 * 60 * 1000);
                    break;
                case '1h':
                    expirationDate = new Date(createdAt.getTime() + 60 * 60 * 1000);
                    break;
                case '1d':
                    expirationDate = new Date(createdAt.getTime() + 24 * 60 * 60 * 1000);
                    break;
                case '1w':
                    expirationDate = new Date(createdAt.getTime() + 7 * 24 * 60 * 60 * 1000);
                    break;
                case '2w':
                    expirationDate = new Date(createdAt.getTime() + 14 * 24 * 60 * 60 * 1000);
                    break;
                case '1m':
                    expirationDate = new Date(createdAt);
                    expirationDate.setMonth(expirationDate.getMonth() + 1);
                    break;
                case '6m':
                    expirationDate = new Date(createdAt);
                    expirationDate.setMonth(expirationDate.getMonth() + 6);
                    break;
                case '1y':
                    expirationDate = new Date(createdAt);
                    expirationDate.setFullYear(expirationDate.getFullYear() + 1);
                    break;
            }
            
            if (now > expirationDate) {
                return res.status(410).json({
                    success: false,
                    error: 'Ce paste a expiré.'
                });
            }
        }
        
        // Si le paste est protégé par un mot de passe, ne pas renvoyer le contenu
        if (paste.isPasswordProtected) {
            return res.json({
                id: paste.id,
                title: paste.title,
                createdAt: paste.createdAt,
                expiration: paste.expiration,
                isPasswordProtected: true
            });
        }
        
        // Supprimer les informations sensibles
        delete paste.passwordHash;
        delete paste.passwordSalt;
        
        // Supprimer les chemins de fichiers complets
        if (paste.files && paste.files.length > 0) {
            paste.files = paste.files.map(file => ({
                id: file.id,
                name: file.name,
                size: file.size
            }));
        }
        
        // Retourner le paste
        res.json(paste);
    } catch (error) {
        console.error('Erreur lors de la récupération du paste:', error);
        res.status(500).json({
            success: false,
            error: 'Une erreur est survenue lors de la récupération du paste.'
        });
    }
});

// Route pour vérifier le mot de passe d'un paste
app.post('/api/paste/:id/verify', (req, res) => {
    try {
        const { id } = req.params;
        const { password } = req.body;
        
        // Vérifier si le paste existe
        const pastePath = path.join(PASTES_DIR, `${id}.json`);
        if (!fs.existsSync(pastePath)) {
            return res.status(404).json({
                success: false,
                error: 'Paste introuvable.'
            });
        }
        
        // Lire le paste
        const pasteData = fs.readFileSync(pastePath, 'utf8');
        const paste = JSON.parse(pasteData);
        
        // Vérifier si le paste a expiré
        if (paste.expiration !== 'never') {
            const createdAt = new Date(paste.createdAt);
            const now = new Date();
            
            let expirationDate;
            switch (paste.expiration) {
                case '10m':
                    expirationDate = new Date(createdAt.getTime() + 10 * 60 * 1000);
                    break;
                case '1h':
                    expirationDate = new Date(createdAt.getTime() + 60 * 60 * 1000);
                    break;
                case '1d':
                    expirationDate = new Date(createdAt.getTime() + 24 * 60 * 60 * 1000);
                    break;
                case '1w':
                    expirationDate = new Date(createdAt.getTime() + 7 * 24 * 60 * 60 * 1000);
                    break;
                case '2w':
                    expirationDate = new Date(createdAt.getTime() + 14 * 24 * 60 * 60 * 1000);
                    break;
                case '1m':
                    expirationDate = new Date(createdAt);
                    expirationDate.setMonth(expirationDate.getMonth() + 1);
                    break;
                case '6m':
                    expirationDate = new Date(createdAt);
                    expirationDate.setMonth(expirationDate.getMonth() + 6);
                    break;
                case '1y':
                    expirationDate = new Date(createdAt);
                    expirationDate.setFullYear(expirationDate.getFullYear() + 1);
                    break;
            }
            
            if (now > expirationDate) {
                return res.status(410).json({
                    success: false,
                    error: 'Ce paste a expiré.'
                });
            }
        }
        
        // Vérifier si le paste est protégé par un mot de passe
        if (!paste.isPasswordProtected) {
            return res.status(400).json({
                success: false,
                error: 'Ce paste n\'est pas protégé par un mot de passe.'
            });
        }
        
        // Vérifier le mot de passe
        const hash = crypto.pbkdf2Sync(password, paste.passwordSalt, 1000, 64, 'sha512').toString('hex');
        if (hash !== paste.passwordHash) {
            return res.status(401).json({
                success: false,
                error: 'Mot de passe incorrect.'
            });
        }
        
        // Supprimer les informations sensibles
        delete paste.passwordHash;
        delete paste.passwordSalt;
        
        // Supprimer les chemins de fichiers complets
        if (paste.files && paste.files.length > 0) {
            paste.files = paste.files.map(file => ({
                id: file.id,
                name: file.name,
                size: file.size
            }));
        }
        
        // Retourner le paste
        res.json(paste);
    } catch (error) {
        console.error('Erreur lors de la vérification du mot de passe:', error);
        res.status(500).json({
            success: false,
            error: 'Une erreur est survenue lors de la vérification du mot de passe.'
        });
    }
});

// Route pour accéder au contenu brut d'un paste
app.get('/raw/:id', (req, res) => {
    try {
        const { id } = req.params;
        
        // Vérifier si le paste existe
        const pastePath = path.join(PASTES_DIR, `${id}.json`);
        if (!fs.existsSync(pastePath)) {
            return res.status(404).send('Paste introuvable.');
        }
        
        // Lire le paste
        const pasteData = fs.readFileSync(pastePath, 'utf8');
        const paste = JSON.parse(pasteData);
        
        // Vérifier si le paste a expiré
        if (paste.expiration !== 'never') {
            const createdAt = new Date(paste.createdAt);
            const now = new Date();
            
            let expirationDate;
            switch (paste.expiration) {
                case '10m':
                    expirationDate = new Date(createdAt.getTime() + 10 * 60 * 1000);
                    break;
                case '1h':
                    expirationDate = new Date(createdAt.getTime() + 60 * 60 * 1000);
                    break;
                case '1d':
                    expirationDate = new Date(createdAt.getTime() + 24 * 60 * 60 * 1000);
                    break;
                case '1w':
                    expirationDate = new Date(createdAt.getTime() + 7 * 24 * 60 * 60 * 1000);
                    break;
                case '2w':
                    expirationDate = new Date(createdAt.getTime() + 14 * 24 * 60 * 60 * 1000);
                    break;
                case '1m':
                    expirationDate = new Date(createdAt);
                    expirationDate.setMonth(expirationDate.getMonth() + 1);
                    break;
                case '6m':
                    expirationDate = new Date(createdAt);
                    expirationDate.setMonth(expirationDate.getMonth() + 6);
                    break;
                case '1y':
                    expirationDate = new Date(createdAt);
                    expirationDate.setFullYear(expirationDate.getFullYear() + 1);
                    break;
            }
            
            if (now > expirationDate) {
                return res.status(410).send('Ce paste a expiré.');
            }
        }
        
        // Vérifier si le paste est protégé par un mot de passe
        if (paste.isPasswordProtected) {
            return res.status(401).send('Ce paste est protégé par un mot de passe.');
        }
        
        // Définir le type de contenu en fonction de la syntaxe
        res.setHeader('Content-Type', 'text/plain');
        
        // Retourner le contenu brut
        res.send(paste.content);
    } catch (error) {
        console.error('Erreur lors de l\'accès au contenu brut:', error);
        res.status(500).send('Une erreur est survenue lors de l\'accès au contenu brut.');
    }
});

// Route pour télécharger un fichier attaché à un paste
app.get('/files/:pasteId/:fileId', (req, res) => {
    try {
        const { pasteId, fileId } = req.params;
        
        // Vérifier si le paste existe
        const pastePath = path.join(PASTES_DIR, `${pasteId}.json`);
        if (!fs.existsSync(pastePath)) {
            return res.status(404).send('Paste introuvable.');
        }
        
        // Lire le paste
        const pasteData = fs.readFileSync(pastePath, 'utf8');
        const paste = JSON.parse(pasteData);
        
        // Vérifier si le paste a expiré
        if (paste.expiration !== 'never') {
            const createdAt = new Date(paste.createdAt);
            const now = new Date();
            
            let expirationDate;
            switch (paste.expiration) {
                case '10m':
                    expirationDate = new Date(createdAt.getTime() + 10 * 60 * 1000);
                    break;
                case '1h':
                    expirationDate = new Date(createdAt.getTime() + 60 * 60 * 1000);
                    break;
                case '1d':
                    expirationDate = new Date(createdAt.getTime() + 24 * 60 * 60 * 1000);
                    break;
                case '1w':
                    expirationDate = new Date(createdAt.getTime() + 7 * 24 * 60 * 60 * 1000);
                    break;
                case '2w':
                    expirationDate = new Date(createdAt.getTime() + 14 * 24 * 60 * 60 * 1000);
                    break;
                case '1m':
                    expirationDate = new Date(createdAt);
                    expirationDate.setMonth(expirationDate.getMonth() + 1);
                    break;
                case '6m':
                    expirationDate = new Date(createdAt);
                    expirationDate.setMonth(expirationDate.getMonth() + 6);
                    break;
                case '1y':
                    expirationDate = new Date(createdAt);
                    expirationDate.setFullYear(expirationDate.getFullYear() + 1);
                    break;
            }
            
            if (now > expirationDate) {
                return res.status(410).send('Ce paste a expiré.');
            }
        }
        
        // Vérifier si le paste est protégé par un mot de passe
        if (paste.isPasswordProtected) {
            return res.status(401).send('Ce paste est protégé par un mot de passe.');
        }
        
        // Trouver le fichier
        const file = paste.files.find(f => f.id === fileId);
        if (!file) {
            return res.status(404).send('Fichier introuvable.');
        }
        
        // Vérifier si le fichier existe
        const filePath = path.join(FILES_DIR, pasteId, file.name);
        if (!fs.existsSync(filePath)) {
            return res.status(404).send('Fichier introuvable.');
        }
        
        // Télécharger le fichier
        res.download(filePath, file.name);
    } catch (error) {
        console.error('Erreur lors du téléchargement du fichier:', error);
        res.status(500).send('Une erreur est survenue lors du téléchargement du fichier.');
    }
});

// Route pour la page d'accueil
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Route pour la page de visualisation d'un paste
app.get('/p/:id', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'view.html'));
});

// Démarrer le serveur
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Serveur démarré sur http://0.0.0.0:${PORT}`);
});
