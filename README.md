# Forum de discussion académique

Une plateforme sophistiquée conçue pour faciliter les discussions académiques et le partage de connaissances entre étudiants, chercheurs et enseignants.

## Fonctionnalités

- **Discussions structurées** : Organisez les conversations par sujets et disciplines académiques
- **Authentification utilisateur** : Système de connexion et d'inscription sécurisé
- **Gestion des fils de discussion** : Créez, modifiez et modérez des fils de discussion
- **Réponses interactives** : Répondez aux fils de discussion et participez aux discussions académiques
- **Système de vote** : Mettez en avant les contributions pertinentes grâce au vote de la communauté
- **Système de tags** : Catégorisez les discussions pour une navigation simplifiée
- **Fonctionnalité de recherche** : Trouvez des discussions et des ressources pertinentes
- **Conception réactive** : Accédez au forum sur n'importe quel appareil

## Pile technique

- **Backend** : Utilisez le framework Gin
- **Base de données** : MySQL avec GORM
- **Authentification** : Authentification basée sur JWT
- **Frontend** : HTML, CSS, JavaScript

## Prise en main

1. Clonez le dépôt
2. Configurez les variables d'environnement dans « .env »
3. Installez les dépendances
4. Exécutez l'application :
« bash »
go run main.go
```

## Variables d'environnement

Créez un fichier `.env` avec les variables suivantes :
```
DB_HOST=localhost
DB_PORT=3306
DB_USER=votre_nom_d'utilisateur
DB_PASSWORD=votre_mot_de_passe
DB_NAME=forum_educatif
JWT_SECRET=votre_secret_jwt
```

## Contribution

1. Forker le dépôt
2. Créer une branche de fonctionnalité
3. Valider les modifications
4. Envoyer vers la branche
5. Créer une demande de tirage

## Licence

Ce projet est sous licence MIT ; consultez le fichier LICENSE pour plus de détails.

## Assistance

Pour obtenir de l'aide, veuillez ouvrir un ticket dans le dépôt ou contacter les mainteneurs.
