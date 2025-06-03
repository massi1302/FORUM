document.addEventListener('DOMContentLoaded', function() {
    // Rediriger si déjà connecté
    const token = localStorage.getItem('token');
    if (token) {
        window.location.href = '/';
        return;
    }

    // Formulaire de connexion
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            login();
        });
    }

    // Formulaire d'inscription
    const registerForm = document.getElementById('register-form');
    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            e.preventDefault();
            register();
        });
    }
});

async function login() {
    const identifier = document.getElementById('identifier').value;
    const password = document.getElementById('password').value;
    const errorMessage = document.getElementById('error-message');

    if (!identifier || !password) {
        errorMessage.textContent = 'Veuillez remplir tous les champs.';
        return;
    }

       try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                identifier,
                password
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Identifiants incorrects');
        }

        const data = await response.json();
        localStorage.setItem('token', data.token);
        localStorage.setItem('user', JSON.stringify(data.user));
        
        // Redirection après connexion
        window.location.href = '/';
    } catch (error) {
        console.error('Erreur:', error);
        errorMessage.textContent = error.message;
    }
}

async function register() {
    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const passwordConfirm = document.getElementById('password-confirm').value;
    const errorMessage = document.getElementById('error-message');

    if (!username || !email || !password || !passwordConfirm) {
        errorMessage.textContent = 'Veuillez remplir tous les champs.';
        return;
    }

    if (password !== passwordConfirm) {
        errorMessage.textContent = 'Les mots de passe ne correspondent pas.';
        return;
    }

    if (password.length < 12) {
        errorMessage.textContent = 'Le mot de passe doit contenir au moins 12 caractères.';
        return;
    }

    try {
        const response = await fetch('/api/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                Username: username,
                Email: email,
                Password: password
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Erreur lors de l\'inscription');
        }

        window.location.href = '/login?registered=true';
    } catch (error) {
        console.error('Erreur:', error);
        errorMessage.textContent = error.message;
    }
}