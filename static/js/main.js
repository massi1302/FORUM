
// Fonctions pour interagir avec l'API
async function fetchThreads(search = '', tag = '') {
    const threadList = document.getElementById('thread-list');
    threadList.innerHTML = '<div class="loading">Chargement des sujets...</div>';

    try {
        let url = '/api/threads/';
        const params = [];
        if (search) params.push(`search=${encodeURIComponent(search)}`);
        if (tag) params.push(`tag=${encodeURIComponent(tag)}`);
        if (params.length > 0) url += '?' + params.join('&');

        const response = await fetch(url);
        const data = await response.json();

        if (data.length === 0) {
            threadList.innerHTML = '<p>Aucun sujet trouvé.</p>';
            return;
        }

        let html = '';
        data.forEach(thread => {
            html += `
                <div class="thread-card">
                    <h3><a href="/thread/${thread.ID}">${thread.Title}</a></h3>
                    <p>${thread.Content.substring(0, 150)}${thread.Content.length > 150 ? '...' : ''}</p>
                    <div class="thread-meta">
                        <span>Par ${thread.User.Username}</span>
                        <span>${new Date(thread.CreatedAt).toLocaleDateString()}</span>
                    </div>
                </div>
            `;
        });
        threadList.innerHTML = html;
    } catch (error) {
        console.error('Erreur lors du chargement des threads:', error);
        threadList.innerHTML = '<p>Erreur lors du chargement des sujets.</p>';
    }
}

async function createNewThread() {
    const form = document.getElementById('new-thread-form');
    const title = form.title.value;
    const content = form.content.value;
    const tags = form.tags.value;

    if (!title || !content) {
        alert('Veuillez remplir tous les champs obligatoires.');
        return;
    }

    const token = localStorage.getItem('token');
    if (!token) {
        alert('Vous devez être connecté pour créer un sujet.');
        window.location.href = '/login';
        return;
    }

    try {
        const response = await fetch('/api/threads/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                Title: title,
                Content: content,
                Tags: tags.split(',').map(tag => tag.trim()).filter(tag => tag)
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Erreur lors de la création du sujet');
        }

        const thread = await response.json();
        document.getElementById('new-thread-modal').style.display = 'none';
        window.location.href = `/thread/${thread.ID}`;
    } catch (error) {
        console.error('Erreur:', error);
        alert(error.message);
    }
}