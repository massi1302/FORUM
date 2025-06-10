document.addEventListener('DOMContentLoaded', function() {
    // Ouvrir le modal
    const newThreadBtn = document.querySelector('.new-thread-btn');
    const modal = document.getElementById('new-thread-modal');
    const close = document.querySelector('.close');

    if (newThreadBtn) {
        newThreadBtn.addEventListener('click', function() {
            modal.style.display = 'block';
        });
    }

    if (close) {
        close.addEventListener('click', function() {
            modal.style.display = 'none';
        });
    }

    // Fermer le modal en cliquant en dehors
    window.addEventListener('click', function(event) {
        if (event.target == modal) {
            modal.style.display = 'none';
        }
    });


});