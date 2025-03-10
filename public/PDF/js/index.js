function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar-right');
    sidebar.classList.toggle('active');
}

function toggleLanguage() {
    document.getElementById('languageOptions').classList.toggle('active');
}

window.addEventListener('resize', () => {
    const sidebar = document.querySelector('.sidebar-right');
    if(window.innerWidth > 768) {
        sidebar.classList.add('active');
    } else {
        sidebar.classList.remove('active');
    }
});
window.addEventListener('load', () => {
    const img = document.querySelector('.forum-visual > img');
    
    const fakeLoad = () => {
        img.classList.add('loaded');
        img.style.willChange = 'transform'; 
    };

    
    setTimeout(fakeLoad, 1000);
});
