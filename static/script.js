
// Sidebar Toggle for Mobile
const openSidebarBtn = document.getElementById('open-sidebar');
const closeSidebarBtn = document.getElementById('close-sidebar');
const sidebar = document.getElementById('sidebar');

if (openSidebarBtn && closeSidebarBtn && sidebar) {
  openSidebarBtn.addEventListener('click', () => {
    sidebar.classList.add('active');
  });
  closeSidebarBtn.addEventListener('click', () => {
    sidebar.classList.remove('active');
  });
}



// Navigation Buttons
document.getElementById('refresh-btn').addEventListener('click', () => location.reload());
document.getElementById('back-btn').addEventListener('click', () => history.back());
document.getElementById('forward-btn').addEventListener('click', () => history.forward());

