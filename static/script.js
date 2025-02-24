document.addEventListener("DOMContentLoaded", () => {
  const themeToggle = document.getElementById("theme-toggle");
  const body = document.body;

  // Check local storage for theme preference
  if (localStorage.getItem("theme") === "dark") {
    body.classList.add("dark-mode");
    themeToggle.textContent = "☀️";
  }

  themeToggle.addEventListener("click", () => {
    if (body.classList.contains("dark-mode")) {
      body.classList.remove("dark-mode");
      localStorage.setItem("theme", "light");
      themeToggle.textContent = "🌙"; // Moon icon for dark mode
    } else {
      body.classList.add("dark-mode");
      localStorage.setItem("theme", "dark");
      themeToggle.textContent = "☀️"; // Sun icon for light mode
    }
  });
});
