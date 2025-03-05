
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

document.addEventListener("DOMContentLoaded", function () {
  const downloadBtn = document.getElementById("download-btn");
  if (downloadBtn) {
    downloadBtn.addEventListener("click", function (e) {
      e.preventDefault();
      const filename = downloadBtn.getAttribute("data-filename");
      if (filename) {
        const downloadUrl = `/download_actual_file/${filename}`;
        // Detect mobile devices
        if (/Mobi|Android/i.test(navigator.userAgent)) {
          // For mobile: Redirect to the URL.
          // Note: Some mobile browsers may open the file in a new tab;
          // instruct users to long-press or use the share menu to save.
          window.location.href = downloadUrl;
        } else {
          // For desktop: Fetch as Blob and force download
          fetch(downloadUrl)
            .then((response) => {
              if (!response.ok) {
                throw new Error("Network response was not ok");
              }
              return response.blob();
            })
            .then((blob) => {
              const url = window.URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.style.display = "none";
              a.href = url;
              a.download = filename;
              document.body.appendChild(a);
              a.click();
              window.URL.revokeObjectURL(url);
              document.body.removeChild(a);
            })
            .catch((error) => {
              console.error("Download error:", error);
              alert("Download failed.");
            });
        }
      } else {
        alert("Error: No filename found for download.");
      }
    });
  }
});

// Function to show the loading overlay
function showLoadingOverlay() {
  document.getElementById('loading-overlay').style.display = 'flex';
}

// Add event listeners to links and forms that trigger a page load
document.addEventListener('DOMContentLoaded', function() {
  // For all links that lead to a new page
  var links = document.querySelectorAll('a');
  links.forEach(function(link) {
    // Optionally, you can check if the link has a specific class, e.g., 'show-loader'
    link.addEventListener('click', function(event) {
      // You may want to check if the link's target is _blank, in which case skip
      if (link.target !== '_blank') {
        showLoadingOverlay();
      }
    });
  });

  // For all forms submissions
  var forms = document.querySelectorAll('form');
  forms.forEach(function(form) {
    form.addEventListener('submit', function(event) {
      showLoadingOverlay();
    });
  });
});


