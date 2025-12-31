document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('.collapsible-header').forEach((header) => {
    header.addEventListener('click', () => {
      const container = header.parentElement;
      container.classList.toggle('active');
    });
  });
});
