(async function() {
  const authenticatedMessage = document.getElementById('authenticated-message');
  const unauthenticatedMessage = document.getElementById('unauthenticated-message');

  if (isAuthenticated()) authenticatedMessage.style.display = 'block';
  else unauthenticatedMessage.style.display = 'block';
})();
