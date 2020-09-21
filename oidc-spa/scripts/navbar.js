(async function() {
  const toDosLink = document.getElementById('to-dos-link');
  const profilePicture = document.getElementById('profile-picture');
  const userFullname = document.getElementById('user-fullname');
  const logInButton = document.getElementById('log-in');
  const logOutButton = document.getElementById('log-out');

  logInButton.onclick = async () => {
    await login();
  };

  if (isAuthenticated()) {
    const user = getProfile();
    profilePicture.src = user.picture;
    userFullname.innerText = user.name;

    logOutButton.style.display = 'inline-block';
    toDosLink.style.display = 'inline-block';
  } else {
    logInButton.style.display = 'inline-block';
  }
})();
