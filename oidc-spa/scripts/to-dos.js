(async function() {
  if (!await allowAccess()) return;

  const consentNeeded = document.getElementById('consent-needed');
  const toDosDiv = document.getElementById('to-dos-container');
  const toDosList = document.getElementById('to-dos-list');
  const loadToDosButton = document.getElementById('load-to-dos');
  const loadingToDos = document.getElementById('loading-to-dos');

  await loadToDos();

  async function loadToDos() {
    try {
      const response = await fetch('http://localhost:3001/', {
        method: 'GET',
        headers: {
          authorization: `Bearer ${getAccessToken()}`,
        }
      });
      if (!response.ok) throw 'Request status: ' + response.status;
      const toDos = await response.json();
      displayToDos(toDos);
    } catch (err) {
      console.log(err);
      alert('Error while fetching the to-do list. Check browser logs.');
    }
  }

  function displayToDos(toDos) {
    toDos.forEach(toDo => {
      const newItem = document.createElement('li');
      const newItemDescription = document.createTextNode(toDo.description);
      newItem.appendChild(newItemDescription);
      toDosList.appendChild(newItem);
    });

    loadingToDos.style.display = 'none';
    consentNeeded.style.display = 'none';
    loadToDosButton.style.display = 'none';
    toDosDiv.style.display = 'block';
  }
})();
